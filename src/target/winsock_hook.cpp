#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <WinSock2.h>
#include <ws2tcpip.h>
#include "winsock_hook.h"
#include "filter_engine.h"
#include "hook_manager.h"
#include "common/ipc_protocol.h"
#include "common/packet_frame.h"
#include "common/packet_ring.h"
#include <algorithm>
#include <atomic>
#include <cctype>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <limits>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace wpe {
namespace {

constexpr std::uint8_t kWs1Send = 0;
constexpr std::uint8_t kWs2Send = 1;
constexpr std::uint8_t kWs1SendTo = 2;
constexpr std::uint8_t kWs2SendTo = 3;
constexpr std::uint8_t kWs1Recv = 4;
constexpr std::uint8_t kWs2Recv = 5;
constexpr std::uint8_t kWs1RecvFrom = 6;
constexpr std::uint8_t kWs2RecvFrom = 7;
constexpr std::uint8_t kWsaSend = 8;
constexpr std::uint8_t kWsaSendTo = 9;
constexpr std::uint8_t kWsaRecv = 10;
constexpr std::uint8_t kWsaRecvEx = 11;
constexpr std::uint8_t kWsaRecvFrom = 12;
constexpr std::uint8_t kFilterNone = 4;
constexpr std::size_t kMaximumCapturedBytes = IpcProtocol::MaxPacketFrame - 1024U;
constexpr DWORD kMaximumWsaBufferCount = 65536;
constexpr std::int64_t kFileTimeDateTimeTicks = 504911232000000000LL;
SRWLOCK g_detour_entry_gate = SRWLOCK_INIT;
thread_local bool g_replay_call = false;

std::int64_t DateTimeTicksNow() noexcept {
    FILETIME utc{};
    FILETIME local{};
    GetSystemTimePreciseAsFileTime(&utc);
    if (!FileTimeToLocalFileTime(&utc, &local)) local = utc;
    ULARGE_INTEGER value{};
    value.LowPart = local.dwLowDateTime;
    value.HighPart = local.dwHighDateTime;
    return kFileTimeDateTimeTicks + static_cast<std::int64_t>(value.QuadPart);
}

bool TryCopyMemory(void* destination, const void* source, std::size_t length) noexcept {
    if (length == 0) return true;
    if (!destination || !source) return false;
    __try {
        std::memcpy(destination, source, length);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

bool TryReadDword(const DWORD* source, DWORD& value) noexcept {
    return TryCopyMemory(&value, source, sizeof(value));
}

bool TryWriteDword(DWORD* destination, DWORD value) noexcept {
    return TryCopyMemory(destination, &value, sizeof(value));
}

bool TryReadInt(const int* source, int& value) noexcept {
    return TryCopyMemory(&value, source, sizeof(value));
}

bool TryReadWsaBuffer(const WSABUF* buffers, DWORD index, WSABUF& value) noexcept {
    if (!buffers) return false;
    return TryCopyMemory(&value, buffers + index, sizeof(value));
}

std::shared_ptr<const ByteBuffer> CopyBytes(const char* bytes, std::size_t length) {
    if (!bytes || length == 0 || length > kMaximumCapturedBytes) return {};
    auto copy = std::make_shared<ByteBuffer>(length);
    if (!TryCopyMemory(copy->data(), bytes, length)) return {};
    return copy;
}

std::shared_ptr<const ByteBuffer> FlattenBuffers(const WSABUF* buffers, DWORD count,
                                                 std::size_t limit) {
    if (!buffers || count == 0 || count > kMaximumWsaBufferCount || limit == 0 ||
        limit > kMaximumCapturedBytes) return {};
    auto copy = std::make_shared<ByteBuffer>();
    copy->reserve(limit);
    std::size_t remaining = limit;
    for (DWORD i = 0; i < count && remaining != 0; ++i) {
        WSABUF buffer{};
        if (!TryReadWsaBuffer(buffers, i, buffer)) return {};
        const auto take = std::min<std::size_t>(buffer.len, remaining);
        if (take != 0) {
            const auto old_size = copy->size();
            copy->resize(old_size + take);
            if (!TryCopyMemory(copy->data() + old_size, buffer.buf, take)) return {};
            remaining -= take;
        }
    }
    if (remaining != 0) return {};
    return copy;
}

std::optional<std::size_t> TotalBufferLength(const WSABUF* buffers, DWORD count) noexcept {
    if (!buffers || count == 0 || count > kMaximumWsaBufferCount) return std::nullopt;
    std::size_t total = 0;
    for (DWORD i = 0; i < count; ++i) {
        WSABUF buffer{};
        if (!TryReadWsaBuffer(buffers, i, buffer)) return std::nullopt;
        if (static_cast<std::size_t>(buffer.len) >
            (std::numeric_limits<std::size_t>::max)() - total)
            return std::nullopt;
        total += buffer.len;
    }
    return total;
}

bool CopyToBuffers(WSABUF* buffers, DWORD count,
                   std::span<const std::uint8_t> bytes) noexcept {
    if (!buffers || count == 0 || count > kMaximumWsaBufferCount) return false;
    std::size_t offset = 0;
    for (DWORD i = 0; i < count && offset < bytes.size(); ++i) {
        WSABUF buffer{};
        if (!TryReadWsaBuffer(buffers, i, buffer)) return false;
        const auto take = (std::min)(static_cast<std::size_t>(buffer.len), bytes.size() - offset);
        if (take != 0 && !TryCopyMemory(buffer.buf, bytes.data() + offset, take)) return false;
        offset += take;
    }
    return offset == bytes.size();
}

std::string FormatIpv4(const sockaddr* address, int length) {
    if (!address || length < static_cast<int>(sizeof(sockaddr_in))) return {};
    sockaddr_in copy{};
    if (!TryCopyMemory(&copy, address, sizeof(copy)) || copy.sin_family != AF_INET) return {};
    const auto* bytes = reinterpret_cast<const unsigned char*>(&copy.sin_addr.s_addr);
    const auto port = ntohs(copy.sin_port);
    return std::to_string(bytes[0]) + "." + std::to_string(bytes[1]) + "." +
           std::to_string(bytes[2]) + "." + std::to_string(bytes[3]) + ":" +
           std::to_string(port);
}

Text AsciiText(std::string_view value) {
    std::u16string result;
    result.reserve(value.size());
    for (const unsigned char character : value)
        result.push_back(static_cast<char16_t>(character));
    return result;
}

std::string Ascii(const Text& value) {
    if (!value) return {};
    std::string result;
    result.reserve(value->size());
    for (const auto character : *value)
        result.push_back(character <= 0x7f ? static_cast<char>(character) : '?');
    return result;
}

std::vector<std::string> Tokens(std::string value, char separator = ';') {
    std::vector<std::string> result;
    std::size_t start = 0;
    for (;;) {
        const auto end = value.find(separator, start);
        auto token = value.substr(start, end == std::string::npos ? end : end - start);
        while (!token.empty() && std::isspace(static_cast<unsigned char>(token.front()))) token.erase(token.begin());
        while (!token.empty() && std::isspace(static_cast<unsigned char>(token.back()))) token.pop_back();
        if (!token.empty()) result.push_back(std::move(token));
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return result;
}

int Hex(char value) noexcept {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

std::string HexText(std::span<const std::uint8_t> bytes) {
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (const auto byte : bytes) { result.push_back(digits[byte >> 4]); result.push_back(digits[byte & 0xf]); }
    return result;
}

std::optional<ByteBuffer> ParseHex(std::string value) {
    value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char c) { return std::isspace(c) != 0; }), value.end());
    if (value.empty() || (value.size() & 1U) != 0) return std::nullopt;
    ByteBuffer result; result.reserve(value.size() / 2);
    for (std::size_t i = 0; i < value.size(); i += 2) {
        const auto high = Hex(value[i]), low = Hex(value[i + 1]);
        if (high < 0 || low < 0) return std::nullopt;
        result.push_back(static_cast<std::uint8_t>((high << 4) | low));
    }
    return result;
}

bool ParseIpv4Endpoint(const Text& value, sockaddr_in& endpoint) noexcept {
    if (!value || value->empty()) return false;
    try {
        std::string text;
        text.reserve(value->size());
        for (const auto character : *value) {
            if (character > 0x7f) return false;
            text.push_back(static_cast<char>(character));
        }
        const auto separator = text.find(':');
        if (separator == std::string::npos || separator == 0 ||
            separator + 1 >= text.size() || text.find(':', separator + 1) != std::string::npos)
            return false;
        unsigned int port = 0;
        const auto* first = text.data() + separator + 1;
        const auto* last = text.data() + text.size();
        const auto parsed = std::from_chars(first, last, port);
        if (parsed.ec != std::errc{} || parsed.ptr != last || port == 0 || port > 65535)
            return false;
        endpoint = {};
        endpoint.sin_family = AF_INET;
        endpoint.sin_port = htons(static_cast<unsigned short>(port));
        text.resize(separator);
        return InetPtonA(AF_INET, text.c_str(), &endpoint.sin_addr) == 1;
    } catch (...) {
        return false;
    }
}

class ReplayCallGuard final {
public:
    ReplayCallGuard() noexcept : previous_(g_replay_call) { g_replay_call = true; }
    ~ReplayCallGuard() { g_replay_call = previous_; }
    ReplayCallGuard(const ReplayCallGuard&) = delete;
    ReplayCallGuard& operator=(const ReplayCallGuard&) = delete;
private:
    bool previous_{};
};

std::uint16_t Ipv4Port(const sockaddr* address, int length) noexcept {
    if (!address || length < static_cast<int>(sizeof(sockaddr_in))) return 0;
    sockaddr_in copy{};
    if (!TryCopyMemory(&copy, address, sizeof(copy)) || copy.sin_family != AF_INET) return 0;
    return ntohs(copy.sin_port);
}

std::uint16_t TryIpv4Port(const sockaddr* address, int length) noexcept {
    if (!address || length < static_cast<int>(sizeof(sockaddr_in))) return 0;
    sockaddr_in copy{};
    if (!TryCopyMemory(&copy, address, sizeof(copy)) || copy.sin_family != AF_INET) return 0;
    return ntohs(copy.sin_port);
}

// The writer populates endpoint metadata after its allowed getsockname/
// getpeername calls. Detours only perform bounded atomic lookups.
class SocketPortCache final {
public:
    SocketPortCache() noexcept { Clear(); }

    void Clear() noexcept {
        for (auto& entry : entries_) {
            entry.ports.store(0, std::memory_order_relaxed);
            entry.socket.store(kEmpty, std::memory_order_relaxed);
        }
    }

    void Store(SOCKET socket, std::uint16_t local, std::uint16_t remote) noexcept {
        const auto key = static_cast<std::uintptr_t>(socket);
        const auto packed = static_cast<std::uint32_t>(local) |
                            (static_cast<std::uint32_t>(remote) << 16U);
        const auto start = Hash(key);
        for (std::size_t probe = 0; probe < kProbeCount; ++probe) {
            auto& entry = entries_[(start + probe) & (kCapacity - 1)];
            auto found = entry.socket.load(std::memory_order_acquire);
            if (found == key) {
                entry.ports.store(packed, std::memory_order_release);
                return;
            }
            if (found == kEmpty && entry.socket.compare_exchange_strong(
                    found, key, std::memory_order_acq_rel, std::memory_order_acquire)) {
                entry.ports.store(packed, std::memory_order_release);
                return;
            }
        }
        auto& replacement = entries_[start];
        replacement.ports.store(0, std::memory_order_relaxed);
        replacement.socket.store(key, std::memory_order_release);
        replacement.ports.store(packed, std::memory_order_release);
    }

    void Merge(SOCKET socket, std::uint16_t local, std::uint16_t remote) noexcept {
        const auto previous = Lookup(socket);
        Store(socket, local == 0 ? previous[0] : local,
              remote == 0 ? previous[1] : remote);
    }

    void Forget(SOCKET socket) noexcept {
        const auto key = static_cast<std::uintptr_t>(socket);
        const auto start = Hash(key);
        for (std::size_t probe = 0; probe < kProbeCount; ++probe) {
            auto& entry = entries_[(start + probe) & (kCapacity - 1)];
            const auto found = entry.socket.load(std::memory_order_acquire);
            if (found == kEmpty) break;
            if (found == key) {
                // Keep the occupied key as a tombstone so a collision later in
                // the probe chain remains reachable, but remove stale ports
                // before Windows can reuse the numeric SOCKET handle.
                entry.ports.store(0, std::memory_order_release);
                return;
            }
        }
    }

    std::array<std::uint16_t, 2> Lookup(SOCKET socket) const noexcept {
        const auto key = static_cast<std::uintptr_t>(socket);
        const auto start = Hash(key);
        for (std::size_t probe = 0; probe < kProbeCount; ++probe) {
            const auto& entry = entries_[(start + probe) & (kCapacity - 1)];
            const auto found = entry.socket.load(std::memory_order_acquire);
            if (found == kEmpty) break;
            if (found == key) {
                const auto packed = entry.ports.load(std::memory_order_acquire);
                return {static_cast<std::uint16_t>(packed & 0xffffU),
                        static_cast<std::uint16_t>(packed >> 16U)};
            }
        }
        return {};
    }

private:
    static constexpr std::size_t kCapacity = 4096;
    static constexpr std::size_t kProbeCount = 16;
    static constexpr std::uintptr_t kEmpty = (std::numeric_limits<std::uintptr_t>::max)();
    struct Entry {
        std::atomic<std::uintptr_t> socket{};
        std::atomic<std::uint32_t> ports{};
    };
    static std::size_t Hash(std::uintptr_t key) noexcept {
        key ^= key >> 16U;
        key *= static_cast<std::uintptr_t>(0x7feb352dU);
        key ^= key >> 15U;
        return static_cast<std::size_t>(key) & (kCapacity - 1);
    }
    std::array<Entry, kCapacity> entries_{};
};

} // namespace

struct WinsockHookController::Impl final {
    using SendFn = int (WSAAPI*)(SOCKET, const char*, int, int);
    using SendToFn = int (WSAAPI*)(SOCKET, const char*, int, int, const sockaddr*, int);
    using RecvFn = int (WSAAPI*)(SOCKET, char*, int, int);
    using RecvFromFn = int (WSAAPI*)(SOCKET, char*, int, int, sockaddr*, int*);
    using WsaSendFn = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD,
                                    LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
    using WsaSendToFn = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD,
                                      const sockaddr*, int, LPWSAOVERLAPPED,
                                      LPWSAOVERLAPPED_COMPLETION_ROUTINE);
    using WsaRecvFn = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD,
                                    LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
    using WsaRecvFromFn = int (WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, LPDWORD,
                                        sockaddr*, LPINT, LPWSAOVERLAPPED,
                                        LPWSAOVERLAPPED_COMPLETION_ROUTINE);
    using WsaRecvExFn = int (WSAAPI*)(SOCKET, char*, int, int*);
    using GetNameFn = int (WSAAPI*)(SOCKET, sockaddr*, int*);
    using BindFn = int (WSAAPI*)(SOCKET, const sockaddr*, int);
    using ConnectFn = int (WSAAPI*)(SOCKET, const sockaddr*, int);
    using WsaConnectFn = int (WSAAPI*)(SOCKET, const sockaddr*, int, LPWSABUF,
                                       LPWSABUF, LPQOS, LPQOS);
    using AcceptFn = SOCKET (WSAAPI*)(SOCKET, sockaddr*, int*);
    using WsaAcceptFn = SOCKET (WSAAPI*)(SOCKET, sockaddr*, LPINT,
        LPCONDITIONPROC, DWORD_PTR);
    using CloseSocketFn = int (WSAAPI*)(SOCKET);

    Impl(bool suspended, FrameSender packets, FrameSender events)
        : suspended_launch(suspended), packet_sender(std::move(packets)),
          event_sender(std::move(events)) {}

    bool suspended_launch{};
    FrameSender packet_sender;
    FrameSender event_sender;
    struct TriggerCallbacks {
        SendTrigger send;
        StoreTrigger store;
    };
    std::atomic<std::shared_ptr<const TriggerCallbacks>> trigger_callbacks;
    struct TriggerNode {
        FilterTrigger trigger;
        TriggerNode* next{};
        explicit TriggerNode(FilterTrigger value) : trigger(std::move(value)) {}
    };
    static constexpr std::size_t kMaximumTriggerCount = 8192;
    static constexpr std::size_t kMaximumTriggerBytes = 16U * 1024U * 1024U;
    std::atomic<TriggerNode*> trigger_head{};
    std::atomic<std::size_t> trigger_count{};
    std::atomic<std::size_t> trigger_bytes{};
    std::atomic<std::uint64_t> trigger_dropped{};
    std::atomic<bool> trigger_running{};
    std::mutex trigger_wait_mutex;
    std::condition_variable trigger_changed;
    std::thread trigger_worker;
    FilterEngine filter_engine;
    HookManager manager;
    PacketRing ring;
    mutable std::mutex lifecycle_mutex;
    std::array<bool, 12> flags{};
    WinsockSupport support{};
    std::vector<void*> targets;
    std::array<std::atomic<std::int64_t>, 11> counters{};
    std::atomic<std::int64_t> sequence{};
    std::atomic<bool> speed_mode{};
    std::atomic<std::shared_ptr<const CaptureFilterSnapshot>> capture_filter;
    std::atomic<bool> accepting{};
    std::atomic<bool> writer_running{};
    std::atomic<std::uint32_t> in_flight{};
    std::mutex in_flight_mutex;
    std::condition_variable in_flight_changed;
    std::thread writer;
    std::uint64_t reported_dropped{};
    std::atomic<std::uint64_t> delivery_dropped{};
    std::atomic<std::size_t> capture_hook_count{};
    SocketPortCache endpoint_ports;

    FilterResult ApplyFilter(const FilterContext& context,
                             std::span<const std::uint8_t> bytes) noexcept {
        auto result = filter_engine.Apply(context, bytes);
        // Detours only transfer immutable trigger records to the bounded
        // lock-free stack. Callbacks (locks, thread creation, IPC encoding)
        // run on trigger_worker, never on the target's Winsock thread.
        for (auto& trigger : result.triggers) (void)EnqueueTrigger(std::move(trigger));
        return result;
    }

    static bool Reserve(std::atomic<std::size_t>& value, std::size_t amount,
                        std::size_t limit) noexcept {
        auto current = value.load(std::memory_order_relaxed);
        for (;;) {
            if (current > limit || amount > limit - current) return false;
            if (value.compare_exchange_weak(current, current + amount,
                                             std::memory_order_acq_rel,
                                             std::memory_order_relaxed)) return true;
        }
    }

    bool EnqueueTrigger(FilterTrigger trigger) noexcept {
        if (!trigger_running.load(std::memory_order_acquire)) {
            trigger_dropped.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        TriggerNode* node = nullptr;
        try { node = new TriggerNode(std::move(trigger)); }
        catch (...) {
            trigger_dropped.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        const auto bytes = node->trigger.bytes.size();
        const bool count_reserved = Reserve(trigger_count, 1, kMaximumTriggerCount);
        const bool bytes_reserved = count_reserved &&
            Reserve(trigger_bytes, bytes, kMaximumTriggerBytes);
        if (!count_reserved || !bytes_reserved) {
            if (count_reserved) trigger_count.fetch_sub(1, std::memory_order_acq_rel);
            trigger_dropped.fetch_add(1, std::memory_order_relaxed);
            delete node;
            return false;
        }
        if (!trigger_running.load(std::memory_order_acquire)) {
            trigger_count.fetch_sub(1, std::memory_order_acq_rel);
            trigger_bytes.fetch_sub(bytes, std::memory_order_acq_rel);
            trigger_dropped.fetch_add(1, std::memory_order_relaxed);
            delete node;
            return false;
        }
        auto* head = trigger_head.load(std::memory_order_relaxed);
        do { node->next = head; }
        while (!trigger_head.compare_exchange_weak(head, node,
                                                   std::memory_order_release,
                                                   std::memory_order_relaxed));
        trigger_changed.notify_one();
        return true;
    }

    void TriggerLoop() noexcept {
        for (;;) {
            auto* list = trigger_head.exchange(nullptr, std::memory_order_acq_rel);
            if (!list) {
                if (!trigger_running.load(std::memory_order_acquire)) break;
                std::unique_lock lock(trigger_wait_mutex);
                trigger_changed.wait_for(lock, std::chrono::milliseconds(10), [&] {
                    return !trigger_running.load(std::memory_order_acquire) ||
                           trigger_head.load(std::memory_order_acquire) != nullptr;
                });
                continue;
            }
            TriggerNode* ordered = nullptr;
            std::size_t count = 0;
            std::size_t bytes = 0;
            while (list) {
                auto* next = list->next;
                list->next = ordered;
                ordered = list;
                ++count;
                bytes += list->trigger.bytes.size();
                list = next;
            }
            trigger_count.fetch_sub(count, std::memory_order_acq_rel);
            trigger_bytes.fetch_sub(bytes, std::memory_order_acq_rel);
            while (ordered) {
                auto* next = ordered->next;
                try {
                    const auto callbacks = trigger_callbacks.load(std::memory_order_acquire);
                    if (callbacks && ordered->trigger.type == FilterExecuteType::Send && callbacks->send)
                        callbacks->send(ordered->trigger.id);
                    else if (callbacks && ordered->trigger.type == FilterExecuteType::WareHouse && callbacks->store)
                        callbacks->store(ordered->trigger.id, ordered->trigger.bytes);
                } catch (...) {}
                delete ordered;
                ordered = next;
            }
        }
        // StopHook quiesces detours before calling this routine, so no new
        // producers remain. Drain anything published just before the stop.
        auto* list = trigger_head.exchange(nullptr, std::memory_order_acq_rel);
        while (list) { auto* next = list->next; delete list; list = next; }
        trigger_count.store(0, std::memory_order_release);
        trigger_bytes.store(0, std::memory_order_release);
    }

    void StopTriggerWorker() noexcept {
        trigger_running.store(false, std::memory_order_release);
        trigger_changed.notify_all();
        if (trigger_worker.joinable() && trigger_worker.get_id() != std::this_thread::get_id())
            trigger_worker.join();
        else if (trigger_worker.joinable()) trigger_worker.detach();
        auto* list = trigger_head.exchange(nullptr, std::memory_order_acq_rel);
        while (list) { auto* next = list->next; delete list; list = next; }
        trigger_count.store(0, std::memory_order_release);
        trigger_bytes.store(0, std::memory_order_release);
    }

    SendFn ws1_send{};
    SendToFn ws1_send_to{};
    RecvFn ws1_recv{};
    RecvFromFn ws1_recv_from{};
    SendFn ws2_send{};
    SendToFn ws2_send_to{};
    RecvFn ws2_recv{};
    RecvFromFn ws2_recv_from{};
    WsaSendFn wsa_send{};
    WsaSendToFn wsa_send_to{};
    WsaRecvFn wsa_recv{};
    WsaRecvFromFn wsa_recv_from{};
    WsaRecvExFn wsa_recv_ex{};
    GetNameFn get_sock_name{};
    GetNameFn get_peer_name{};
    BindFn hook_bind{};
    ConnectFn hook_connect{};
    WsaConnectFn hook_wsa_connect{};
    AcceptFn hook_accept{};
    WsaAcceptFn hook_wsa_accept{};
    CloseSocketFn hook_close_socket{};
    GetNameFn hook_get_sock_name{};
    GetNameFn hook_get_peer_name{};
    // Raw exports used by active replay. When the export is detoured, the
    // replay TLS guard makes the detour jump directly to its trampoline so a
    // user-triggered replay is not filtered/captured a second time.
    SendFn replay_ws1_send{};
    SendToFn replay_ws1_send_to{};
    SendFn replay_ws2_send{};
    SendToFn replay_ws2_send_to{};

    static std::atomic<Impl*> active;

    struct CallGuard final {
        Impl* owner{};
        CallGuard() noexcept {
            AcquireSRWLockShared(&g_detour_entry_gate);
            owner = active.load(std::memory_order_acquire);
            if (owner) owner->in_flight.fetch_add(1, std::memory_order_acq_rel);
            ReleaseSRWLockShared(&g_detour_entry_gate);
        }
        ~CallGuard() {
            if (!owner) return;
            if (owner->in_flight.fetch_sub(1, std::memory_order_acq_rel) == 1)
                owner->in_flight_changed.notify_all();
        }
        CallGuard(const CallGuard&) = delete;
        CallGuard& operator=(const CallGuard&) = delete;
    };

    template<class T>
    void Add(const char* module, const char* procedure, void* detour, T& original) {
        void* raw = nullptr;
        auto* target = manager.Create(module, procedure, detour, &raw);
        original = reinterpret_cast<T>(raw);
        targets.push_back(target);
    }

    void ResolveNameFunctions() noexcept {
        const auto module = GetModuleHandleW(L"ws2_32.dll");
        if (!module) return;
        get_sock_name = reinterpret_cast<GetNameFn>(GetProcAddress(module, "getsockname"));
        get_peer_name = reinterpret_cast<GetNameFn>(GetProcAddress(module, "getpeername"));
    }

    void ResolveReplayFunctions() noexcept {
        if (const auto module = GetModuleHandleW(L"wsock32.dll")) {
            replay_ws1_send = reinterpret_cast<SendFn>(GetProcAddress(module, "send"));
            replay_ws1_send_to = reinterpret_cast<SendToFn>(GetProcAddress(module, "sendto"));
        }
        if (const auto module = GetModuleHandleW(L"ws2_32.dll")) {
            replay_ws2_send = reinterpret_cast<SendFn>(GetProcAddress(module, "send"));
            replay_ws2_send_to = reinterpret_cast<SendToFn>(GetProcAddress(module, "sendto"));
        }
    }

    WinsockSupport Detect(bool may_load) {
        if (may_load && suspended_launch) {
            if (!GetModuleHandleW(L"wsock32.dll")) (void)LoadLibraryW(L"wsock32.dll");
            if (!GetModuleHandleW(L"ws2_32.dll")) (void)LoadLibraryW(L"ws2_32.dll");
            if (!GetModuleHandleW(L"mswsock.dll")) (void)LoadLibraryW(L"mswsock.dll");
        }
        support = WinsockSupport{
            GetModuleHandleW(L"wsock32.dll") != nullptr,
            GetModuleHandleW(L"ws2_32.dll") != nullptr,
            GetModuleHandleW(L"mswsock.dll") != nullptr,
        };
        ResolveNameFunctions();
        ResolveReplayFunctions();
        return support;
    }

    SocketInfo QuerySocketInfo(SOCKET socket) {
        SocketInfo result{Text{u""}, Text{u""}};
        sockaddr_storage local{};
        sockaddr_storage remote{};
        int local_length = sizeof(local);
        int remote_length = sizeof(remote);
        if (get_sock_name && get_sock_name(socket, reinterpret_cast<sockaddr*>(&local),
                                           &local_length) != SOCKET_ERROR) {
            const auto formatted = FormatIpv4(reinterpret_cast<const sockaddr*>(&local),
                                              local_length);
            if (!formatted.empty()) result.from = AsciiText(formatted);
        }
        if (get_peer_name && get_peer_name(socket, reinterpret_cast<sockaddr*>(&remote),
                                           &remote_length) != SOCKET_ERROR) {
            const auto formatted = FormatIpv4(reinterpret_cast<const sockaddr*>(&remote),
                                              remote_length);
            if (!formatted.empty()) result.to = AsciiText(formatted);
        }
        endpoint_ports.Store(socket,
            Ipv4Port(reinterpret_cast<const sockaddr*>(&local), local_length),
            Ipv4Port(reinterpret_cast<const sockaddr*>(&remote), remote_length));
        return result;
    }

    bool Replay(const ReplayPacketSnapshot& packet) noexcept {
        if (packet.socket <= 0 || !packet.bytes || packet.bytes->empty() ||
            packet.bytes->size() > static_cast<std::size_t>((std::numeric_limits<int>::max)()))
            return false;
        const auto socket = static_cast<SOCKET>(static_cast<std::uint32_t>(packet.socket));
        const auto* bytes = reinterpret_cast<const char*>(packet.bytes->data());
        const auto length = static_cast<int>(packet.bytes->size());
        SendFn stream = nullptr;
        SendToFn datagram = nullptr;
        const Text* address = nullptr;
        switch (packet.packet_type) {
        case 0: case 4:
            stream = replay_ws1_send;
            break;
        case 1: case 5: case 8: case 10: case 11: case 13: case 15:
            stream = replay_ws2_send;
            break;
        case 2:
            datagram = replay_ws1_send_to; address = &packet.to;
            break;
        case 6:
            datagram = replay_ws1_send_to; address = &packet.from;
            break;
        case 3: case 9: case 14:
            datagram = replay_ws2_send_to; address = &packet.to;
            break;
        case 7: case 12: case 16:
            datagram = replay_ws2_send_to; address = &packet.from;
            break;
        default:
            return false;
        }
        ReplayCallGuard replay_guard;
        if (stream) return stream(socket, bytes, length, 0) > 0;
        sockaddr_in endpoint{};
        if (!datagram || !address || !ParseIpv4Endpoint(*address, endpoint)) return false;
        return datagram(socket, bytes, length, 0,
                        reinterpret_cast<const sockaddr*>(&endpoint), sizeof(endpoint)) > 0;
    }

    void Count(std::uint8_t type, std::size_t length) noexcept {
        if (length == 0) return;
        counters[0].fetch_add(1, std::memory_order_relaxed);
        std::size_t count_index = 0;
        bool sending = false;
        switch (type) {
        case kWs1Send: case kWs2Send: count_index = 1; sending = true; break;
        case kWs1SendTo: case kWs2SendTo: count_index = 2; sending = true; break;
        case kWs1Recv: case kWs2Recv: count_index = 3; break;
        case kWs1RecvFrom: case kWs2RecvFrom: count_index = 4; break;
        case kWsaSend: count_index = 5; sending = true; break;
        case kWsaSendTo: count_index = 6; sending = true; break;
        case kWsaRecv: case kWsaRecvEx: count_index = 7; break;
        case kWsaRecvFrom: count_index = 8; break;
        default: return;
        }
        counters[count_index].fetch_add(1, std::memory_order_relaxed);
        counters[sending ? 9 : 10].fetch_add(static_cast<std::int64_t>(length),
                                             std::memory_order_relaxed);
    }

    void EmitFilterLog(const PendingFilterLog& record) noexcept {
        if (!event_sender) return;
        try {
            IpcWriter writer_event;
            writer_event.U8(static_cast<std::uint8_t>(IpcEvent::FilterLog));
            writer_event.Str(record.name);
            writer_event.I32(record.action);
            writer_event.I32(record.matches);
            writer_event.I32(record.packet_type);
            writer_event.I32(record.packet_length);
            event_sender(writer_event.ToArray());
        } catch (...) {}
    }

    FilterContext Context(SOCKET socket, std::uint8_t type,
                          const sockaddr* address, int address_length) const noexcept {
        FilterContext context;
        context.socket = static_cast<std::int64_t>(socket);
        context.packet_type = type;
        // Address strings are filled on the writer thread (where the allowed
        // getsockname/getpeername calls happen).  Detours only retain an
        // explicit sendto/recvfrom endpoint here.
        if (address) context.addresses[1] = FormatIpv4(address, address_length);
        const auto append = [&](const sockaddr* candidate, int length) {
            if (!candidate || length < static_cast<int>(sizeof(sockaddr_in)) ||
                context.port_count >= context.ports.size()) return;
            sockaddr_in copy{};
            if (!TryCopyMemory(&copy, candidate, sizeof(copy)) || copy.sin_family != AF_INET) return;
            const auto port = ntohs(copy.sin_port);
            if (std::find(context.ports.begin(), context.ports.begin() +
                          static_cast<std::ptrdiff_t>(context.port_count), port) ==
                context.ports.begin() + static_cast<std::ptrdiff_t>(context.port_count))
                context.ports[context.port_count++] = port;
        };
        append(address, address_length);
        const auto cached = endpoint_ports.Lookup(socket);
        for (const auto port : cached) {
            if (port == 0 || context.port_count >= context.ports.size()) continue;
            if (std::find(context.ports.begin(), context.ports.begin() +
                          static_cast<std::ptrdiff_t>(context.port_count), port) ==
                context.ports.begin() + static_cast<std::ptrdiff_t>(context.port_count))
                context.ports[context.port_count++] = port;
        }
        return context;
    }

    static FilterContext ContextFromEndpoints(const PendingPacket& packet,
                                              const std::pair<std::string, std::string>& endpoints) {
        FilterContext context;
        context.socket = packet.socket;
        context.packet_type = packet.packet_type;
        context.addresses = {endpoints.first, endpoints.second};
        for (const auto& endpoint : context.addresses) {
            const auto colon = endpoint.rfind(':');
            if (colon == std::string::npos || context.port_count >= context.ports.size()) continue;
            unsigned int port = 0;
            const auto parsed = std::from_chars(endpoint.data() + colon + 1,
                                                 endpoint.data() + endpoint.size(), port);
            if (parsed.ec == std::errc{} && parsed.ptr == endpoint.data() + endpoint.size() && port <= 65535)
                context.ports[context.port_count++] = static_cast<std::uint16_t>(port);
        }
        return context;
    }

    static bool ContainsSocket(std::string_view value, std::int64_t socket) noexcept {
        for (auto token : Tokens(std::string(value))) {
            std::int64_t parsed = 0;
            const auto result = std::from_chars(token.data(), token.data() + token.size(), parsed);
            if (result.ec == std::errc{} && result.ptr == token.data() + token.size() && parsed == socket) return true;
        }
        return false;
    }

    static bool ContainsPort(std::string_view value, const FilterContext& context) noexcept {
        for (auto token : Tokens(std::string(value))) {
            unsigned int parsed = 0;
            const auto result = std::from_chars(token.data(), token.data() + token.size(), parsed);
            if (result.ec != std::errc{} || result.ptr != token.data() + token.size() || parsed > 65535) continue;
            for (std::size_t i = 0; i < context.port_count; ++i) if (context.ports[i] == parsed) return true;
        }
        return false;
    }

    static bool ContainsIp(std::string_view value, const FilterContext& context) {
        for (const auto& address : context.addresses) {
            if (address.empty()) continue;
            const auto colon = address.find(':');
            const auto ip = address.substr(0, colon);
            for (auto token : Tokens(std::string(value))) if (token == ip) return true;
        }
        return false;
    }

    static bool StartsWithHex(std::string_view value, std::span<const std::uint8_t> bytes) {
        return value.size() >= bytes.size() * 2 && value.substr(0, bytes.size() * 2) == HexText(bytes);
    }

    static bool ContainsHead(std::string_view value, std::string_view patterns) {
        for (const auto& token : Tokens(std::string(patterns))) {
            const auto parsed = ParseHex(token);
            if (parsed && StartsWithHex(value, *parsed)) return true;
        }
        return false;
    }

    static bool ContainsData(std::string_view value, std::span<const std::uint8_t> bytes,
                             std::string_view patterns) {
        for (auto token : Tokens(std::string(patterns))) {
            const auto raw_token = token;
            token.erase(std::remove_if(token.begin(), token.end(), [](unsigned char c) { return std::isspace(c) != 0; }), token.end());
            std::transform(token.begin(), token.end(), token.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
            if (!token.empty() && value.find(token) != std::string::npos) return true;
            // The original UI advertises both hex and text.  Retain the
            // original hex-substring behavior and additionally match a raw
            // ASCII/UTF-8 token against the captured bytes.
            if (!raw_token.empty() && std::search(bytes.begin(), bytes.end(), raw_token.begin(), raw_token.end(),
                [](std::uint8_t byte, char character) {
                    return static_cast<unsigned char>(std::toupper(byte)) ==
                           static_cast<unsigned char>(std::toupper(static_cast<unsigned char>(character)));
                }) != bytes.end()) return true;
        }
        return false;
    }

    static bool ContainsLength(std::string_view value, std::size_t length) noexcept {
        for (auto token : Tokens(std::string(value))) {
            const auto dash = token.find('-');
            unsigned int low = 0, high = 0;
            if (dash == std::string::npos) {
                const auto parsed = std::from_chars(token.data(), token.data() + token.size(), low);
                if (parsed.ec == std::errc{} && parsed.ptr == token.data() + token.size() && length == low) return true;
                continue;
            }
            const auto left = std::from_chars(token.data(), token.data() + dash, low);
            const auto right = std::from_chars(token.data() + dash + 1, token.data() + token.size(), high);
            if (left.ec == std::errc{} && right.ec == std::errc{} && left.ptr == token.data() + dash &&
                right.ptr == token.data() + token.size() && low <= high && length >= low && length <= high) return true;
        }
        return false;
    }

    static std::optional<std::size_t> TypeIndex(std::uint8_t type) noexcept {
        switch (type) {
        case kWs1Send: case kWs2Send: return 0;
        case kWs1SendTo: case kWs2SendTo: return 1;
        case kWs1Recv: case kWs2Recv: return 2;
        case kWs1RecvFrom: case kWs2RecvFrom: return 3;
        case kWsaSend: return 4;
        case kWsaSendTo: return 5;
        case kWsaRecv: case kWsaRecvEx: return 6;
        case kWsaRecvFrom: return 7;
        default: return std::nullopt;
        }
    }

    bool CaptureFilterAllows(const FilterContext& context, std::span<const std::uint8_t> bytes) const noexcept {
        const auto filter = capture_filter.load(std::memory_order_acquire);
        if (!filter) return true;
        const auto check = [&](bool enabled, bool matched) { return !enabled || filter->not_show != matched; };
        bool any = filter->check_socket || filter->check_ip || filter->check_port || filter->check_head ||
                   filter->check_data || filter->check_length || filter->check_type;
        if (!any) return true;
        try {
            const auto hex = HexText(bytes);
            if (!check(filter->check_socket, ContainsSocket(Ascii(filter->socket_value), context.socket))) return false;
            if (!check(filter->check_ip, ContainsIp(Ascii(filter->ip_value), context))) return false;
            if (!check(filter->check_port, ContainsPort(Ascii(filter->port_value), context))) return false;
            if (!check(filter->check_head, ContainsHead(hex, Ascii(filter->head_value))) ) return false;
            if (!check(filter->check_data, ContainsData(hex, bytes, Ascii(filter->data_value)))) return false;
            if (!check(filter->check_length, ContainsLength(Ascii(filter->length_value), bytes.size()))) return false;
            if (filter->check_type) {
                const auto index = TypeIndex(context.packet_type);
                const bool matched = index && filter->type_flags[*index];
                if (!check(true, matched)) return false;
            }
        } catch (...) {
            // Invalid user text must not break a target detour.  Treat it as
            // a non-match, which is the original UI's fail-open behavior.
            return true;
        }
        return true;
    }

    void Capture(SOCKET socket, std::uint8_t type,
                 std::shared_ptr<const ByteBuffer> raw,
                 std::shared_ptr<const ByteBuffer> modified,
                 std::uint8_t filter_action,
                 std::size_t logical_length,
                 std::vector<PendingFilterLog> filter_logs,
                 const sockaddr* address = nullptr, int address_length = 0,
        std::int64_t time_ticks = 0) noexcept {
        if (!accepting.load(std::memory_order_acquire)) return;
        bool deliver_packet =
            filter_action != static_cast<std::uint8_t>(FilterAction::NoModifyNoDisplay) &&
            (filter_action == static_cast<std::uint8_t>(FilterAction::Intercept) ||
             logical_length != 0);
        // Match the original OnPacket order: intercepted receives are still
        // counted/displayed even though the caller observes a zero return, and
        // byte counters describe the post-filter buffer rather than a partial
        // send return. If capture allocation failed, the supplied logical
        // length remains the best available accounting value.
        if (deliver_packet) Count(type, modified ? modified->size() : logical_length);
        if (speed_mode.load(std::memory_order_relaxed)) return;
        if (deliver_packet && (!raw || raw->empty() || !modified || modified->empty())) {
            delivery_dropped.fetch_add(1, std::memory_order_relaxed);
            ring.Wake();
            deliver_packet = false;
        }
        if (!deliver_packet && filter_logs.empty()) return;
        try {
            auto packet = std::make_shared<PendingPacket>();
            packet->id = sequence.fetch_add(1, std::memory_order_relaxed) + 1;
            packet->time_ticks = time_ticks == 0 ? DateTimeTicksNow() : time_ticks;
            packet->socket = static_cast<std::int64_t>(socket);
            packet->packet_type = type;
            packet->filter_action = filter_action;
            packet->raw = std::move(raw);
            packet->modified = std::move(modified);
            packet->filter_logs = std::move(filter_logs);
            packet->suppress_packet = !deliver_packet;
            if (address && address_length > 0) {
                const auto length = std::min<std::size_t>(
                    static_cast<std::size_t>(address_length), packet->socket_address.size());
                if (TryCopyMemory(packet->socket_address.data(), address, length))
                    packet->socket_address_length = length;
            }
            ring.Enqueue(std::move(packet));
        } catch (...) {
            // A capture allocation failure must never change the target's I/O,
            // but it still represents a visible packet-delivery loss.
            delivery_dropped.fetch_add(1, std::memory_order_relaxed);
            ring.Wake();
        }
    }

    std::pair<std::string, std::string> Endpoints(const PendingPacket& packet) {
        sockaddr_storage local{};
        sockaddr_storage remote{};
        int local_length = sizeof(local);
        int remote_length = sizeof(remote);
        if (!get_sock_name || get_sock_name(static_cast<SOCKET>(packet.socket),
                reinterpret_cast<sockaddr*>(&local), &local_length) == SOCKET_ERROR) return {};
        if (packet.socket_address_length != 0) {
            remote_length = static_cast<int>(std::min(packet.socket_address_length, sizeof(remote)));
            std::memcpy(&remote, packet.socket_address.data(), static_cast<std::size_t>(remote_length));
        } else if (!get_peer_name || get_peer_name(static_cast<SOCKET>(packet.socket),
                       reinterpret_cast<sockaddr*>(&remote), &remote_length) == SOCKET_ERROR) {
            return {};
        }
        auto from = FormatIpv4(reinterpret_cast<const sockaddr*>(&local), local_length);
        auto to = FormatIpv4(reinterpret_cast<const sockaddr*>(&remote), remote_length);
        if (from.empty() || to.empty()) return {};
        endpoint_ports.Store(static_cast<SOCKET>(packet.socket),
                             Ipv4Port(reinterpret_cast<const sockaddr*>(&local), local_length),
                             Ipv4Port(reinterpret_cast<const sockaddr*>(&remote), remote_length));
        return {std::move(from), std::move(to)};
    }

    void ReportDropped() noexcept {
        const auto dropped = ring.Dropped() + delivery_dropped.load(std::memory_order_relaxed);
        if (dropped == reported_dropped || !event_sender) return;
        try {
            IpcWriter writer_event;
            writer_event.U8(static_cast<std::uint8_t>(IpcEvent::Dropped));
            writer_event.I64(static_cast<std::int64_t>(dropped));
            event_sender(writer_event.ToArray());
            reported_dropped = dropped;
        } catch (...) {}
    }

    void WriterLoop() noexcept {
        while (writer_running.load(std::memory_order_acquire)) {
            std::vector<PacketRing::Item> batch;
            std::size_t next = 0;
            bool delivery_failed = false;
            try {
                batch = ring.DequeueBatch(256, 1024 * 1024,
                                          std::chrono::milliseconds(5));
                for (; next < batch.size(); ++next) {
                    if (!writer_running.load(std::memory_order_relaxed)) {
                        next = batch.size(); // intentional teardown, not a delivery loss
                        break;
                    }
                    const auto& pending = batch[next];
                    if (pending->suppress_packet) {
                        for (const auto& log : pending->filter_logs) EmitFilterLog(log);
                        continue;
                    }
                    const auto endpoints = Endpoints(*pending);
                    if (endpoints.first.empty() || !packet_sender) {
                        delivery_dropped.fetch_add(1, std::memory_order_relaxed);
                        continue;
                    }
                    const auto capture_context = ContextFromEndpoints(*pending, endpoints);
                    const auto capture_bytes = pending->modified && !pending->modified->empty()
                        ? std::span<const std::uint8_t>(*pending->modified)
                        : (pending->raw ? std::span<const std::uint8_t>(*pending->raw)
                                        : std::span<const std::uint8_t>{});
                    if (!CaptureFilterAllows(capture_context, capture_bytes)) continue;
                    for (const auto& log : pending->filter_logs) EmitFilterLog(log);
                    try {
                        Packet packet;
                        packet.id = pending->id;
                        packet.time_ticks = pending->time_ticks;
                        packet.socket = pending->socket;
                        packet.packet_type = pending->packet_type;
                        packet.filter_action = pending->filter_action;
                        packet.from = AsciiText(endpoints.first);
                        packet.to = AsciiText(endpoints.second);
                        packet.raw = *pending->raw;
                        packet.modified = *pending->modified;
                        packet_sender(PacketFrame::Encode(packet));
                    } catch (...) {
                        std::uint64_t lost_packets = 0;
                        for (std::size_t i = next; i < batch.size(); ++i)
                            if (!batch[i]->suppress_packet) ++lost_packets;
                        delivery_dropped.fetch_add(lost_packets, std::memory_order_relaxed);
                        delivery_failed = true;
                        next = batch.size();
                        break;
                    }
                }
            } catch (...) {
                // The batch has already left the ring. Account for every item
                // that an allocation/endpoint-formatting failure prevented us
                // from delivering instead of silently destroying the batch.
                if (writer_running.load(std::memory_order_relaxed) && next < batch.size()) {
                    std::uint64_t lost_packets = 0;
                    for (std::size_t i = next; i < batch.size(); ++i)
                        if (!batch[i]->suppress_packet) ++lost_packets;
                    delivery_dropped.fetch_add(lost_packets, std::memory_order_relaxed);
                    delivery_failed = true;
                }
            }
            ReportDropped();
            if (delivery_failed && writer_running.load(std::memory_order_relaxed))
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    void StopWriter() noexcept {
        writer_running.store(false, std::memory_order_release);
        ring.Wake();
        if (writer.joinable() && writer.get_id() != std::this_thread::get_id()) writer.join();
        ring.Clear();
    }

    bool WaitForDetours(std::chrono::milliseconds timeout) noexcept {
        std::unique_lock lock(in_flight_mutex);
        return in_flight_changed.wait_for(lock, timeout, [&] {
            return in_flight.load(std::memory_order_acquire) == 0;
        });
    }

    bool QuiesceAndShutdown(std::chrono::milliseconds timeout) noexcept {
        accepting.store(false, std::memory_order_release);
        // Close admission while holding the same gate every detour takes
        // before publishing its in-flight lease. Once this exchange completes,
        // every call that retained this owner is already represented in
        // in_flight; a thread that jumped to a detour just before MinHook is
        // disabled can no longer acquire the soon-to-be-retired owner.
        AcquireSRWLockExclusive(&g_detour_entry_gate);
        auto* expected = this;
        (void)active.compare_exchange_strong(expected, nullptr,
                                             std::memory_order_acq_rel);
        ReleaseSRWLockExclusive(&g_detour_entry_gate);
        if (!manager.DisableAll()) return false;
        if (!WaitForDetours(timeout)) return false;
        if (!manager.Shutdown()) return false;
        targets.clear();
        capture_hook_count.store(0, std::memory_order_release);
        return true;
    }

    void RetireUntilSafe() noexcept {
        StopWriter();
        while (!QuiesceAndShutdown(std::chrono::milliseconds(500)))
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        StopTriggerWorker();
    }

    int OnBind(BindFn original, SOCKET socket, const sockaddr* address,
               int address_length) noexcept {
        const int result = original(socket, address, address_length);
        const int saved_error = WSAGetLastError();
        if (result != SOCKET_ERROR)
            endpoint_ports.Merge(socket, TryIpv4Port(address, address_length), 0);
        WSASetLastError(saved_error);
        return result;
    }

    int OnConnect(ConnectFn original, SOCKET socket, const sockaddr* address,
                  int address_length) noexcept {
        const int result = original(socket, address, address_length);
        const int saved_error = WSAGetLastError();
        if (result != SOCKET_ERROR)
            endpoint_ports.Merge(socket, 0, TryIpv4Port(address, address_length));
        WSASetLastError(saved_error);
        return result;
    }

    int OnWsaConnect(WsaConnectFn original, SOCKET socket, const sockaddr* address,
                     int address_length, LPWSABUF caller_data, LPWSABUF callee_data,
                     LPQOS sqos, LPQOS gqos) noexcept {
        const int result = original(socket, address, address_length, caller_data,
                                    callee_data, sqos, gqos);
        const int saved_error = WSAGetLastError();
        if (result != SOCKET_ERROR)
            endpoint_ports.Merge(socket, 0, TryIpv4Port(address, address_length));
        WSASetLastError(saved_error);
        return result;
    }

    SOCKET OnAccept(AcceptFn original, SOCKET listener, sockaddr* address,
                    int* address_length) noexcept {
        const SOCKET accepted = original(listener, address, address_length);
        const int saved_error = WSAGetLastError();
        if (accepted != INVALID_SOCKET) {
            int length = 0;
            if (address_length) (void)TryReadInt(address_length, length);
            endpoint_ports.Merge(accepted, endpoint_ports.Lookup(listener)[0],
                                 TryIpv4Port(address, length));
        }
        WSASetLastError(saved_error);
        return accepted;
    }

    SOCKET OnWsaAccept(WsaAcceptFn original, SOCKET listener, sockaddr* address,
                       LPINT address_length, LPCONDITIONPROC condition,
                       DWORD_PTR callback_data) noexcept {
        const SOCKET accepted = original(listener, address, address_length,
                                         condition, callback_data);
        const int saved_error = WSAGetLastError();
        if (accepted != INVALID_SOCKET) {
            int length = 0;
            if (address_length) (void)TryReadInt(address_length, length);
            endpoint_ports.Merge(accepted, endpoint_ports.Lookup(listener)[0],
                                 TryIpv4Port(address, length));
        }
        WSASetLastError(saved_error);
        return accepted;
    }

    int OnCloseSocket(CloseSocketFn original, SOCKET socket) noexcept {
        const int result = original(socket);
        const int saved_error = WSAGetLastError();
        if (result != SOCKET_ERROR) endpoint_ports.Forget(socket);
        WSASetLastError(saved_error);
        return result;
    }

    int OnGetName(GetNameFn original, SOCKET socket, sockaddr* address,
                  int* address_length, bool peer) noexcept {
        const int result = original(socket, address, address_length);
        const int saved_error = WSAGetLastError();
        if (result != SOCKET_ERROR) {
            int length = 0;
            if (address_length) (void)TryReadInt(address_length, length);
            const auto port = TryIpv4Port(address, length);
            endpoint_ports.Merge(socket, peer ? 0 : port, peer ? port : 0);
        }
        WSASetLastError(saved_error);
        return result;
    }

    int OnSend(SendFn original, SOCKET socket, const char* buffer, int length,
               int flags_value, std::uint8_t type) noexcept {
        const auto time_ticks = DateTimeTicksNow();
        std::shared_ptr<const ByteBuffer> raw;
        FilterResult filtered;
        try {
            if (length > 0) {
                raw = CopyBytes(buffer, static_cast<std::size_t>(length));
                if (raw) filtered = ApplyFilter(Context(socket, type, nullptr, 0), *raw);
            }
        } catch (...) {}
        const auto action = filtered.bytes.empty() ? FilterAction::None : filtered.action;
        int result = 0;
        if (action == FilterAction::Intercept) result = length;
        else {
            const char* outgoing = filtered.bytes.empty() ? buffer :
                reinterpret_cast<const char*>(filtered.bytes.data());
            const int outgoing_length = filtered.bytes.empty() ? length :
                static_cast<int>(filtered.bytes.size());
            result = original(socket, outgoing, outgoing_length, flags_value);
        }
        const int saved_error = WSAGetLastError();
        if (result > 0 || raw || !filtered.logs.empty()) {
            auto modified = filtered.bytes.empty() ? raw :
                std::shared_ptr<const ByteBuffer>(std::make_shared<ByteBuffer>(std::move(filtered.bytes)));
            const auto filtered_length = result > 0
                ? (modified ? modified->size() : static_cast<std::size_t>(length)) : 0U;
            Capture(socket, type, std::move(raw), std::move(modified),
                    static_cast<std::uint8_t>(action), filtered_length,
                    std::move(filtered.logs),
                    nullptr, 0, time_ticks);
        }
        WSASetLastError(saved_error);
        return result;
    }

    int OnSendTo(SendToFn original, SOCKET socket, const char* buffer, int length,
                 int flags_value, const sockaddr* to, int to_length,
                 std::uint8_t type) noexcept {
        const auto time_ticks = DateTimeTicksNow();
        std::shared_ptr<const ByteBuffer> raw;
        FilterResult filtered;
        try {
            if (length > 0) {
                raw = CopyBytes(buffer, static_cast<std::size_t>(length));
                if (raw) filtered = ApplyFilter(Context(socket, type, to, to_length), *raw);
            }
        } catch (...) {}
        const auto action = filtered.bytes.empty() ? FilterAction::None : filtered.action;
        int result = 0;
        if (action == FilterAction::Intercept) result = length;
        else {
            const char* outgoing = filtered.bytes.empty() ? buffer :
                reinterpret_cast<const char*>(filtered.bytes.data());
            const int outgoing_length = filtered.bytes.empty() ? length :
                static_cast<int>(filtered.bytes.size());
            result = original(socket, outgoing, outgoing_length, flags_value, to, to_length);
        }
        const int saved_error = WSAGetLastError();
        if (result > 0 || raw || !filtered.logs.empty()) {
            auto modified = filtered.bytes.empty() ? raw :
                std::shared_ptr<const ByteBuffer>(std::make_shared<ByteBuffer>(std::move(filtered.bytes)));
            const auto filtered_length = result > 0
                ? (modified ? modified->size() : static_cast<std::size_t>(length)) : 0U;
            Capture(socket, type, std::move(raw), std::move(modified),
                    static_cast<std::uint8_t>(action), filtered_length,
                    std::move(filtered.logs),
                    to, to_length, time_ticks);
        }
        WSASetLastError(saved_error);
        return result;
    }

    int OnRecv(RecvFn original, SOCKET socket, char* buffer, int length,
               int flags_value, std::uint8_t type) noexcept {
        int result = original(socket, buffer, length, flags_value);
        const int saved_error = WSAGetLastError();
        if (result > 0) {
            try {
                auto raw = CopyBytes(buffer, static_cast<std::size_t>(result));
                if (raw) {
                    auto filtered = ApplyFilter(Context(socket, type, nullptr, 0), *raw);
                    const auto action = filtered.action;
                    if (action == FilterAction::Intercept) result = 0;
                    else {
                        const auto returned = (std::min)(filtered.bytes.size(), static_cast<std::size_t>(result));
                        if (TryCopyMemory(buffer, filtered.bytes.data(), returned))
                            result = static_cast<int>(returned);
                        else
                            filtered.bytes = *raw;
                    }
                    auto modified = std::shared_ptr<const ByteBuffer>(
                        std::make_shared<ByteBuffer>(std::move(filtered.bytes)));
                    Capture(socket, type, std::move(raw), std::move(modified),
                            static_cast<std::uint8_t>(action), static_cast<std::size_t>(result),
                            std::move(filtered.logs));
                }
            }
            catch (...) {}
        }
        WSASetLastError(saved_error);
        return result;
    }

    int OnRecvFrom(RecvFromFn original, SOCKET socket, char* buffer, int length,
                   int flags_value, sockaddr* from, int* from_length,
                   std::uint8_t type) noexcept {
        int result = original(socket, buffer, length, flags_value, from, from_length);
        const int saved_error = WSAGetLastError();
        if (result > 0) {
            try {
                int captured_from_length = 0;
                if (from_length) (void)TryReadInt(from_length, captured_from_length);
                auto raw = CopyBytes(buffer, static_cast<std::size_t>(result));
                if (raw) {
                    auto filtered = ApplyFilter(
                        Context(socket, type, from, captured_from_length), *raw);
                    const auto action = filtered.action;
                    if (action == FilterAction::Intercept) result = 0;
                    else {
                        const auto returned = (std::min)(filtered.bytes.size(), static_cast<std::size_t>(result));
                        if (TryCopyMemory(buffer, filtered.bytes.data(), returned))
                            result = static_cast<int>(returned);
                        else
                            filtered.bytes = *raw;
                    }
                    auto modified = std::shared_ptr<const ByteBuffer>(
                        std::make_shared<ByteBuffer>(std::move(filtered.bytes)));
                    Capture(socket, type, std::move(raw), std::move(modified),
                            static_cast<std::uint8_t>(action), static_cast<std::size_t>(result),
                            std::move(filtered.logs),
                            from, captured_from_length);
                }
            } catch (...) {}
        }
        WSASetLastError(saved_error);
        return result;
    }

    int OnWsaSend(WsaSendFn original, SOCKET socket, LPWSABUF buffers, DWORD count,
                   LPDWORD bytes_sent, DWORD flags_value, LPWSAOVERLAPPED overlapped,
                   LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) noexcept {
        const auto time_ticks = DateTimeTicksNow();
        const auto total_length = TotalBufferLength(buffers, count);
        std::shared_ptr<const ByteBuffer> raw;
        FilterResult filtered;
        try {
            if (total_length) {
                raw = FlattenBuffers(buffers, count, *total_length);
                if (raw && !overlapped)
                    filtered = ApplyFilter(Context(socket, kWsaSend, nullptr, 0), *raw);
            }
        }
        catch (...) {}
        const auto action = filtered.bytes.empty() ? FilterAction::None : filtered.action;
        int result = 0;
        if (action == FilterAction::Intercept) {
            const auto length = total_length.value_or(0);
            result = length <= (std::numeric_limits<DWORD>::max)() && bytes_sent &&
                     TryWriteDword(bytes_sent, static_cast<DWORD>(length)) ? 0 : SOCKET_ERROR;
        } else if (!filtered.bytes.empty()) {
            WSABUF outgoing{static_cast<ULONG>(filtered.bytes.size()),
                            reinterpret_cast<char*>(filtered.bytes.data())};
            result = original(socket, &outgoing, 1, bytes_sent, flags_value, overlapped, completion);
        } else {
            result = original(socket, buffers, count, bytes_sent, flags_value, overlapped, completion);
        }
        const int saved_error = WSAGetLastError();
        DWORD captured_bytes = 0;
        const bool completed = result == 0 && bytes_sent &&
            TryReadDword(bytes_sent, captured_bytes) && captured_bytes > 0;
        if (completed || raw || !filtered.logs.empty()) {
            auto modified = filtered.bytes.empty() ? raw :
                std::shared_ptr<const ByteBuffer>(std::make_shared<ByteBuffer>(std::move(filtered.bytes)));
            const auto filtered_length = completed
                ? (modified ? modified->size() : total_length.value_or(captured_bytes)) : 0U;
            Capture(socket, kWsaSend, std::move(raw), std::move(modified),
                    static_cast<std::uint8_t>(action),
                    filtered_length,
                    std::move(filtered.logs),
                    nullptr, 0, time_ticks);
        }
        WSASetLastError(saved_error);
        return result;
    }

    int OnWsaSendTo(WsaSendToFn original, SOCKET socket, LPWSABUF buffers, DWORD count,
                    LPDWORD bytes_sent, DWORD flags_value, const sockaddr* to, int to_length,
                    LPWSAOVERLAPPED overlapped,
                    LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) noexcept {
        const auto time_ticks = DateTimeTicksNow();
        const auto total_length = TotalBufferLength(buffers, count);
        std::shared_ptr<const ByteBuffer> raw;
        FilterResult filtered;
        try {
            if (total_length) {
                raw = FlattenBuffers(buffers, count, *total_length);
                if (raw && !overlapped)
                    filtered = ApplyFilter(Context(socket, kWsaSendTo, to, to_length), *raw);
            }
        }
        catch (...) {}
        const auto action = filtered.bytes.empty() ? FilterAction::None : filtered.action;
        int result = 0;
        if (action == FilterAction::Intercept) {
            const auto length = total_length.value_or(0);
            result = length <= (std::numeric_limits<DWORD>::max)() && bytes_sent &&
                     TryWriteDword(bytes_sent, static_cast<DWORD>(length)) ? 0 : SOCKET_ERROR;
        } else if (!filtered.bytes.empty()) {
            WSABUF outgoing{static_cast<ULONG>(filtered.bytes.size()),
                            reinterpret_cast<char*>(filtered.bytes.data())};
            result = original(socket, &outgoing, 1, bytes_sent, flags_value, to, to_length,
                              overlapped, completion);
        } else {
            result = original(socket, buffers, count, bytes_sent, flags_value, to,
                              to_length, overlapped, completion);
        }
        const int saved_error = WSAGetLastError();
        DWORD captured_bytes = 0;
        const bool completed = result == 0 && bytes_sent &&
            TryReadDword(bytes_sent, captured_bytes) && captured_bytes > 0;
        if (completed || raw || !filtered.logs.empty()) {
            auto modified = filtered.bytes.empty() ? raw :
                std::shared_ptr<const ByteBuffer>(std::make_shared<ByteBuffer>(std::move(filtered.bytes)));
            const auto filtered_length = completed
                ? (modified ? modified->size() : total_length.value_or(captured_bytes)) : 0U;
            Capture(socket, kWsaSendTo, std::move(raw), std::move(modified),
                    static_cast<std::uint8_t>(action),
                    filtered_length,
                    std::move(filtered.logs),
                    to, to_length, time_ticks);
        }
        WSASetLastError(saved_error);
        return result;
    }

    int OnWsaRecv(WsaRecvFn original, SOCKET socket, LPWSABUF buffers, DWORD count,
                  LPDWORD bytes_received, LPDWORD flags_value, LPWSAOVERLAPPED overlapped,
                  LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) noexcept {
        const int result = original(socket, buffers, count, bytes_received, flags_value,
                                    overlapped, completion);
        const int saved_error = WSAGetLastError();
        DWORD captured_bytes = 0;
        if (result == 0 && bytes_received && TryReadDword(bytes_received, captured_bytes) &&
            captured_bytes > 0) {
            try {
                auto raw = FlattenBuffers(buffers, count, captured_bytes);
                auto filtered = raw && !overlapped
                    ? ApplyFilter(Context(socket, kWsaRecv, nullptr, 0), *raw)
                    : FilterResult{};
                const auto action = filtered.bytes.empty() ? FilterAction::None : filtered.action;
                DWORD returned = captured_bytes;
                if (action == FilterAction::Intercept) returned = 0;
                else if (!filtered.bytes.empty()) {
                    returned = static_cast<DWORD>((std::min)(filtered.bytes.size(),
                                                            static_cast<std::size_t>(captured_bytes)));
                    if (!CopyToBuffers(buffers, count,
                        std::span<const std::uint8_t>(filtered.bytes.data(), returned))) returned = captured_bytes;
                }
                (void)TryWriteDword(bytes_received, returned);
                auto modified = filtered.bytes.empty() ? raw :
                    std::shared_ptr<const ByteBuffer>(std::make_shared<ByteBuffer>(std::move(filtered.bytes)));
                Capture(socket, kWsaRecv, std::move(raw), std::move(modified),
                        static_cast<std::uint8_t>(action), static_cast<std::size_t>(returned),
                        std::move(filtered.logs));
            }
            catch (...) {}
        }
        WSASetLastError(saved_error);
        return result;
    }

    int OnWsaRecvFrom(WsaRecvFromFn original, SOCKET socket, LPWSABUF buffers, DWORD count,
                      LPDWORD bytes_received, LPDWORD flags_value, sockaddr* from,
                      LPINT from_length, LPWSAOVERLAPPED overlapped,
                      LPWSAOVERLAPPED_COMPLETION_ROUTINE completion) noexcept {
        const int result = original(socket, buffers, count, bytes_received, flags_value, from,
                                    from_length, overlapped, completion);
        const int saved_error = WSAGetLastError();
        DWORD captured_bytes = 0;
        if (result == 0 && bytes_received && TryReadDword(bytes_received, captured_bytes) &&
            captured_bytes > 0) {
            try {
                int captured_from_length = 0;
                if (from_length) (void)TryReadInt(from_length, captured_from_length);
                auto raw = FlattenBuffers(buffers, count, captured_bytes);
                auto filtered = raw && !overlapped
                    ? ApplyFilter(Context(socket, kWsaRecvFrom, from, captured_from_length), *raw)
                    : FilterResult{};
                const auto action = filtered.bytes.empty() ? FilterAction::None : filtered.action;
                DWORD returned = captured_bytes;
                if (action == FilterAction::Intercept) returned = 0;
                else if (!filtered.bytes.empty()) {
                    returned = static_cast<DWORD>((std::min)(filtered.bytes.size(),
                                                            static_cast<std::size_t>(captured_bytes)));
                    if (!CopyToBuffers(buffers, count,
                        std::span<const std::uint8_t>(filtered.bytes.data(), returned))) returned = captured_bytes;
                }
                (void)TryWriteDword(bytes_received, returned);
                auto modified = filtered.bytes.empty() ? raw :
                    std::shared_ptr<const ByteBuffer>(std::make_shared<ByteBuffer>(std::move(filtered.bytes)));
                Capture(socket, kWsaRecvFrom, std::move(raw), std::move(modified),
                        static_cast<std::uint8_t>(action), static_cast<std::size_t>(returned),
                        std::move(filtered.logs),
                        from, captured_from_length);
            } catch (...) {}
        }
        WSASetLastError(saved_error);
        return result;
    }

    int OnWsaRecvEx(WsaRecvExFn original, SOCKET socket, char* buffer, int length,
                    int* flags_value) noexcept {
        int result = original(socket, buffer, length, flags_value);
        const int saved_error = WSAGetLastError();
        if (result > 0) {
            try {
                auto raw = CopyBytes(buffer, static_cast<std::size_t>(result));
                auto filtered = raw
                    ? ApplyFilter(Context(socket, kWsaRecvEx, nullptr, 0), *raw)
                    : FilterResult{};
                const auto action = filtered.bytes.empty() ? FilterAction::None : filtered.action;
                if (action == FilterAction::Intercept) result = 0;
                else if (!filtered.bytes.empty()) {
                    const auto returned = (std::min)(filtered.bytes.size(), static_cast<std::size_t>(result));
                    if (TryCopyMemory(buffer, filtered.bytes.data(), returned)) result = static_cast<int>(returned);
                }
                auto modified = filtered.bytes.empty() ? raw :
                    std::shared_ptr<const ByteBuffer>(std::make_shared<ByteBuffer>(std::move(filtered.bytes)));
                Capture(socket, kWsaRecvEx, std::move(raw), std::move(modified),
                        static_cast<std::uint8_t>(action), static_cast<std::size_t>(result),
                        std::move(filtered.logs));
            }
            catch (...) {}
        }
        WSASetLastError(saved_error);
        return result;
    }

    static int WSAAPI DetourBind(SOCKET s, const sockaddr* a, int n) noexcept {
        CallGuard call;
        auto* owner = call.owner;
        return owner && owner->hook_bind ? owner->OnBind(owner->hook_bind, s, a, n)
                                         : SOCKET_ERROR;
    }
    static int WSAAPI DetourConnect(SOCKET s, const sockaddr* a, int n) noexcept {
        CallGuard call;
        auto* owner = call.owner;
        return owner && owner->hook_connect ? owner->OnConnect(owner->hook_connect, s, a, n)
                                            : SOCKET_ERROR;
    }
    static int WSAAPI DetourWsaConnect(SOCKET s, const sockaddr* a, int n,
                                       LPWSABUF caller, LPWSABUF callee,
                                       LPQOS sqos, LPQOS gqos) noexcept {
        CallGuard call;
        auto* owner = call.owner;
        return owner && owner->hook_wsa_connect
            ? owner->OnWsaConnect(owner->hook_wsa_connect, s, a, n, caller, callee, sqos, gqos)
            : SOCKET_ERROR;
    }
    static SOCKET WSAAPI DetourAccept(SOCKET s, sockaddr* a, int* n) noexcept {
        CallGuard call;
        auto* owner = call.owner;
        return owner && owner->hook_accept ? owner->OnAccept(owner->hook_accept, s, a, n)
                                           : INVALID_SOCKET;
    }
    static SOCKET WSAAPI DetourWsaAccept(SOCKET s, sockaddr* a, LPINT n,
                                         LPCONDITIONPROC condition,
                                         DWORD_PTR callback_data) noexcept {
        CallGuard call;
        auto* owner = call.owner;
        return owner && owner->hook_wsa_accept
            ? owner->OnWsaAccept(owner->hook_wsa_accept, s, a, n, condition, callback_data)
            : INVALID_SOCKET;
    }
    static int WSAAPI DetourCloseSocket(SOCKET s) noexcept {
        CallGuard call;
        auto* owner = call.owner;
        return owner && owner->hook_close_socket
            ? owner->OnCloseSocket(owner->hook_close_socket, s) : SOCKET_ERROR;
    }
    static int WSAAPI DetourGetSockName(SOCKET s, sockaddr* a, int* n) noexcept {
        CallGuard call;
        auto* owner = call.owner;
        return owner && owner->hook_get_sock_name
            ? owner->OnGetName(owner->hook_get_sock_name, s, a, n, false) : SOCKET_ERROR;
    }
    static int WSAAPI DetourGetPeerName(SOCKET s, sockaddr* a, int* n) noexcept {
        CallGuard call;
        auto* owner = call.owner;
        return owner && owner->hook_get_peer_name
            ? owner->OnGetName(owner->hook_get_peer_name, s, a, n, true) : SOCKET_ERROR;
    }

    static int WSAAPI DetourWs1Send(SOCKET s, const char* b, int n, int f) noexcept {
        CallGuard call;
        auto* owner = call.owner;
        if (g_replay_call)
            return owner && owner->ws1_send ? owner->ws1_send(s, b, n, f) : SOCKET_ERROR;
        return owner && owner->ws1_send ? owner->OnSend(owner->ws1_send, s, b, n, f, kWs1Send) : SOCKET_ERROR;
    }
    static int WSAAPI DetourWs1SendTo(SOCKET s, const char* b, int n, int f,
                                      const sockaddr* to, int to_length) noexcept {
        CallGuard call;
        auto* owner = call.owner;
        if (g_replay_call)
            return owner && owner->ws1_send_to ? owner->ws1_send_to(s, b, n, f, to, to_length) : SOCKET_ERROR;
        return owner && owner->ws1_send_to ? owner->OnSendTo(owner->ws1_send_to, s, b, n, f, to, to_length, kWs1SendTo) : SOCKET_ERROR;
    }
    static int WSAAPI DetourWs1Recv(SOCKET s, char* b, int n, int f) noexcept {
        CallGuard call;
        auto* owner = call.owner;
        return owner && owner->ws1_recv ? owner->OnRecv(owner->ws1_recv, s, b, n, f, kWs1Recv) : SOCKET_ERROR;
    }
    static int WSAAPI DetourWs1RecvFrom(SOCKET s, char* b, int n, int f,
                                        sockaddr* from, int* from_length) noexcept {
        CallGuard call;
        auto* owner = call.owner;
        return owner && owner->ws1_recv_from ? owner->OnRecvFrom(owner->ws1_recv_from, s, b, n, f, from, from_length, kWs1RecvFrom) : SOCKET_ERROR;
    }
    static int WSAAPI DetourWs2Send(SOCKET s, const char* b, int n, int f) noexcept {
        CallGuard call;
        auto* owner = call.owner;
        if (g_replay_call)
            return owner && owner->ws2_send ? owner->ws2_send(s, b, n, f) : SOCKET_ERROR;
        return owner && owner->ws2_send ? owner->OnSend(owner->ws2_send, s, b, n, f, kWs2Send) : SOCKET_ERROR;
    }
    static int WSAAPI DetourWs2SendTo(SOCKET s, const char* b, int n, int f,
                                      const sockaddr* to, int to_length) noexcept {
        CallGuard call;
        auto* owner = call.owner;
        if (g_replay_call)
            return owner && owner->ws2_send_to ? owner->ws2_send_to(s, b, n, f, to, to_length) : SOCKET_ERROR;
        return owner && owner->ws2_send_to ? owner->OnSendTo(owner->ws2_send_to, s, b, n, f, to, to_length, kWs2SendTo) : SOCKET_ERROR;
    }
    static int WSAAPI DetourWs2Recv(SOCKET s, char* b, int n, int f) noexcept {
        CallGuard call;
        auto* owner = call.owner;
        return owner && owner->ws2_recv ? owner->OnRecv(owner->ws2_recv, s, b, n, f, kWs2Recv) : SOCKET_ERROR;
    }
    static int WSAAPI DetourWs2RecvFrom(SOCKET s, char* b, int n, int f,
                                        sockaddr* from, int* from_length) noexcept {
        CallGuard call;
        auto* owner = call.owner;
        return owner && owner->ws2_recv_from ? owner->OnRecvFrom(owner->ws2_recv_from, s, b, n, f, from, from_length, kWs2RecvFrom) : SOCKET_ERROR;
    }
    static int WSAAPI DetourWsaSend(SOCKET s, LPWSABUF b, DWORD n, LPDWORD sent,
                                    DWORD f, LPWSAOVERLAPPED o,
                                    LPWSAOVERLAPPED_COMPLETION_ROUTINE c) noexcept {
        CallGuard call;
        auto* owner = call.owner;
        return owner && owner->wsa_send ? owner->OnWsaSend(owner->wsa_send, s, b, n, sent, f, o, c) : SOCKET_ERROR;
    }
    static int WSAAPI DetourWsaSendTo(SOCKET s, LPWSABUF b, DWORD n, LPDWORD sent,
                                      DWORD f, const sockaddr* to, int to_length,
                                      LPWSAOVERLAPPED o,
                                      LPWSAOVERLAPPED_COMPLETION_ROUTINE c) noexcept {
        CallGuard call;
        auto* owner = call.owner;
        return owner && owner->wsa_send_to ? owner->OnWsaSendTo(owner->wsa_send_to, s, b, n, sent, f, to, to_length, o, c) : SOCKET_ERROR;
    }
    static int WSAAPI DetourWsaRecv(SOCKET s, LPWSABUF b, DWORD n, LPDWORD received,
                                    LPDWORD f, LPWSAOVERLAPPED o,
                                    LPWSAOVERLAPPED_COMPLETION_ROUTINE c) noexcept {
        CallGuard call;
        auto* owner = call.owner;
        return owner && owner->wsa_recv ? owner->OnWsaRecv(owner->wsa_recv, s, b, n, received, f, o, c) : SOCKET_ERROR;
    }
    static int WSAAPI DetourWsaRecvFrom(SOCKET s, LPWSABUF b, DWORD n, LPDWORD received,
                                        LPDWORD f, sockaddr* from, LPINT from_length,
                                        LPWSAOVERLAPPED o,
                                        LPWSAOVERLAPPED_COMPLETION_ROUTINE c) noexcept {
        CallGuard call;
        auto* owner = call.owner;
        return owner && owner->wsa_recv_from ? owner->OnWsaRecvFrom(owner->wsa_recv_from, s, b, n, received, f, from, from_length, o, c) : SOCKET_ERROR;
    }
    static int WSAAPI DetourWsaRecvEx(SOCKET s, char* b, int n, int* f) noexcept {
        CallGuard call;
        auto* owner = call.owner;
        return owner && owner->wsa_recv_ex ? owner->OnWsaRecvEx(owner->wsa_recv_ex, s, b, n, f) : SOCKET_ERROR;
    }
};

std::atomic<WinsockHookController::Impl*> WinsockHookController::Impl::active{};

WinsockHookController::WinsockHookController(bool suspended_launch, FrameSender packet_sender,
                                             FrameSender event_sender)
    : impl_(std::make_unique<Impl>(suspended_launch, std::move(packet_sender),
                                  std::move(event_sender))) {}

WinsockHookController::~WinsockHookController() {
    StopHook();
    if (!impl_ || (!impl_->manager.Initialized() &&
                   Impl::active.load(std::memory_order_acquire) != impl_.get() &&
                   !impl_->writer.joinable() && !impl_->trigger_worker.joinable())) return;

    // A target thread may remain blocked inside an already-entered recv. Never
    // hang Detach and never free its owner/trampoline. The injected DLL remains
    // loaded in the target, so a detached reaper can safely finish retirement.
    auto* retired = impl_.release();
    try {
        std::thread([retired] {
            retired->RetireUntilSafe();
            delete retired;
        }).detach();
    } catch (...) {
        // Deliberately leak on an out-of-resource retirement failure. Keeping
        // disabled hooks, trampolines and active owner memory is safer than a
        // target crash or a jump into freed code.
    }
}

WinsockSupport WinsockHookController::DetectWinsock(bool may_load) {
    std::lock_guard lock(impl_->lifecycle_mutex);
    return impl_->Detect(may_load);
}

void WinsockHookController::ConfigureHookFlags(const std::array<bool, 12>& flags) {
    std::lock_guard lock(impl_->lifecycle_mutex);
    // Like the original implementation, flag edits affect the next StartHook;
    // an already installed set is left stable until StopHook.
    impl_->flags = flags;
}

void WinsockHookController::ConfigureSpeedMode(bool enabled) noexcept {
    impl_->speed_mode.store(enabled, std::memory_order_release);
}

void WinsockHookController::ConfigureCaptureFilter(const CaptureFilterSnapshot& filter) {
    impl_->capture_filter.store(
        std::make_shared<const CaptureFilterSnapshot>(filter), std::memory_order_release);
}

void WinsockHookController::ConfigureFilters(const std::vector<FilterSnapshot>& filters,
                                             std::int32_t execute_mode,
                                             bool speed_mode) {
    impl_->filter_engine.Publish(filters, execute_mode, speed_mode);
}

void WinsockHookController::ConfigureFilterTriggers(SendTrigger send, StoreTrigger store) {
    auto callbacks = std::make_shared<Impl::TriggerCallbacks>();
    callbacks->send = std::move(send);
    callbacks->store = std::move(store);
    impl_->trigger_callbacks.store(
        std::shared_ptr<const Impl::TriggerCallbacks>(std::move(callbacks)),
        std::memory_order_release);
}

void WinsockHookController::StartHook() {
    std::lock_guard lock(impl_->lifecycle_mutex);
    if (impl_->accepting.load()) return;
    if (Impl::active.load()) throw ProtocolError("Another Winsock hook controller is active");
    // Refresh modules at every start: a running target may load Winsock after
    // Hello, while a suspended launch needs the three original modules loaded.
    impl_->Detect(true);
    impl_->endpoint_ports.Clear();

    impl_->manager.Initialize();
    try {
        if (impl_->support.ws1) {
            if (impl_->flags[0]) impl_->Add("wsock32.dll", "send", reinterpret_cast<void*>(&Impl::DetourWs1Send), impl_->ws1_send);
            if (impl_->flags[1]) impl_->Add("wsock32.dll", "sendto", reinterpret_cast<void*>(&Impl::DetourWs1SendTo), impl_->ws1_send_to);
            if (impl_->flags[2]) impl_->Add("wsock32.dll", "recv", reinterpret_cast<void*>(&Impl::DetourWs1Recv), impl_->ws1_recv);
            if (impl_->flags[3]) impl_->Add("wsock32.dll", "recvfrom", reinterpret_cast<void*>(&Impl::DetourWs1RecvFrom), impl_->ws1_recv_from);
        }
        if (impl_->support.ws2) {
            if (impl_->flags[4]) impl_->Add("ws2_32.dll", "send", reinterpret_cast<void*>(&Impl::DetourWs2Send), impl_->ws2_send);
            if (impl_->flags[5]) impl_->Add("ws2_32.dll", "sendto", reinterpret_cast<void*>(&Impl::DetourWs2SendTo), impl_->ws2_send_to);
            if (impl_->flags[6]) impl_->Add("ws2_32.dll", "recv", reinterpret_cast<void*>(&Impl::DetourWs2Recv), impl_->ws2_recv);
            if (impl_->flags[7]) impl_->Add("ws2_32.dll", "recvfrom", reinterpret_cast<void*>(&Impl::DetourWs2RecvFrom), impl_->ws2_recv_from);
            if (impl_->flags[8]) impl_->Add("ws2_32.dll", "WSASend", reinterpret_cast<void*>(&Impl::DetourWsaSend), impl_->wsa_send);
            if (impl_->flags[9]) impl_->Add("ws2_32.dll", "WSASendTo", reinterpret_cast<void*>(&Impl::DetourWsaSendTo), impl_->wsa_send_to);
            if (impl_->flags[10]) impl_->Add("ws2_32.dll", "WSARecv", reinterpret_cast<void*>(&Impl::DetourWsaRecv), impl_->wsa_recv);
            if (impl_->flags[11]) impl_->Add("ws2_32.dll", "WSARecvFrom", reinterpret_cast<void*>(&Impl::DetourWsaRecvFrom), impl_->wsa_recv_from);
        }
        if (impl_->support.msws && impl_->flags[10] && sizeof(void*) == 4)
            impl_->Add("mswsock.dll", "WSARecvEx", reinterpret_cast<void*>(&Impl::DetourWsaRecvEx), impl_->wsa_recv_ex);

        impl_->capture_hook_count.store(impl_->targets.size(), std::memory_order_release);
        // These hooks only maintain fixed-size endpoint metadata. They never
        // encode strings, write IPC or synchronously query socket names. This
        // makes port filters correct for the first connected packet and clears
        // stale metadata before numeric SOCKET handles are reused.
        if (impl_->support.ws2) {
            impl_->Add("ws2_32.dll", "bind", reinterpret_cast<void*>(&Impl::DetourBind), impl_->hook_bind);
            impl_->Add("ws2_32.dll", "connect", reinterpret_cast<void*>(&Impl::DetourConnect), impl_->hook_connect);
            impl_->Add("ws2_32.dll", "WSAConnect", reinterpret_cast<void*>(&Impl::DetourWsaConnect), impl_->hook_wsa_connect);
            impl_->Add("ws2_32.dll", "accept", reinterpret_cast<void*>(&Impl::DetourAccept), impl_->hook_accept);
            impl_->Add("ws2_32.dll", "WSAAccept", reinterpret_cast<void*>(&Impl::DetourWsaAccept), impl_->hook_wsa_accept);
            impl_->Add("ws2_32.dll", "closesocket", reinterpret_cast<void*>(&Impl::DetourCloseSocket), impl_->hook_close_socket);
            impl_->Add("ws2_32.dll", "getsockname", reinterpret_cast<void*>(&Impl::DetourGetSockName), impl_->hook_get_sock_name);
            impl_->Add("ws2_32.dll", "getpeername", reinterpret_cast<void*>(&Impl::DetourGetPeerName), impl_->hook_get_peer_name);
        }

        impl_->trigger_running.store(true, std::memory_order_release);
        impl_->trigger_worker = std::thread(&Impl::TriggerLoop, impl_.get());
        impl_->writer_running.store(true);
        impl_->writer = std::thread(&Impl::WriterLoop, impl_.get());
        Impl::active.store(impl_.get(), std::memory_order_release);
        impl_->accepting.store(true, std::memory_order_release);
        for (auto* target : impl_->targets) impl_->manager.Enable(target);
    } catch (...) {
        impl_->accepting.store(false);
        impl_->StopWriter();
        if (impl_->QuiesceAndShutdown(std::chrono::milliseconds(500)))
            impl_->StopTriggerWorker();
        throw;
    }
}

void WinsockHookController::StopHook() {
    if (!impl_) return;
    std::lock_guard lock(impl_->lifecycle_mutex);
    impl_->accepting.store(false, std::memory_order_release);
    impl_->StopWriter();
    if (impl_->QuiesceAndShutdown(std::chrono::milliseconds(500)))
        impl_->StopTriggerWorker();
}

std::optional<std::array<std::int64_t, 11>>
WinsockHookController::LivePacketCounters() const noexcept {
    std::array<std::int64_t, 11> result{};
    for (std::size_t i = 0; i < result.size(); ++i)
        result[i] = impl_->counters[i].load(std::memory_order_relaxed);
    return result;
}

void WinsockHookController::ResetLivePacketCounters() noexcept {
    for (auto& counter : impl_->counters) counter.store(0, std::memory_order_relaxed);
}

std::optional<FilterRuntimeStats> WinsockHookController::LiveFilterStats() const noexcept {
    const auto stats = impl_->filter_engine.Stats();
    return FilterRuntimeStats{stats.filters, stats.globals};
}

void WinsockHookController::ResetLiveFilterStats() noexcept {
    impl_->filter_engine.ResetStats();
}

bool WinsockHookController::SendPacket(const ReplayPacketSnapshot& packet) {
    std::lock_guard lock(impl_->lifecycle_mutex);
    // A target can load Winsock after Hello. Refresh exports here as well as at
    // StartHook so active replay also works before capture has been enabled.
    impl_->Detect(true);
    return impl_->Replay(packet);
}

SocketInfo WinsockHookController::GetSocketInfo(std::int32_t socket) {
    std::lock_guard lock(impl_->lifecycle_mutex);
    impl_->Detect(true);
    if (socket <= 0) return {Text{u""}, Text{u""}};
    return impl_->QuerySocketInfo(
        static_cast<SOCKET>(static_cast<std::uint32_t>(socket)));
}

std::size_t WinsockHookController::RegisteredHookCount() const noexcept {
    if (impl_->manager.HookCount() == 0) return 0;
    return impl_->capture_hook_count.load(std::memory_order_acquire);
}

std::uint32_t WinsockHookController::InFlightDetourCount() const noexcept {
    return impl_->in_flight.load(std::memory_order_acquire);
}

std::uint64_t WinsockHookController::DroppedPacketCount() const noexcept {
    return impl_->ring.Dropped() + impl_->delivery_dropped.load(std::memory_order_relaxed);
}

std::uint64_t WinsockHookController::DroppedTriggerCount() const noexcept {
    return impl_->trigger_dropped.load(std::memory_order_relaxed);
}

} // namespace wpe
