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
    if (!address || length < static_cast<int>(sizeof(sockaddr_in)) ||
        address->sa_family != AF_INET) return {};
    const auto* ipv4 = reinterpret_cast<const sockaddr_in*>(address);
    const auto* bytes = reinterpret_cast<const unsigned char*>(&ipv4->sin_addr.s_addr);
    const auto port = static_cast<unsigned short>((ipv4->sin_port >> 8U) |
                                                   (ipv4->sin_port << 8U));
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

    Impl(bool suspended, FrameSender packets, FrameSender events)
        : suspended_launch(suspended), packet_sender(std::move(packets)),
          event_sender(std::move(events)),
          filter_engine([this](const FilterLogRecord& record) { EmitFilterLog(record); }) {}

    bool suspended_launch{};
    FrameSender packet_sender;
    FrameSender event_sender;
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
    std::atomic<bool> accepting{};
    std::atomic<bool> writer_running{};
    std::atomic<std::uint32_t> in_flight{};
    std::mutex in_flight_mutex;
    std::condition_variable in_flight_changed;
    std::thread writer;
    std::uint64_t reported_dropped{};
    std::atomic<std::uint64_t> delivery_dropped{};

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
        return support;
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

    void EmitFilterLog(const FilterLogRecord& record) noexcept {
        if (!event_sender) return;
        try {
            IpcWriter writer_event;
            writer_event.U8(static_cast<std::uint8_t>(IpcEvent::FilterLog));
            writer_event.Str(record.name);
            writer_event.I32(static_cast<std::int32_t>(record.action));
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
        const auto append = [&](const sockaddr* candidate, int length) {
            if (!candidate || length < static_cast<int>(sizeof(sockaddr_in)) ||
                candidate->sa_family != AF_INET || context.port_count >= context.ports.size()) return;
            const auto port = ntohs(reinterpret_cast<const sockaddr_in*>(candidate)->sin_port);
            if (std::find(context.ports.begin(), context.ports.begin() +
                          static_cast<std::ptrdiff_t>(context.port_count), port) ==
                context.ports.begin() + static_cast<std::ptrdiff_t>(context.port_count))
                context.ports[context.port_count++] = port;
        };
        append(address, address_length);
        sockaddr_storage endpoint{};
        int endpoint_length = sizeof(endpoint);
        if (get_sock_name && get_sock_name(socket, reinterpret_cast<sockaddr*>(&endpoint),
                                            &endpoint_length) == 0)
            append(reinterpret_cast<const sockaddr*>(&endpoint), endpoint_length);
        endpoint = {};
        endpoint_length = sizeof(endpoint);
        if (get_peer_name && get_peer_name(socket, reinterpret_cast<sockaddr*>(&endpoint),
                                            &endpoint_length) == 0)
            append(reinterpret_cast<const sockaddr*>(&endpoint), endpoint_length);
        return context;
    }

    void Capture(SOCKET socket, std::uint8_t type,
                 std::shared_ptr<const ByteBuffer> raw,
                 std::shared_ptr<const ByteBuffer> modified,
                 std::uint8_t filter_action,
                 std::size_t logical_length,
                 const sockaddr* address = nullptr, int address_length = 0,
                 std::int64_t time_ticks = 0) noexcept {
        if (!accepting.load(std::memory_order_acquire)) return;
        if (filter_action == static_cast<std::uint8_t>(FilterAction::NoModifyNoDisplay)) return;
        if (filter_action != static_cast<std::uint8_t>(FilterAction::Intercept) &&
            logical_length == 0) return;
        // Match the original OnPacket order: intercepted receives are still
        // counted/displayed even though the caller observes a zero return, and
        // byte counters describe the post-filter buffer rather than a partial
        // send return. If capture allocation failed, the supplied logical
        // length remains the best available accounting value.
        Count(type, modified ? modified->size() : logical_length);
        if (speed_mode.load(std::memory_order_relaxed)) return;
        if (!raw || raw->empty() || !modified || modified->empty()) {
            delivery_dropped.fetch_add(1, std::memory_order_relaxed);
            ring.Wake();
            return;
        }
        try {
            auto packet = std::make_shared<PendingPacket>();
            packet->id = sequence.fetch_add(1, std::memory_order_relaxed) + 1;
            packet->time_ticks = time_ticks == 0 ? DateTimeTicksNow() : time_ticks;
            packet->socket = static_cast<std::int64_t>(socket);
            packet->packet_type = type;
            packet->filter_action = filter_action;
            packet->raw = std::move(raw);
            packet->modified = std::move(modified);
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

    std::pair<std::string, std::string> Endpoints(const PendingPacket& packet) const {
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
                    const auto endpoints = Endpoints(*pending);
                    if (endpoints.first.empty() || !packet_sender) {
                        delivery_dropped.fetch_add(1, std::memory_order_relaxed);
                        continue;
                    }
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
                        delivery_dropped.fetch_add(batch.size() - next,
                                                   std::memory_order_relaxed);
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
                    delivery_dropped.fetch_add(batch.size() - next,
                                               std::memory_order_relaxed);
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
        return true;
    }

    void RetireUntilSafe() noexcept {
        StopWriter();
        while (!QuiesceAndShutdown(std::chrono::milliseconds(500)))
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    int OnSend(SendFn original, SOCKET socket, const char* buffer, int length,
               int flags_value, std::uint8_t type) noexcept {
        const auto time_ticks = DateTimeTicksNow();
        std::shared_ptr<const ByteBuffer> raw;
        FilterResult filtered;
        try {
            if (length > 0) {
                raw = CopyBytes(buffer, static_cast<std::size_t>(length));
                if (raw) filtered = filter_engine.Apply(Context(socket, type, nullptr, 0), *raw);
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
        if (result > 0) {
            auto modified = filtered.bytes.empty() ? raw :
                std::shared_ptr<const ByteBuffer>(std::make_shared<ByteBuffer>(std::move(filtered.bytes)));
            const auto filtered_length = modified ? modified->size() : static_cast<std::size_t>(length);
            Capture(socket, type, std::move(raw), std::move(modified),
                    static_cast<std::uint8_t>(action), filtered_length,
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
                if (raw) filtered = filter_engine.Apply(Context(socket, type, to, to_length), *raw);
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
        if (result > 0) {
            auto modified = filtered.bytes.empty() ? raw :
                std::shared_ptr<const ByteBuffer>(std::make_shared<ByteBuffer>(std::move(filtered.bytes)));
            const auto filtered_length = modified ? modified->size() : static_cast<std::size_t>(length);
            Capture(socket, type, std::move(raw), std::move(modified),
                    static_cast<std::uint8_t>(action), filtered_length,
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
                    auto filtered = filter_engine.Apply(Context(socket, type, nullptr, 0), *raw);
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
                            static_cast<std::uint8_t>(action), static_cast<std::size_t>(result));
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
                    auto filtered = filter_engine.Apply(
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
                    filtered = filter_engine.Apply(Context(socket, kWsaSend, nullptr, 0), *raw);
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
        if (result == 0 && bytes_sent && TryReadDword(bytes_sent, captured_bytes) &&
            captured_bytes > 0) {
            auto modified = filtered.bytes.empty() ? raw :
                std::shared_ptr<const ByteBuffer>(std::make_shared<ByteBuffer>(std::move(filtered.bytes)));
            const auto filtered_length = modified ? modified->size() : total_length.value_or(captured_bytes);
            Capture(socket, kWsaSend, std::move(raw), std::move(modified),
                    static_cast<std::uint8_t>(action),
                    filtered_length,
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
                    filtered = filter_engine.Apply(Context(socket, kWsaSendTo, to, to_length), *raw);
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
        if (result == 0 && bytes_sent && TryReadDword(bytes_sent, captured_bytes) &&
            captured_bytes > 0) {
            auto modified = filtered.bytes.empty() ? raw :
                std::shared_ptr<const ByteBuffer>(std::make_shared<ByteBuffer>(std::move(filtered.bytes)));
            const auto filtered_length = modified ? modified->size() : total_length.value_or(captured_bytes);
            Capture(socket, kWsaSendTo, std::move(raw), std::move(modified),
                    static_cast<std::uint8_t>(action),
                    filtered_length,
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
                    ? filter_engine.Apply(Context(socket, kWsaRecv, nullptr, 0), *raw)
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
                        static_cast<std::uint8_t>(action), static_cast<std::size_t>(returned));
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
                    ? filter_engine.Apply(Context(socket, kWsaRecvFrom, from, captured_from_length), *raw)
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
                    ? filter_engine.Apply(Context(socket, kWsaRecvEx, nullptr, 0), *raw)
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
                        static_cast<std::uint8_t>(action), static_cast<std::size_t>(result));
            }
            catch (...) {}
        }
        WSASetLastError(saved_error);
        return result;
    }

    static int WSAAPI DetourWs1Send(SOCKET s, const char* b, int n, int f) noexcept {
        CallGuard call;
        auto* owner = call.owner;
        return owner && owner->ws1_send ? owner->OnSend(owner->ws1_send, s, b, n, f, kWs1Send) : SOCKET_ERROR;
    }
    static int WSAAPI DetourWs1SendTo(SOCKET s, const char* b, int n, int f,
                                      const sockaddr* to, int to_length) noexcept {
        CallGuard call;
        auto* owner = call.owner;
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
        return owner && owner->ws2_send ? owner->OnSend(owner->ws2_send, s, b, n, f, kWs2Send) : SOCKET_ERROR;
    }
    static int WSAAPI DetourWs2SendTo(SOCKET s, const char* b, int n, int f,
                                      const sockaddr* to, int to_length) noexcept {
        CallGuard call;
        auto* owner = call.owner;
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
                   !impl_->writer.joinable())) return;

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

void WinsockHookController::ConfigureFilters(const std::vector<FilterSnapshot>& filters,
                                             std::int32_t execute_mode,
                                             bool speed_mode) {
    impl_->filter_engine.Publish(filters, execute_mode, speed_mode);
}

void WinsockHookController::StartHook() {
    std::lock_guard lock(impl_->lifecycle_mutex);
    if (impl_->accepting.load()) return;
    if (Impl::active.load()) throw ProtocolError("Another Winsock hook controller is active");
    // Refresh modules at every start: a running target may load Winsock after
    // Hello, while a suspended launch needs the three original modules loaded.
    impl_->Detect(true);

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

        impl_->writer_running.store(true);
        impl_->writer = std::thread(&Impl::WriterLoop, impl_.get());
        Impl::active.store(impl_.get(), std::memory_order_release);
        impl_->accepting.store(true, std::memory_order_release);
        for (auto* target : impl_->targets) impl_->manager.Enable(target);
    } catch (...) {
        impl_->accepting.store(false);
        impl_->StopWriter();
        (void)impl_->QuiesceAndShutdown(std::chrono::milliseconds(500));
        throw;
    }
}

void WinsockHookController::StopHook() {
    if (!impl_) return;
    std::lock_guard lock(impl_->lifecycle_mutex);
    impl_->accepting.store(false, std::memory_order_release);
    impl_->StopWriter();
    (void)impl_->QuiesceAndShutdown(std::chrono::milliseconds(500));
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

std::size_t WinsockHookController::RegisteredHookCount() const noexcept {
    return impl_->manager.HookCount();
}

std::uint32_t WinsockHookController::InFlightDetourCount() const noexcept {
    return impl_->in_flight.load(std::memory_order_acquire);
}

std::uint64_t WinsockHookController::DroppedPacketCount() const noexcept {
    return impl_->ring.Dropped() + impl_->delivery_dropped.load(std::memory_order_relaxed);
}

} // namespace wpe
