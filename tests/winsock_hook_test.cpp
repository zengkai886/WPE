#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <WinSock2.h>
#include <Windows.h>
#include "target/winsock_hook.h"
#include "common/packet_frame.h"
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;

namespace {
std::size_t checks{};
void Check(bool value, const char* message) {
    ++checks;
    if (!value) throw std::runtime_error(message);
}

struct Winsock final {
    Winsock() {
        WSADATA data{};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) throw std::runtime_error("WSAStartup failed");
    }
    ~Winsock() { WSACleanup(); }
};

struct Socket final {
    SOCKET value{INVALID_SOCKET};
    Socket() = default;
    explicit Socket(SOCKET socket) : value(socket) {}
    ~Socket() { if (value != INVALID_SOCKET) closesocket(value); }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&& other) noexcept : value(other.value) { other.value = INVALID_SOCKET; }
};

std::pair<Socket, Socket> TcpPair() {
    Socket listener(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    if (listener.value == INVALID_SOCKET) throw std::runtime_error("listener socket failed");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(listener.value, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0 ||
        listen(listener.value, 1) != 0) throw std::runtime_error("listener setup failed");
    int length = sizeof(address);
    if (getsockname(listener.value, reinterpret_cast<sockaddr*>(&address), &length) != 0)
        throw std::runtime_error("getsockname failed");
    Socket client(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    if (client.value == INVALID_SOCKET ||
        connect(client.value, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0)
        throw std::runtime_error("connect failed");
    Socket server(accept(listener.value, nullptr, nullptr));
    if (server.value == INVALID_SOCKET) throw std::runtime_error("accept failed");
    return {std::move(client), std::move(server)};
}

struct UdpPair final {
    Socket sender{socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)};
    Socket receiver{socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)};
    sockaddr_in destination{};
    UdpPair() {
        if (sender.value == INVALID_SOCKET || receiver.value == INVALID_SOCKET)
            throw std::runtime_error("UDP socket failed");
        destination.sin_family = AF_INET;
        destination.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(receiver.value, reinterpret_cast<const sockaddr*>(&destination),
                 sizeof(destination)) != 0) throw std::runtime_error("UDP bind failed");
        int length = sizeof(destination);
        if (getsockname(receiver.value, reinterpret_cast<sockaddr*>(&destination), &length) != 0)
            throw std::runtime_error("UDP getsockname failed");
        sockaddr_in source{};
        source.sin_family = AF_INET;
        source.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(sender.value, reinterpret_cast<const sockaddr*>(&source), sizeof(source)) != 0)
            throw std::runtime_error("UDP sender bind failed");
    }
};

class Collector final {
public:
    void Push(wpe::ByteBuffer frame) {
        {
            std::lock_guard lock(mutex_);
            frames_.push_back(wpe::PacketFrame::Decode(frame));
        }
        ready_.notify_all();
    }
    void Clear() {
        std::lock_guard lock(mutex_);
        frames_.clear();
    }
    std::vector<wpe::Packet> Wait(std::size_t count) {
        std::unique_lock lock(mutex_);
        if (!ready_.wait_for(lock, 3s, [&] { return frames_.size() >= count; }))
            throw std::runtime_error("packet writer timeout");
        return frames_;
    }
    std::vector<wpe::Packet> WaitFor(std::uint8_t type, std::string_view bytes) {
        std::unique_lock lock(mutex_);
        const auto found = [&] {
            for (const auto& packet : frames_) {
                if (packet.packet_type == type && packet.raw &&
                    packet.raw->size() == bytes.size() &&
                    std::memcmp(packet.raw->data(), bytes.data(), bytes.size()) == 0) return true;
            }
            return false;
        };
        if (!ready_.wait_for(lock, 3s, found))
            throw std::runtime_error("specific packet writer timeout");
        return frames_;
    }
    std::size_t Count() const {
        std::lock_guard lock(mutex_);
        return frames_.size();
    }
private:
    mutable std::mutex mutex_;
    std::condition_variable ready_;
    std::vector<wpe::Packet> frames_;
};

bool Has(const std::vector<wpe::Packet>& packets, std::uint8_t type, std::string_view bytes) {
    for (const auto& packet : packets) {
        if (packet.packet_type != type || !packet.raw) continue;
        if (packet.raw->size() == bytes.size() &&
            std::memcmp(packet.raw->data(), bytes.data(), bytes.size()) == 0 &&
            packet.modified == packet.raw && packet.from && packet.to &&
            !packet.from->empty() && !packet.to->empty()) return true;
    }
    return false;
}

const wpe::Packet* Find(const std::vector<wpe::Packet>& packets, std::uint8_t type,
                        std::string_view bytes) {
    for (const auto& packet : packets) {
        if (packet.packet_type == type && packet.raw && packet.raw->size() == bytes.size() &&
            std::memcmp(packet.raw->data(), bytes.data(), bytes.size()) == 0) return &packet;
    }
    return nullptr;
}

std::int64_t LocalDateTimeTicksNow() {
    FILETIME utc{};
    FILETIME local{};
    GetSystemTimePreciseAsFileTime(&utc);
    if (!FileTimeToLocalFileTime(&utc, &local)) throw std::runtime_error("local FILETIME failed");
    ULARGE_INTEGER value{};
    value.LowPart = local.dwLowDateTime;
    value.HighPart = local.dwHighDateTime;
    return 504911232000000000LL + static_cast<std::int64_t>(value.QuadPart);
}

void ReceiveExact(SOCKET socket, std::string_view expected) {
    std::array<char, 64> buffer{};
    const int result = recv(socket, buffer.data(), static_cast<int>(buffer.size()), 0);
    Check(result == static_cast<int>(expected.size()), "recv length");
    Check(std::memcmp(buffer.data(), expected.data(), expected.size()) == 0, "recv bytes");
}

wpe::Text Text(std::string_view value) {
    std::u16string result;
    for (const unsigned char character : value) result.push_back(static_cast<char16_t>(character));
    return result;
}
} // namespace

int main() {
    try {
        Winsock winsock;
        auto tcp = TcpPair();
        UdpPair udp;
        Collector collector;
        std::atomic<std::int64_t> filter_log_events{};
        wpe::WinsockHookController hooks(true,
            [&](wpe::ByteBuffer frame) { collector.Push(std::move(frame)); },
            [&](wpe::ByteBuffer frame) {
                try {
                    wpe::IpcReader event(frame);
                    if (event.U8() == static_cast<std::uint8_t>(wpe::IpcEvent::FilterLog))
                        filter_log_events.fetch_add(1, std::memory_order_relaxed);
                } catch (...) {}
            });
        const auto support = hooks.DetectWinsock(true);
        Check(support.ws1 && support.ws2 && support.msws, "three Winsock modules detected");

        std::array<bool, 12> flags{};
        flags[4] = true; flags[6] = true;
        hooks.ConfigureHookFlags(flags);
        hooks.StartHook();
        Check(hooks.RegisteredHookCount() == 2, "ws2 send/recv hooks registered");
        const auto before_send_ticks = LocalDateTimeTicksNow();
        Check(send(tcp.first.value, "alpha", 5, 0) == 5, "hooked send result");
        ReceiveExact(tcp.second.value, "alpha");
        const auto after_send_ticks = LocalDateTimeTicksNow();
        auto packets = collector.Wait(2);
        Check(Has(packets, 1, "alpha"), "ws2 send captured");
        Check(Has(packets, 5, "alpha"), "ws2 recv captured");
        const auto* sent_packet = Find(packets, 1, "alpha");
        Check(sent_packet && sent_packet->time_ticks >= before_send_ticks &&
              sent_packet->time_ticks <= after_send_ticks,
              "packet timestamp uses original DateTime.Now local ticks");

        wpe::FilterSnapshot filter;
        filter.enabled = true;
        filter.id = wpe::Guid::Parse("00112233-4455-6677-8899-aabbccddeeff");
        filter.name = Text("live-send-filter");
        filter.functions.fill(false);
        filter.functions[0] = true;
        filter.mode = 0;
        filter.action = 0;
        filter.search = Text("0|61");
        filter.modify = Text("0|6f");
        sockaddr_in peer{};
        int peer_length = sizeof(peer);
        Check(getpeername(tcp.first.value, reinterpret_cast<sockaddr*>(&peer),
                          &peer_length) == 0,
              "connected peer endpoint available for port-filter fixture");
        filter.appoint_port = true;
        filter.port = Text(std::to_string(ntohs(peer.sin_port)));
        hooks.ConfigureFilters({filter}, 0, false);
        collector.Clear();
        Check(send(tcp.first.value, "alpha", 5, 0) == 5, "filtered send result");
        ReceiveExact(tcp.second.value, "olpha");
        packets = collector.WaitFor(1, "alpha");
        sent_packet = Find(packets, 1, "alpha");
        Check(sent_packet && sent_packet->modified &&
              *sent_packet->modified == wpe::ByteBuffer({'o','l','p','h','a'}) &&
              sent_packet->filter_action == 0,
              "cached endpoint port gates and modifies a connected send");
        Check(filter_log_events.load(std::memory_order_relaxed) >= 1,
              "writer thread delivers deferred filter log events");
        auto filter_stats = *hooks.LiveFilterStats();
        Check(filter_stats.filters.size() == 1 && filter_stats.filters[0].second == 1 &&
              filter_stats.globals[0] == 1 && filter_stats.globals[1] == 1,
              "live send filter updates item and global counters");

        filter.name = Text("live-intercept-filter");
        filter.appoint_port = false;
        filter.action = 1;
        filter.search = Text("0|64");
        filter.modify = Text("");
        hooks.ConfigureFilters({filter}, 0, false);
        collector.Clear();
        Check(send(tcp.first.value, "drop", 4, 0) == 4,
              "intercepted send reports original length");
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(tcp.second.value, &readable);
        timeval short_wait{0, 50000};
        Check(select(0, &readable, nullptr, nullptr, &short_wait) == 0,
              "intercepted send does not reach peer");
        packets = collector.WaitFor(1, "drop");
        sent_packet = Find(packets, 1, "drop");
        Check(sent_packet && sent_packet->filter_action == 1,
              "intercepted send is captured with intercept action");

        filter.name = Text("live-no-display-filter");
        filter.action = 3;
        filter.search = Text("0|71");
        const auto log_events_before_hidden =
            filter_log_events.load(std::memory_order_relaxed);
        hooks.ConfigureFilters({filter}, 0, false);
        collector.Clear();
        Check(send(tcp.first.value, "quiet", 5, 0) == 5,
              "no-display filter preserves send result");
        for (int i = 0; i < 2000 &&
             filter_log_events.load(std::memory_order_relaxed) == log_events_before_hidden; ++i)
            Sleep(1);
        Check(filter_log_events.load(std::memory_order_relaxed) ==
              log_events_before_hidden + 1,
              "log-only ring item delivers no-display filter event");
        Check(collector.Count() == 0,
              "no-display action suppresses packet frame without suppressing its log");
        hooks.ConfigureFilters({}, 0, false);
        ReceiveExact(tcp.second.value, "quiet");

        filter.name = Text("live-recv-filter");
        filter.action = 0;
        filter.functions.fill(false);
        filter.functions[2] = true;
        filter.search = Text("0|72");
        filter.modify = Text("0|78");
        hooks.ConfigureFilters({filter}, 0, false);
        collector.Clear();
        Check(send(tcp.second.value, "reply", 5, 0) == 5, "receive-filter fixture sent");
        ReceiveExact(tcp.first.value, "xeply");
        packets = collector.WaitFor(5, "reply");
        const auto* received_packet = Find(packets, 5, "reply");
        Check(received_packet && received_packet->modified &&
              *received_packet->modified == wpe::ByteBuffer({'x','e','p','l','y'}) &&
              received_packet->filter_action == 0,
              "recv detour returns modified bytes and records original bytes");

        filter.name = Text("live-recv-intercept-filter");
        filter.action = 1;
        filter.search = Text("0|68");
        filter.modify = Text("");
        hooks.ConfigureFilters({filter}, 0, false);
        collector.Clear();
        Check(send(tcp.second.value, "hide", 4, 0) == 4,
              "receive-intercept fixture sent");
        std::array<char, 8> intercepted_receive{};
        Check(recv(tcp.first.value, intercepted_receive.data(),
                   static_cast<int>(intercepted_receive.size()), 0) == 0,
              "intercepted receive reports zero to caller");
        packets = collector.WaitFor(5, "hide");
        received_packet = Find(packets, 5, "hide");
        Check(received_packet && received_packet->filter_action == 1,
              "intercepted receive remains visible with original bytes and action");
        hooks.ConfigureFilters({}, 0, false);

        Check(send(tcp.first.value,
                   reinterpret_cast<const char*>(static_cast<std::uintptr_t>(1)),
                   1, 0) == SOCKET_ERROR,
              "invalid send buffer is passed to Winsock without crashing the detour");
        auto counters = *hooks.LivePacketCounters();
        Check(counters[0] == 10 && counters[1] == 5 && counters[3] == 5,
              "basic counters by function family");
        Check(counters[9] == 23 && counters[10] == 24, "basic byte counters");
        hooks.ConfigureSpeedMode(true);
        const auto before_speed = collector.Count();
        Check(send(tcp.first.value, "fast", 4, 0) == 4, "speed-mode send result");
        ReceiveExact(tcp.second.value, "fast");
        Sleep(50);
        Check(collector.Count() == before_speed, "speed mode counts without packet frames");
        counters = *hooks.LivePacketCounters();
        Check(counters[0] == 12 && counters[9] == 27 && counters[10] == 28,
              "speed mode preserves target counters");
        hooks.ResetLivePacketCounters();
        counters = *hooks.LivePacketCounters();
        Check(counters[0] == 0 && counters[9] == 0 && counters[10] == 0,
              "live counters reset atomically");
        hooks.StopHook();
        hooks.ConfigureSpeedMode(false);

        collector.Clear();
        flags.fill(false); flags[0] = true; flags[1] = true;
        flags[2] = true; flags[3] = true;
        hooks.ConfigureHookFlags(flags);
        hooks.StartHook();
        using SendFn = int (WSAAPI*)(SOCKET, const char*, int, int);
        using SendToFn = int (WSAAPI*)(SOCKET, const char*, int, int, const sockaddr*, int);
        using RecvFn = int (WSAAPI*)(SOCKET, char*, int, int);
        using RecvFromFn = int (WSAAPI*)(SOCKET, char*, int, int, sockaddr*, int*);
        const auto ws1 = GetModuleHandleW(L"wsock32.dll");
        const auto ws1_send = reinterpret_cast<SendFn>(GetProcAddress(ws1, "send"));
        const auto ws1_send_to = reinterpret_cast<SendToFn>(GetProcAddress(ws1, "sendto"));
        const auto ws1_recv = reinterpret_cast<RecvFn>(GetProcAddress(ws1, "recv"));
        const auto ws1_recv_from = reinterpret_cast<RecvFromFn>(GetProcAddress(ws1, "recvfrom"));
        Check(ws1_send && ws1_send_to && ws1_recv && ws1_recv_from,
              "wsock32 exports resolved");
        Check(hooks.RegisteredHookCount() == 4, "all wsock32 hooks registered");
        Check(ws1_send(tcp.first.value, "legacy", 6, 0) == 6, "wsock32 send result");
        std::array<char, 16> legacy{};
        Check(ws1_recv(tcp.second.value, legacy.data(), static_cast<int>(legacy.size()), 0) == 6,
              "wsock32 recv result");
        packets = collector.Wait(2);
        Check(Has(packets, 0, "legacy") && Has(packets, 4, "legacy"),
              "wsock32 send/recv captured");
        collector.Clear();
        Check(ws1_send_to(udp.sender.value, "oldudp", 6, 0,
                          reinterpret_cast<const sockaddr*>(&udp.destination),
                          sizeof(udp.destination)) == 6, "wsock32 sendto result");
        std::array<char, 16> legacy_datagram{};
        sockaddr_in legacy_source{};
        int legacy_source_length = sizeof(legacy_source);
        Check(ws1_recv_from(udp.receiver.value, legacy_datagram.data(),
                            static_cast<int>(legacy_datagram.size()), 0,
                            reinterpret_cast<sockaddr*>(&legacy_source),
                            &legacy_source_length) == 6, "wsock32 recvfrom result");
        packets = collector.Wait(2);
        Check(Has(packets, 2, "oldudp") && Has(packets, 6, "oldudp"),
              "wsock32 sendto/recvfrom captured");
        hooks.StopHook();

        collector.Clear();
        flags.fill(false); flags[8] = true; flags[10] = true;
        hooks.ConfigureHookFlags(flags);
        hooks.StartHook();
        Check(hooks.RegisteredHookCount() == (sizeof(void*) == 4 ? 3U : 2U),
              "WSA hook set follows the original WSARecvEx architecture rule");
        std::array<char, 2> part1{'m','u'};
        std::array<char, 3> part2{'l','t','i'};
        WSABUF outgoing[2]{{static_cast<ULONG>(part1.size()), part1.data()},
                           {static_cast<ULONG>(part2.size()), part2.data()}};
        DWORD transferred = 0;
        Check(WSASend(tcp.first.value, outgoing, 2, &transferred, 0, nullptr, nullptr) == 0 &&
              transferred == 5, "WSASend result");
        std::array<char, 2> receive1{};
        std::array<char, 3> receive2{};
        WSABUF incoming[2]{{static_cast<ULONG>(receive1.size()), receive1.data()},
                           {static_cast<ULONG>(receive2.size()), receive2.data()}};
        DWORD receive_flags = 0;
        transferred = 0;
        Check(WSARecv(tcp.second.value, incoming, 2, &transferred, &receive_flags,
                      nullptr, nullptr) == 0 && transferred == 5, "WSARecv result");
        Check(WSASend(tcp.first.value,
                      reinterpret_cast<LPWSABUF>(static_cast<std::uintptr_t>(1)),
                      1, &transferred, 0, nullptr, nullptr) == SOCKET_ERROR,
              "invalid WSABUF array is passed to Winsock without crashing the detour");
        packets = collector.Wait(2);
        Check(Has(packets, 8, "multi") && Has(packets, 10, "multi"),
              "multi-buffer WSA send/recv captured");

        filter.name = Text("wsa-send-filter");
        filter.action = 0;
        filter.functions.fill(false);
        filter.functions[4] = true;
        filter.search = Text("0|66");
        filter.modify = Text("0|6c");
        hooks.ConfigureFilters({filter}, 0, false);
        collector.Clear();
        std::array<char, 2> filter_part1{'f','i'};
        std::array<char, 2> filter_part2{'v','e'};
        WSABUF filter_outgoing[2]{{2, filter_part1.data()}, {2, filter_part2.data()}};
        transferred = 0;
        Check(WSASend(tcp.first.value, filter_outgoing, 2, &transferred, 0, nullptr, nullptr) == 0 &&
              transferred == 4, "filtered WSASend result");
        ReceiveExact(tcp.second.value, "live");
        packets = collector.WaitFor(8, "five");
        sent_packet = Find(packets, 8, "five");
        Check(sent_packet && sent_packet->modified &&
              *sent_packet->modified == wpe::ByteBuffer({'l','i','v','e'}) &&
              sent_packet->filter_action == 0,
              "synchronous WSASend filters a scatter buffer without changing caller storage");

        filter.name = Text("wsa-recv-filter");
        filter.functions.fill(false);
        filter.functions[6] = true;
        filter.search = Text("0|72");
        filter.modify = Text("0|78");
        hooks.ConfigureFilters({filter}, 0, false);
        collector.Clear();
        Check(send(tcp.second.value, "reply", 5, 0) == 5, "WSARecv filter fixture sent");
        std::array<char, 2> filter_receive1{};
        std::array<char, 3> filter_receive2{};
        WSABUF filter_incoming[2]{{2, filter_receive1.data()}, {3, filter_receive2.data()}};
        transferred = 0;
        Check(WSARecv(tcp.first.value, filter_incoming, 2, &transferred, &receive_flags,
                      nullptr, nullptr) == 0 && transferred == 5,
              "filtered WSARecv result");
        Check(std::string(filter_receive1.data(), 2) + std::string(filter_receive2.data(), 3) == "xeply",
              "synchronous WSARecv writes modified bytes across caller buffers");
        packets = collector.WaitFor(10, "reply");
        received_packet = Find(packets, 10, "reply");
        Check(received_packet && received_packet->modified &&
              *received_packet->modified == wpe::ByteBuffer({'x','e','p','l','y'}),
              "WSARecv packet frame preserves raw and modified buffers");
        hooks.ConfigureFilters({}, 0, false);
        if constexpr (sizeof(void*) == 4) {
            using WsaRecvExFn = int (WSAAPI*)(SOCKET, char*, int, int*);
            const auto msws = GetModuleHandleW(L"mswsock.dll");
            const auto receive_ex = reinterpret_cast<WsaRecvExFn>(GetProcAddress(msws, "WSARecvEx"));
            Check(receive_ex != nullptr, "x86 WSARecvEx export resolved");
            Check(send(tcp.first.value, "ex", 2, 0) == 2, "WSARecvEx fixture sent");
            std::array<char, 8> ex_buffer{};
            int ex_flags = 0;
            Check(receive_ex(tcp.second.value, ex_buffer.data(),
                             static_cast<int>(ex_buffer.size()), &ex_flags) == 2,
                  "WSARecvEx result");
            packets = collector.WaitFor(11, "ex");
            Check(Has(packets, 11, "ex"), "x86 WSARecvEx captured with pointer flags signature");
        }
        hooks.StopHook();

        collector.Clear();
        flags.fill(false); flags[5] = true; flags[7] = true;
        hooks.ConfigureHookFlags(flags);
        hooks.StartHook();
        Check(sendto(udp.sender.value, "gram", 4, 0,
                     reinterpret_cast<const sockaddr*>(&udp.destination),
                     sizeof(udp.destination)) == 4, "sendto result");
        std::array<char, 16> datagram{};
        sockaddr_in source{};
        int source_length = sizeof(source);
        Check(recvfrom(udp.receiver.value, datagram.data(), static_cast<int>(datagram.size()), 0,
                       reinterpret_cast<sockaddr*>(&source), &source_length) == 4,
              "recvfrom result");
        packets = collector.Wait(2);
        Check(Has(packets, 3, "gram") && Has(packets, 7, "gram"),
              "ws2 sendto/recvfrom captured");
        hooks.StopHook();

        collector.Clear();
        flags.fill(false); flags[9] = true; flags[11] = true;
        hooks.ConfigureHookFlags(flags);
        hooks.StartHook();
        std::array<char, 3> udp1{'w','s','a'};
        std::array<char, 3> udp2{'u','d','p'};
        WSABUF udp_out[2]{{static_cast<ULONG>(udp1.size()), udp1.data()},
                          {static_cast<ULONG>(udp2.size()), udp2.data()}};
        transferred = 0;
        Check(WSASendTo(udp.sender.value, udp_out, 2, &transferred, 0,
                        reinterpret_cast<const sockaddr*>(&udp.destination),
                        sizeof(udp.destination), nullptr, nullptr) == 0 && transferred == 6,
              "WSASendTo result");
        std::array<char, 2> udp_in1{};
        std::array<char, 4> udp_in2{};
        WSABUF udp_in[2]{{static_cast<ULONG>(udp_in1.size()), udp_in1.data()},
                         {static_cast<ULONG>(udp_in2.size()), udp_in2.data()}};
        source_length = sizeof(source);
        receive_flags = 0;
        transferred = 0;
        Check(WSARecvFrom(udp.receiver.value, udp_in, 2, &transferred, &receive_flags,
                          reinterpret_cast<sockaddr*>(&source), &source_length,
                          nullptr, nullptr) == 0 && transferred == 6,
              "WSARecvFrom result");
        packets = collector.Wait(2);
        Check(Has(packets, 9, "wsaudp") && Has(packets, 12, "wsaudp"),
              "multi-buffer WSA sendto/recvfrom captured");
        hooks.StopHook();

        // The wire frame has a finite cap. A larger, otherwise-successful
        // Winsock call is still part of the original traffic counters, but its
        // uncapturable payload becomes an explicit delivery drop. A fresh
        // nonblocking socket makes send return a positive partial result
        // without transferring the whole 16 MiB test buffer.
        auto oversized_pair = TcpPair();
        u_long nonblocking = 1;
        Check(ioctlsocket(oversized_pair.first.value, FIONBIO, &nonblocking) == 0,
              "oversized fixture socket switched to nonblocking mode");
        constexpr std::size_t oversized_length =
            static_cast<std::size_t>(wpe::IpcProtocol::MaxPacketFrame) - 1024U + 1U;
        void* oversized = VirtualAlloc(nullptr, oversized_length,
                                       MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        Check(oversized != nullptr, "oversized fixture buffer allocated");
        collector.Clear();
        hooks.ResetLivePacketCounters();
        const auto dropped_before_oversized = hooks.DroppedPacketCount();
        flags.fill(false); flags[4] = true;
        hooks.ConfigureHookFlags(flags);
        hooks.StartHook();
        const int oversized_result = send(oversized_pair.first.value,
            static_cast<const char*>(oversized), static_cast<int>(oversized_length), 0);
        VirtualFree(oversized, 0, MEM_RELEASE);
        Check(oversized_result > 0,
              "oversized nonblocking send made positive forward progress");
        counters = *hooks.LivePacketCounters();
        Check(counters[0] == 1 && counters[1] == 1 &&
              counters[9] == static_cast<std::int64_t>(oversized_length),
              "oversized send is counted before bounded capture rejects its payload");
        Check(hooks.DroppedPacketCount() == dropped_before_oversized + 1,
              "oversized payload rejection is visible as a delivery drop");
        Sleep(20);
        Check(collector.Count() == 0,
              "oversized payload never emits an invalid over-limit packet frame");
        hooks.StopHook();

        flags.fill(false); flags[6] = true;
        hooks.ConfigureHookFlags(flags);
        hooks.StartHook();
        std::atomic<int> blocked_result{SOCKET_ERROR};
        std::thread blocked_receiver([&] {
            std::array<char, 8> bytes{};
            blocked_result.store(recv(tcp.second.value, bytes.data(),
                                      static_cast<int>(bytes.size()), 0));
        });
        const auto in_flight_deadline = std::chrono::steady_clock::now() + 2s;
        while (hooks.InFlightDetourCount() == 0 &&
               std::chrono::steady_clock::now() < in_flight_deadline) Sleep(1);
        const bool entered_detour = hooks.InFlightDetourCount() == 1;
        const auto stop_started = std::chrono::steady_clock::now();
        hooks.StopHook();
        const bool bounded_stop = std::chrono::steady_clock::now() - stop_started < 2s;
        const bool retained_trampoline = hooks.RegisteredHookCount() == 1;
        const bool released = send(tcp.first.value, "wake", 4, 0) == 4;
        blocked_receiver.join();
        const bool completed = blocked_result.load() == 4;
        hooks.StopHook();
        Check(entered_detour, "blocking recv entered the detour");
        Check(bounded_stop, "StopHook remains bounded while an entered recv is blocked");
        Check(retained_trampoline,
              "blocked detour keeps its trampoline registered until quiescent");
        Check(released, "blocked recv released");
        Check(completed, "entered recv completes through retained trampoline");
        Check(hooks.RegisteredHookCount() == 0,
              "quiescent retry removes the retained trampoline");

        const auto after_stop = collector.Count();
        Check(send(tcp.first.value, "plain", 5, 0) == 5, "unhooked send result");
        ReceiveExact(tcp.second.value, "plain");
        Sleep(50);
        Check(collector.Count() == after_stop, "StopHook removes all detours");
        Check(hooks.RegisteredHookCount() == 0, "StopHook removes MinHook registrations");

        // A packet writer failure is a real delivery loss, not a successful
        // capture. It must contribute to the same cumulative Dropped event the
        // UI already understands, and it must not escape onto the target's
        // send thread.
        auto failing_pair = TcpPair();
        std::atomic<std::int64_t> reported_drop{-1};
        wpe::WinsockHookController failing_writer(false,
            [](wpe::ByteBuffer) { throw std::runtime_error("deliberate packet sink failure"); },
            [&](wpe::ByteBuffer event_bytes) {
                try {
                    wpe::IpcReader event(event_bytes);
                    if (event.U8() == static_cast<std::uint8_t>(wpe::IpcEvent::Dropped))
                        reported_drop.store(event.I64());
                } catch (...) {}
            });
        flags.fill(false);
        flags[4] = true;
        failing_writer.ConfigureHookFlags(flags);
        failing_writer.StartHook();
        Check(send(failing_pair.first.value, "lost", 4, 0) == 4,
              "packet sink failure does not alter send result");
        ReceiveExact(failing_pair.second.value, "lost");
        for (int i = 0; i < 2000 && reported_drop.load() < 1; ++i) Sleep(1);
        Check(failing_writer.DroppedPacketCount() == 1,
              "packet sink failure contributes to cumulative delivery drops");
        Check(reported_drop.load() == 1,
              "packet sink failure emits the visible cumulative Dropped event");
        failing_writer.StopHook();

        std::cout << "PASS: " << checks
                  << " Winsock hook checks; 13 production signatures, packet frames, speed mode, counters and teardown\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
