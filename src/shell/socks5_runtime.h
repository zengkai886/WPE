#pragma once

#include <atomic>
#include <cstdint>
#include <mutex>
#include <limits>
#include <string>
#include <thread>
#include <vector>

namespace wpe::shell {

struct Socks5Credential {
    std::string user;
    std::string password;
};

struct Socks5Config {
    std::string bind_address{"127.0.0.1"};
    std::uint16_t port{};
    std::size_t max_connections{256};
    bool require_auth{};
    bool only_wpc{};
    std::vector<Socks5Credential> credentials;
};

struct Socks5Stats {
    bool running{};
    std::uint16_t port{};
    std::uint64_t accepted{};
    std::uint64_t completed{};
    std::uint64_t active{};
    std::uint64_t requests{};
    std::uint64_t responses{};
    std::uint64_t bytes_up{};
    std::uint64_t bytes_down{};
    std::uint64_t errors{};
    // HTTP mapping counters are zero for SOCKS5 and populated by the HTTP
    // runtime.  Keeping them in the shared snapshot makes the native status
    // path additive without introducing a second statistics DTO.
    std::uint64_t map_hits{};
    std::uint64_t map_misses{};
    std::uint64_t map_errors{};
    std::uint64_t udp_requests{};
    std::uint64_t udp_responses{};
    std::uint64_t udp_active{};
};

// Small, self-contained SOCKS5 runtime used by the native proxy mode.  It
// implements TCP CONNECT and RFC 1928 UDP ASSOCIATE; HTTP/HTTPS uses the
// sibling HttpProxyRuntime while WPC transport remains a separate protocol.
class Socks5Runtime final {
public:
    Socks5Runtime() = default;
    ~Socks5Runtime();
    Socks5Runtime(const Socks5Runtime&) = delete;
    Socks5Runtime& operator=(const Socks5Runtime&) = delete;

    bool Start(Socks5Config config, std::string& error);
    void Stop();
    [[nodiscard]] Socks5Stats Stats() const noexcept;
    [[nodiscard]] bool Running() const noexcept;

private:
    void AcceptLoop();
    void Client(std::uintptr_t client);
    bool Authenticate(std::uintptr_t client) const;
    bool ConnectRequest(std::uintptr_t client, std::uintptr_t& remote);
    bool RelayUdp(std::uintptr_t client, std::uintptr_t udp_socket);
    void Relay(std::uintptr_t client, std::uintptr_t remote);
    static void Close(std::uintptr_t socket) noexcept;

    mutable std::mutex lifecycle_;
    std::atomic<bool> stopping_{false};
    std::atomic<bool> running_{false};
    std::atomic<std::uintptr_t> listener_{std::numeric_limits<std::uintptr_t>::max()};
    std::thread accept_thread_;
    std::vector<std::thread> clients_;
    Socks5Config config_;
    std::atomic<std::uint16_t> port_{0};
    std::atomic<std::uint64_t> accepted_{0};
    std::atomic<std::uint64_t> completed_{0};
    std::atomic<std::uint64_t> active_{0};
    std::atomic<std::uint64_t> requests_{0};
    std::atomic<std::uint64_t> responses_{0};
    std::atomic<std::uint64_t> bytes_up_{0};
    std::atomic<std::uint64_t> bytes_down_{0};
    std::atomic<std::uint64_t> errors_{0};
    std::atomic<std::uint64_t> udp_requests_{0};
    std::atomic<std::uint64_t> udp_responses_{0};
    std::atomic<std::uint64_t> udp_active_{0};
    bool winsock_started_{};
};

} // namespace wpe::shell
