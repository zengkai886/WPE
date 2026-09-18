#pragma once

#include "web_bridge.h"

#include <atomic>
#include <cstdint>
#include <limits>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace wpe::shell {

// The WPC control surface is deliberately separate from the forward proxy:
// it is a small HTTP service used by Proxy Cap to pull node/rule and notice
// snapshots.  The two ProxyCap endpoints are intentionally unauthenticated;
// the management/health endpoint uses HTTP Basic authentication.
struct WpcConfig {
    std::string bind_address{"127.0.0.1"};
    std::uint16_t port{};
    std::string user;
    std::string password;
    Json servers{Json::array()};
    Json notices{Json::array()};
};

struct WpcStats {
    bool running{};
    std::uint16_t port{};
    std::uint64_t accepted{};
    std::uint64_t completed{};
    std::uint64_t active{};
    std::uint64_t requests{};
    std::uint64_t responses{};
    std::uint64_t server_requests{};
    std::uint64_t notice_requests{};
    std::uint64_t errors{};
};

class WpcRuntime final {
public:
    WpcRuntime() = default;
    ~WpcRuntime();
    WpcRuntime(const WpcRuntime&) = delete;
    WpcRuntime& operator=(const WpcRuntime&) = delete;

    bool Start(WpcConfig config, std::string& error);
    void Stop();
    // Replaces only the published data.  Existing client connections finish
    // against their current request, while the next request observes the new
    // snapshot without a listener restart.
    void Update(Json servers, Json notices);
    [[nodiscard]] WpcStats Stats() const noexcept;
    [[nodiscard]] bool Running() const noexcept;

private:
    void AcceptLoop();
    void Client(std::uintptr_t client);
    static void Close(std::uintptr_t socket) noexcept;

    mutable std::mutex lifecycle_;
    mutable std::mutex data_mutex_;
    std::atomic<bool> stopping_{false};
    std::atomic<bool> running_{false};
    std::atomic<std::uintptr_t> listener_{std::numeric_limits<std::uintptr_t>::max()};
    std::thread accept_thread_;
    std::vector<std::thread> clients_;
    // Keep the accepted sockets separately from the worker threads so Stop()
    // can actively wake a client that is still waiting for request bytes.
    // Joining a thread without closing its socket would otherwise make
    // shutdown depend on the peer eventually sending or closing the request.
    mutable std::mutex clients_mutex_;
    std::vector<std::uintptr_t> active_clients_;
    WpcConfig config_;
    std::atomic<std::uint16_t> port_{0};
    std::atomic<std::uint64_t> accepted_{0};
    std::atomic<std::uint64_t> completed_{0};
    std::atomic<std::uint64_t> active_{0};
    std::atomic<std::uint64_t> requests_{0};
    std::atomic<std::uint64_t> responses_{0};
    std::atomic<std::uint64_t> server_requests_{0};
    std::atomic<std::uint64_t> notice_requests_{0};
    std::atomic<std::uint64_t> errors_{0};
    bool winsock_started_{};
};

} // namespace wpe::shell
