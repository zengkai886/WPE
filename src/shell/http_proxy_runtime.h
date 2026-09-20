#pragma once

#include "socks5_runtime.h"

#include <atomic>
#include <cstdint>
#include <limits>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace wpe::shell {

struct HttpProxyConfig {
    std::string bind_address{"127.0.0.1"};
    std::uint16_t port{};
    std::size_t max_connections{256};
    bool require_auth{};
    std::vector<Socks5Credential> credentials;
    bool enable_local_map{};
    bool enable_remote_map{};

    struct LocalMapRule {
        bool enabled{};
        std::string protocol{"Http"};
        std::string host;
        std::uint16_t port{80};
        std::string remote_path;
        std::string local_path;
    };
    struct RemoteMapRule {
        bool enabled{};
        std::string protocol_from{"Http"};
        std::string host_from;
        std::uint16_t port_from{80};
        std::string path_from;
        std::string protocol_to{"Http"};
        std::string host_to;
        std::uint16_t port_to{80};
        std::string path_to;
    };
    std::vector<LocalMapRule> local_maps;
    std::vector<RemoteMapRule> remote_maps;
    ProxyPacketCallback on_packet;
    ProxyClientCallback on_client;
    ProxyConnectionCallback on_connection;
};

// HTTP forward proxy runtime.  It supports ordinary absolute-form HTTP
// requests and CONNECT tunnelling; each client is deliberately single-request
// and closed after the upstream connection closes.
class HttpProxyRuntime final {
public:
    HttpProxyRuntime() = default;
    ~HttpProxyRuntime();
    HttpProxyRuntime(const HttpProxyRuntime&) = delete;
    HttpProxyRuntime& operator=(const HttpProxyRuntime&) = delete;

    bool Start(HttpProxyConfig config, std::string& error);
    void Stop();
    [[nodiscard]] Socks5Stats Stats() const noexcept;
    [[nodiscard]] bool Running() const noexcept;
    [[nodiscard]] std::vector<std::string> OnlineAccounts() const;

private:
    void AcceptLoop();
    void Client(std::uintptr_t client);
    bool HandleRequest(std::uintptr_t client, std::uintptr_t& remote, std::string& account_key, bool& connection_emitted);
    bool ConnectTarget(const std::string& host, std::uint16_t port, std::uintptr_t& remote);
    void Relay(std::uintptr_t client, std::uintptr_t remote, const std::string& server_domain = {}, std::uint8_t domain_type = 1);
    void EmitPacket(ProxyPacket packet) const;
    void EmitClient(ProxyClientEvent event) const;
    void EmitConnection(ProxyConnectionEvent event) const;
    static void Close(std::uintptr_t socket) noexcept;
    void MarkAccountOnline(const std::string& account_key);
    void MarkAccountOffline(const std::string& account_key);

    mutable std::mutex lifecycle_;
    std::atomic<bool> stopping_{false};
    std::atomic<bool> running_{false};
    std::atomic<std::uintptr_t> listener_{std::numeric_limits<std::uintptr_t>::max()};
    std::thread accept_thread_;
    std::vector<std::thread> clients_;
    HttpProxyConfig config_;
    mutable std::mutex account_mutex_;
    std::unordered_map<std::string, std::size_t> online_accounts_;
    std::atomic<std::uint16_t> port_{0};
    std::atomic<std::uint64_t> accepted_{0};
    std::atomic<std::uint64_t> completed_{0};
    std::atomic<std::uint64_t> active_{0};
    std::atomic<std::uint64_t> requests_{0};
    std::atomic<std::uint64_t> responses_{0};
    std::atomic<std::uint64_t> bytes_up_{0};
    std::atomic<std::uint64_t> bytes_down_{0};
    std::atomic<std::uint64_t> errors_{0};
    std::atomic<std::uint64_t> map_hits_{0};
    std::atomic<std::uint64_t> map_misses_{0};
    std::atomic<std::uint64_t> map_errors_{0};
    bool winsock_started_{};
};

} // namespace wpe::shell
