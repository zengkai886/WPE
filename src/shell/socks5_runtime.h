#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <limits>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace wpe::shell {

struct Socks5Credential {
    std::string user;
    std::string password;
    // The remaining fields are used by the private WPC registration path.
    // Ordinary SOCKS5/HTTP authentication only needs user/password.
    std::string account_id;
    bool enabled{true};
    bool limit_devices{};
    std::size_t max_devices{1};
    bool expiry{};
    std::string expiry_time;
};

struct WpcDeviceInfo {
    std::string token;
    std::string account_id;
    std::string device_id;
    std::string client_ip;
    std::string version;
    std::string os;
};

// A proxy relay emits a small, ownership-safe copy of each forwarded chunk.
// The native host consumes it on its UI thread and turns it into a ProxyRow;
// the runtime never calls WebView2 directly from a Winsock worker thread.
struct ProxyPacket {
    std::uintptr_t socket{};
    std::uint8_t packet_type{};
    std::uint8_t domain_type{};
    std::string client_addr;
    std::string server_addr;
    std::string server_domain;
    std::vector<std::uint8_t> bytes;
};
using ProxyPacketCallback = std::function<void(ProxyPacket)>;

// Authentication/session lifecycle emitted by the native listener.  The
// callback carries only copied strings so a Winsock worker never touches the
// WebView or a host-owned socket.  The host aggregates these events into the
// Auth/Client feed (the same activity list the original WinForms client used).
struct ProxyClientEvent {
    bool connected{};
    std::string session_id;
    std::string account_key;
    std::string client_ip;
    std::string device_id;
    std::string client;
    std::string auth_time;
};
using ProxyClientCallback = std::function<void(ProxyClientEvent)>;

struct ProxyConnectionEvent {
    bool connected{};
    std::string session_id;
    std::string client_ip;
    int client_port{};
    std::string target;
    std::uint8_t domain_type{};
    std::string server_address;
    bool udp{};
    bool wpc{};
};
using ProxyConnectionCallback = std::function<void(ProxyConnectionEvent)>;

struct Socks5Config {
    std::string bind_address{"127.0.0.1"};
    std::uint16_t port{};
    std::size_t max_connections{256};
    bool require_auth{};
    bool only_wpc{};
    std::vector<Socks5Credential> credentials;
    // Includes disabled accounts so the WPC register response can preserve
    // the original distinction between bad credentials and a disabled or
    // expired account.  The ordinary credential vector remains the fast
    // path for regular SOCKS5 authentication.
    std::vector<Socks5Credential> wpc_accounts;
    ProxyPacketCallback on_packet;
    ProxyClientCallback on_client;
    ProxyConnectionCallback on_connection;
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
    std::uint64_t wpc_controls{};
    std::uint64_t wpc_devices{};
    std::uint64_t wpc_registers{};
    std::uint64_t wpc_pings{};
    std::uint64_t wpc_errors{};
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
    // Returns the account keys that currently have an authenticated SOCKS5
    // session (or a registered WPC control session).  This is deliberately a
    // separate snapshot from the traffic counters: account-list presence is
    // a UI concern and must not change the existing Stats ABI.
    [[nodiscard]] std::vector<std::string> OnlineAccounts() const;

private:
    enum class AuthMode { Failed, Username, WpcControl };
    struct SessionIdentity {
        bool via_wpc{};
        WpcDeviceInfo device;
        // Username for ordinary proxy authentication; account GUID for a
        // WPC token.  The data worker accepts either key when updating rows.
        std::string account_key;
    };

    void AcceptLoop();
    void Client(std::uintptr_t client);
    AuthMode Authenticate(std::uintptr_t client, SessionIdentity& identity);
    bool RunWpcControl(std::uintptr_t client);
    bool HandleWpcFrame(std::uintptr_t client, const std::vector<std::uint8_t>& frame, std::string& token);
    int RegisterWpc(std::uintptr_t client, const std::string& payload, std::string& token, std::string& message);
    bool AuthenticateWpcToken(const std::string& user, const std::string& token, WpcDeviceInfo& device) const;
    void UnregisterWpc(const std::string& token, std::uintptr_t client);
    static bool ValidWpcDeviceId(const std::string& value);
    static std::string CleanWpcLabel(const std::string& value, std::size_t max_length);
    static bool AccountExpired(const Socks5Credential& account);
    static std::string NewWpcToken();
    static bool SendWpcFrame(std::uintptr_t client, std::uint8_t type, const std::string& payload);
    void MarkAccountOnline(const std::string& account_key);
    void MarkAccountOffline(const std::string& account_key);
    bool ConnectRequest(std::uintptr_t client, std::uintptr_t& remote);
    bool RelayUdp(std::uintptr_t client, std::uintptr_t udp_socket);
    void Relay(std::uintptr_t client, std::uintptr_t remote);
    void EmitPacket(ProxyPacket packet) const;
    void EmitClient(ProxyClientEvent event) const;
    void EmitConnection(ProxyConnectionEvent event) const;
    static void Close(std::uintptr_t socket) noexcept;

    mutable std::mutex lifecycle_;
    std::atomic<bool> stopping_{false};
    std::atomic<bool> running_{false};
    std::atomic<std::uintptr_t> listener_{std::numeric_limits<std::uintptr_t>::max()};
    std::thread accept_thread_;
    std::vector<std::thread> clients_;
    Socks5Config config_;
    mutable std::mutex wpc_mutex_;
    mutable std::mutex account_mutex_;
    std::unordered_map<std::string, WpcDeviceInfo> wpc_devices_;
    std::unordered_map<std::string, std::string> wpc_account_devices_;
    std::unordered_map<std::string, std::uintptr_t> wpc_controls_;
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
    std::atomic<std::uint64_t> udp_requests_{0};
    std::atomic<std::uint64_t> udp_responses_{0};
    std::atomic<std::uint64_t> udp_active_{0};
    std::atomic<std::uint64_t> wpc_controls_count_{0};
    std::atomic<std::uint64_t> wpc_registers_{0};
    std::atomic<std::uint64_t> wpc_pings_{0};
    std::atomic<std::uint64_t> wpc_errors_{0};
    bool winsock_started_{};
};

} // namespace wpe::shell
