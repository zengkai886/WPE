#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include "shell/socks5_runtime.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstring>
#include <iostream>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using namespace std::chrono_literals;
using wpe::shell::Socks5Config;
using wpe::shell::Socks5Credential;
using wpe::shell::Socks5Runtime;

namespace {
void Check(bool value, const char* message) {
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
    explicit Socket(SOCKET socket = INVALID_SOCKET) : value(socket) {}
    ~Socket() { if (value != INVALID_SOCKET) closesocket(value); }
    Socket(const Socket&) = delete;
    Socket& operator=(const Socket&) = delete;
    Socket(Socket&& other) noexcept : value(other.value) { other.value = INVALID_SOCKET; }
};

Socket Listener(std::uint16_t& port) {
    Socket listener(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    Check(listener.value != INVALID_SOCKET, "destination socket failed");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    Check(bind(listener.value, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0,
          "destination bind failed");
    Check(listen(listener.value, 1) == 0, "destination listen failed");
    int size = sizeof(address);
    Check(getsockname(listener.value, reinterpret_cast<sockaddr*>(&address), &size) == 0,
          "destination getsockname failed");
    port = ntohs(address.sin_port);
    return listener;
}

Socket Connect(std::uint16_t port) {
    Socket client(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP));
    Check(client.value != INVALID_SOCKET, "client socket failed");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    Check(connect(client.value, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0,
          "client connect failed");
    return client;
}

Socket UdpListener(std::uint16_t& port) {
    Socket listener(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
    Check(listener.value != INVALID_SOCKET, "UDP destination socket failed");
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    Check(bind(listener.value, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0,
          "UDP destination bind failed");
    int size = sizeof(address);
    Check(getsockname(listener.value, reinterpret_cast<sockaddr*>(&address), &size) == 0,
          "UDP destination getsockname failed");
    port = ntohs(address.sin_port);
    return listener;
}

void SendAll(SOCKET socket, const std::uint8_t* data, std::size_t size) {
    while (size != 0) {
        const auto sent = send(socket, reinterpret_cast<const char*>(data), static_cast<int>(size), 0);
        Check(sent > 0, "client send failed");
        data += sent;
        size -= static_cast<std::size_t>(sent);
    }
}

void ReceiveAll(SOCKET socket, std::uint8_t* data, std::size_t size) {
    while (size != 0) {
        const auto received = recv(socket, reinterpret_cast<char*>(data), static_cast<int>(size), 0);
        Check(received > 0, "client receive failed");
        data += received;
        size -= static_cast<std::size_t>(received);
    }
}

void RunRelay(Socks5Runtime& runtime, std::uint16_t destination_port, bool auth) {
    auto client = Connect(runtime.Stats().port);
    if (auth) {
        const std::array<std::uint8_t, 3> methods{5, 1, 2};
        SendAll(client.value, methods.data(), methods.size());
        std::array<std::uint8_t, 2> selected{};
        ReceiveAll(client.value, selected.data(), selected.size());
        Check(selected == std::array<std::uint8_t, 2>{5, 2}, "username/password method not selected");
        const std::array<std::uint8_t, 11> credentials{1, 4, 'u', 's', 'e', 'r', 4, 'p', 'a', 's', 's'};
        SendAll(client.value, credentials.data(), credentials.size());
        std::array<std::uint8_t, 2> result{};
        ReceiveAll(client.value, result.data(), result.size());
        Check(result == std::array<std::uint8_t, 2>{1, 0}, "proxy authentication failed");
        const auto online = runtime.OnlineAccounts();
        Check(std::find(online.begin(), online.end(), "user") != online.end(),
              "authenticated account was not reported online");
    } else {
        const std::array<std::uint8_t, 3> methods{5, 1, 0};
        SendAll(client.value, methods.data(), methods.size());
        std::array<std::uint8_t, 2> selected{};
        ReceiveAll(client.value, selected.data(), selected.size());
        Check(selected == std::array<std::uint8_t, 2>{5, 0}, "no-auth method not selected");
    }
    const std::array<std::uint8_t, 10> request{
        5, 1, 0, 1, 127, 0, 0, 1,
        static_cast<std::uint8_t>(destination_port >> 8), static_cast<std::uint8_t>(destination_port & 0xff)};
    SendAll(client.value, request.data(), request.size());
    std::array<std::uint8_t, 10> reply{};
    ReceiveAll(client.value, reply.data(), reply.size());
    Check(reply[0] == 5 && reply[1] == 0, "SOCKS CONNECT was rejected");
    SendAll(client.value, reinterpret_cast<const std::uint8_t*>("ping"), 4);
    std::array<std::uint8_t, 4> response{};
    ReceiveAll(client.value, response.data(), response.size());
    Check(std::memcmp(response.data(), "pong", 4) == 0, "relay response mismatch");
}

void RunDestination(Socket& listener) {
    Socket server(accept(listener.value, nullptr, nullptr));
    Check(server.value != INVALID_SOCKET, "destination accept failed");
    std::array<char, 4> request{};
    ReceiveAll(server.value, reinterpret_cast<std::uint8_t*>(request.data()), request.size());
    Check(request == std::array<char, 4>{'p', 'i', 'n', 'g'}, "destination request mismatch");
    SendAll(server.value, reinterpret_cast<const std::uint8_t*>("pong"), 4);
}

void RunUdpDestination(Socket& listener) {
    std::array<char, 64> request{};
    sockaddr_in source{};
    int source_size = sizeof(source);
    const auto count = recvfrom(listener.value, request.data(), static_cast<int>(request.size()), 0,
                                reinterpret_cast<sockaddr*>(&source), &source_size);
    Check(count == 4 && std::memcmp(request.data(), "ping", 4) == 0, "UDP destination request mismatch");
    const auto sent = sendto(listener.value, "pong", 4, 0, reinterpret_cast<const sockaddr*>(&source), source_size);
    Check(sent == 4, "UDP destination response failed");
}

void RunUdpAssociate(Socks5Runtime& runtime, std::uint16_t destination_port) {
    auto control = Connect(runtime.Stats().port);
    const std::array<std::uint8_t, 3> methods{5, 1, 0};
    SendAll(control.value, methods.data(), methods.size());
    std::array<std::uint8_t, 2> selected{};
    ReceiveAll(control.value, selected.data(), selected.size());
    Check(selected == std::array<std::uint8_t, 2>{5, 0}, "UDP no-auth method not selected");

    const std::array<std::uint8_t, 10> request{5, 3, 0, 1, 0, 0, 0, 0, 0, 0};
    SendAll(control.value, request.data(), request.size());
    std::array<std::uint8_t, 10> reply{};
    ReceiveAll(control.value, reply.data(), reply.size());
    Check(reply[0] == 5 && reply[1] == 0 && reply[3] == 1, "SOCKS UDP ASSOCIATE was rejected");
    const auto relay_port = static_cast<std::uint16_t>((static_cast<std::uint16_t>(reply[8]) << 8) | reply[9]);
    Check(relay_port != 0, "SOCKS UDP relay port missing");

    Socket client(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));
    Check(client.value != INVALID_SOCKET, "UDP client socket failed");
    sockaddr_in client_bind{};
    client_bind.sin_family = AF_INET;
    client_bind.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    Check(bind(client.value, reinterpret_cast<const sockaddr*>(&client_bind), sizeof(client_bind)) == 0,
          "UDP client bind failed");
    DWORD timeout = 2000;
    setsockopt(client.value, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    std::array<std::uint8_t, 14> packet{0, 0, 0, 1, 127, 0, 0, 1,
                                        static_cast<std::uint8_t>(destination_port >> 8),
                                        static_cast<std::uint8_t>(destination_port & 0xff), 'p', 'i', 'n', 'g'};
    sockaddr_in relay{};
    relay.sin_family = AF_INET;
    relay.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    relay.sin_port = htons(relay_port);
    const auto sent = sendto(client.value, reinterpret_cast<const char*>(packet.data()), static_cast<int>(packet.size()), 0,
                             reinterpret_cast<const sockaddr*>(&relay), sizeof(relay));
    Check(sent == static_cast<int>(packet.size()), "UDP association request failed");

    std::array<std::uint8_t, 64> response{};
    sockaddr_in response_source{};
    int response_size = sizeof(response_source);
    const auto received = recvfrom(client.value, reinterpret_cast<char*>(response.data()), static_cast<int>(response.size()), 0,
                                   reinterpret_cast<sockaddr*>(&response_source), &response_size);
    Check(received >= 14 && response[0] == 0 && response[1] == 0 && response[2] == 0 &&
          std::memcmp(response.data() + received - 4, "pong", 4) == 0, "UDP association response mismatch");
}

void SendWpcFrame(SOCKET socket, std::uint8_t type, const std::string& payload) {
    Check(payload.size() <= 4091, "WPC payload too large");
    std::vector<std::uint8_t> frame(5 + payload.size());
    frame[0] = 0x57;
    frame[1] = 0x01;
    frame[2] = type;
    frame[3] = static_cast<std::uint8_t>(payload.size() >> 8);
    frame[4] = static_cast<std::uint8_t>(payload.size() & 0xff);
    std::copy(payload.begin(), payload.end(), frame.begin() + 5);
    SendAll(socket, frame.data(), frame.size());
}

std::pair<std::uint8_t, std::string> ReceiveWpcFrame(SOCKET socket) {
    std::array<std::uint8_t, 5> header{};
    ReceiveAll(socket, header.data(), header.size());
    Check(header[0] == 0x57 && header[1] == 0x01, "invalid WPC response header");
    const auto size = (static_cast<std::size_t>(header[3]) << 8) | header[4];
    Check(size <= 4091, "invalid WPC response size");
    std::string payload(size, '\0');
    if (size != 0) ReceiveAll(socket, reinterpret_cast<std::uint8_t*>(payload.data()), size);
    return {header[2], std::move(payload)};
}

void RunWpcControlAndToken(Socks5Runtime& runtime, Socket& listener, std::uint16_t destination_port) {
    auto control = Connect(runtime.Stats().port);
    const std::array<std::uint8_t, 4> methods{5, 2, 2, 0x80};
    SendAll(control.value, methods.data(), methods.size());
    std::array<std::uint8_t, 2> selected{};
    ReceiveAll(control.value, selected.data(), selected.size());
    Check(selected == std::array<std::uint8_t, 2>{5, 0x80}, "private WPC method not selected");

    SendWpcFrame(control.value, 0x01,
                 R"({"user":"user","pass":"pass","device":"device-001","version":"1.0","client":"WPE","os":"Windows"})");
    const auto registration = ReceiveWpcFrame(control.value);
    Check(registration.first == 0x81, "WPC register result type mismatch");
    const auto register_json = nlohmann::json::parse(registration.second);
    Check(register_json.value("code", -1) == 0, "WPC registration failed");
    const auto token = register_json.value("token", std::string{});
    Check(token.rfind("wpc1.", 0) == 0, "WPC token prefix mismatch");

    SendWpcFrame(control.value, 0x02, "{}");
    const auto pong = ReceiveWpcFrame(control.value);
    Check(pong.first == 0x82, "WPC pong type mismatch");

    // A WPC token is a regular SOCKS username/password credential for data
    // sessions.  Only-WPC mode must reject the original password here.
    auto rejected = Connect(runtime.Stats().port);
    const std::array<std::uint8_t, 3> auth_methods{5, 1, 2};
    SendAll(rejected.value, auth_methods.data(), auth_methods.size());
    ReceiveAll(rejected.value, selected.data(), selected.size());
    Check(selected == std::array<std::uint8_t, 2>{5, 2}, "WPC data auth method mismatch");
    const std::array<std::uint8_t, 11> ordinary{1, 4, 'u', 's', 'e', 'r', 4, 'p', 'a', 's', 's'};
    SendAll(rejected.value, ordinary.data(), ordinary.size());
    std::array<std::uint8_t, 2> rejected_result{};
    ReceiveAll(rejected.value, rejected_result.data(), rejected_result.size());
    Check(rejected_result == std::array<std::uint8_t, 2>{1, 1}, "ordinary credential bypassed Only-WPC");

    std::thread destination([&] { RunDestination(listener); });
    auto data = Connect(runtime.Stats().port);
    SendAll(data.value, auth_methods.data(), auth_methods.size());
    ReceiveAll(data.value, selected.data(), selected.size());
    Check(selected == std::array<std::uint8_t, 2>{5, 2}, "WPC token method not selected");
    std::vector<std::uint8_t> token_credentials{1, static_cast<std::uint8_t>(4)};
    token_credentials.insert(token_credentials.end(), {'u', 's', 'e', 'r'});
    token_credentials.push_back(static_cast<std::uint8_t>(token.size()));
    token_credentials.insert(token_credentials.end(), token.begin(), token.end());
    SendAll(data.value, token_credentials.data(), token_credentials.size());
    std::array<std::uint8_t, 2> token_result{};
    ReceiveAll(data.value, token_result.data(), token_result.size());
    Check(token_result == std::array<std::uint8_t, 2>{1, 0}, "WPC token authentication failed");
    const std::array<std::uint8_t, 10> request{
        5, 1, 0, 1, 127, 0, 0, 1,
        static_cast<std::uint8_t>(destination_port >> 8), static_cast<std::uint8_t>(destination_port & 0xff)};
    SendAll(data.value, request.data(), request.size());
    std::array<std::uint8_t, 10> reply{};
    ReceiveAll(data.value, reply.data(), reply.size());
    Check(reply[0] == 5 && reply[1] == 0, "WPC token CONNECT was rejected");
    SendAll(data.value, reinterpret_cast<const std::uint8_t*>("ping"), 4);
    std::array<std::uint8_t, 4> response{};
    ReceiveAll(data.value, response.data(), response.size());
    Check(std::memcmp(response.data(), "pong", 4) == 0, "WPC token relay response mismatch");
    shutdown(data.value, SD_BOTH);
    closesocket(data.value);
    data.value = INVALID_SOCKET;
    destination.join();
    const auto live = runtime.Stats();
    Check(live.wpc_controls == 1 && live.wpc_devices == 1, "WPC live state was not reported");
}
} // namespace

int main() {
    try {
        Winsock winsock;
        Socks5Runtime runtime;
        std::uint16_t destination_port{};
        auto listener = Listener(destination_port);
        std::string error;
        Check(runtime.Start({"127.0.0.1", 0, 8, false, false, {}}, error), error.c_str());
        std::thread destination([&] { RunDestination(listener); });
        RunRelay(runtime, destination_port, false);
        destination.join();
        for (int i = 0; i != 50 && runtime.Stats().active != 0; ++i) std::this_thread::sleep_for(10ms);
        auto stats = runtime.Stats();
        Check(stats.accepted == 1 && stats.completed == 1 && stats.active == 0, "no-auth session counters mismatch");
        Check(stats.requests == 1 && stats.responses >= 1 && stats.bytes_up >= 4 && stats.bytes_down >= 4,
              "relay counters mismatch");
        runtime.Stop();
        Check(!runtime.Running() && runtime.Stats().port == 0, "runtime did not stop");

        std::uint16_t udp_destination_port{};
        auto udp_listener = UdpListener(udp_destination_port);
        Check(runtime.Start({"127.0.0.1", 0, 8, false, false, {}}, error), error.c_str());
        std::thread udp_destination([&] { RunUdpDestination(udp_listener); });
        RunUdpAssociate(runtime, udp_destination_port);
        udp_destination.join();
        for (int i = 0; i != 50 && runtime.Stats().active != 0; ++i) std::this_thread::sleep_for(10ms);
        const auto udp_stats = runtime.Stats();
        Check(udp_stats.udp_requests == 1 && udp_stats.udp_responses == 1 && udp_stats.udp_active == 0 &&
              udp_stats.bytes_up >= 4 && udp_stats.bytes_down >= 4, "UDP association counters mismatch");
        runtime.Stop();

        std::uint16_t auth_destination_port{};
        auto auth_listener = Listener(auth_destination_port);
        Check(runtime.Start({"127.0.0.1", 0, 8, true, false, {Socks5Credential{"user", "pass"}}}, error),
              error.c_str());
        std::thread auth_destination([&] { RunDestination(auth_listener); });
        RunRelay(runtime, auth_destination_port, true);
        auth_destination.join();
        for (int i = 0; i != 50 && !runtime.OnlineAccounts().empty(); ++i) std::this_thread::sleep_for(10ms);
        Check(runtime.OnlineAccounts().empty(), "authenticated account remained online after disconnect");
        runtime.Stop();

        std::uint16_t wpc_destination_port{};
        auto wpc_listener = Listener(wpc_destination_port);
        Socks5Credential wpc_account;
        wpc_account.user = "user";
        wpc_account.password = "pass";
        wpc_account.account_id = "account-001";
        wpc_account.enabled = true;
        wpc_account.limit_devices = true;
        wpc_account.max_devices = 2;
        Socks5Config wpc_config;
        wpc_config.bind_address = "127.0.0.1";
        wpc_config.max_connections = 8;
        wpc_config.require_auth = true;
        wpc_config.only_wpc = true;
        wpc_config.credentials = {wpc_account};
        wpc_config.wpc_accounts = {wpc_account};
        Check(runtime.Start(std::move(wpc_config), error), error.c_str());
        RunWpcControlAndToken(runtime, wpc_listener, wpc_destination_port);
        for (int i = 0; i != 100 && runtime.Stats().active != 0; ++i) std::this_thread::sleep_for(10ms);
        const auto wpc_stats = runtime.Stats();
        Check(wpc_stats.wpc_controls == 0 && wpc_stats.wpc_devices == 0,
              "WPC control/device state did not clear on disconnect");
        Check(wpc_stats.wpc_registers == 1 && wpc_stats.wpc_pings == 1 && wpc_stats.wpc_errors == 0,
              "WPC counters mismatch");
        runtime.Stop();
        std::cout << "PASS: SOCKS5 TCP CONNECT, UDP ASSOCIATE, auth, private WPC control/token relay, counters, restart and stop\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
