#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include "shell/socks5_runtime.h"

#include <array>
#include <chrono>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

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

        std::uint16_t auth_destination_port{};
        auto auth_listener = Listener(auth_destination_port);
        Check(runtime.Start({"127.0.0.1", 0, 8, true, false, {Socks5Credential{"user", "pass"}}}, error),
              error.c_str());
        std::thread auth_destination([&] { RunDestination(auth_listener); });
        RunRelay(runtime, auth_destination_port, true);
        auth_destination.join();
        runtime.Stop();
        std::cout << "PASS: SOCKS5 no-auth and username/password CONNECT relay, counters, restart and stop\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
