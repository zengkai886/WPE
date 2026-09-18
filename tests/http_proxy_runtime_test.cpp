#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include "shell/http_proxy_runtime.h"

#include <array>
#include <chrono>
#include <cstring>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>

using namespace std::chrono_literals;
using wpe::shell::HttpProxyConfig;
using wpe::shell::HttpProxyRuntime;
using wpe::shell::Socks5Credential;

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

void SendAll(SOCKET socket, const std::string& value) {
    const auto* data = reinterpret_cast<const std::uint8_t*>(value.data());
    auto remaining = value.size();
    while (remaining != 0) {
        const auto sent = send(socket, reinterpret_cast<const char*>(data), static_cast<int>(remaining), 0);
        Check(sent > 0, "send failed");
        data += sent;
        remaining -= static_cast<std::size_t>(sent);
    }
}

std::string ReceiveUntil(SOCKET socket, std::string_view marker) {
    std::string result;
    std::array<char, 4096> buffer{};
    while (result.find(marker) == std::string::npos && result.size() < 128 * 1024) {
        const auto count = recv(socket, buffer.data(), static_cast<int>(buffer.size()), 0);
        Check(count > 0, "receive failed");
        result.append(buffer.data(), static_cast<std::size_t>(count));
    }
    Check(result.find(marker) != std::string::npos, "response marker missing");
    return result;
}

void RunHttpDestination(Socket& listener, std::string expected_path) {
    Socket server(accept(listener.value, nullptr, nullptr));
    Check(server.value != INVALID_SOCKET, "HTTP destination accept failed");
    const auto request = ReceiveUntil(server.value, "\r\n\r\n");
    Check(request.find("GET " + expected_path + " HTTP/1.1") != std::string::npos,
          "HTTP origin-form request mismatch");
    Check(request.find("Proxy-Authorization") == std::string::npos, "proxy authorization leaked upstream");
    const std::string response="HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\npong";
    SendAll(server.value, response);
}

void RunConnectDestination(Socket& listener) {
    Socket server(accept(listener.value, nullptr, nullptr));
    Check(server.value != INVALID_SOCKET, "CONNECT destination accept failed");
    std::array<char, 4> request{};
    const auto count=recv(server.value,request.data(),static_cast<int>(request.size()),0);
    Check(count==4&&std::memcmp(request.data(),"ping",4)==0,"CONNECT payload mismatch");
    SendAll(server.value,"pong");
}
} // namespace

int main() {
    try {
        Winsock winsock;
        HttpProxyRuntime runtime;
        std::string error;
        Check(runtime.Start(HttpProxyConfig{"127.0.0.1",0,8,false,{}},error),error.c_str());

        std::uint16_t destination_port{};
        auto listener=Listener(destination_port);
        std::thread destination([&]{RunHttpDestination(listener,"/hello");});
        {
            auto client=Connect(runtime.Stats().port);
            SendAll(client.value,"GET http://127.0.0.1:"+std::to_string(destination_port)+"/hello HTTP/1.1\r\n"
                               "Host: 127.0.0.1:"+std::to_string(destination_port)+"\r\n"
                               "Proxy-Connection: keep-alive\r\n\r\n");
            const auto response=ReceiveUntil(client.value,"pong");
            Check(response.find("HTTP/1.1 200 OK")!=std::string::npos,"HTTP response status mismatch");
        }
        destination.join();

        std::uint16_t connect_port{};
        auto connect_listener=Listener(connect_port);
        std::thread connect_destination([&]{RunConnectDestination(connect_listener);});
        {
            auto client=Connect(runtime.Stats().port);
            SendAll(client.value,"CONNECT 127.0.0.1:"+std::to_string(connect_port)+" HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
            const auto response=ReceiveUntil(client.value,"\r\n\r\n");
            Check(response.find("200 Connection Established")!=std::string::npos,"CONNECT was rejected");
            SendAll(client.value,"ping");
            const auto payload=ReceiveUntil(client.value,"pong");
            Check(payload.find("pong")!=std::string::npos,"CONNECT relay response mismatch");
        }
        connect_destination.join();
        for(int i=0;i!=50&&runtime.Stats().active!=0;++i)std::this_thread::sleep_for(10ms);
        auto stats=runtime.Stats();
        Check(stats.accepted==2&&stats.completed==2&&stats.active==0,"HTTP session counters mismatch");
        Check(stats.requests==2&&stats.responses>=2&&stats.bytes_up>=4&&stats.bytes_down>=4,"HTTP relay counters mismatch");
        runtime.Stop();
        Check(!runtime.Running()&&runtime.Stats().port==0,"HTTP runtime did not stop");

        Check(runtime.Start(HttpProxyConfig{"127.0.0.1",0,8,true,{Socks5Credential{"user","pass"}}},error),error.c_str());
        {
            auto client=Connect(runtime.Stats().port);
            SendAll(client.value,"GET http://127.0.0.1/without-auth HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
            const auto response=ReceiveUntil(client.value,"\r\n\r\n");
            Check(response.find("407 Proxy Authentication Required")!=std::string::npos,"missing proxy auth challenge");
        }
        std::uint16_t auth_destination_port{};
        auto auth_listener=Listener(auth_destination_port);
        std::thread auth_destination([&]{RunHttpDestination(auth_listener,"/auth");});
        {
            auto client=Connect(runtime.Stats().port);
            SendAll(client.value,"GET http://127.0.0.1:"+std::to_string(auth_destination_port)+"/auth HTTP/1.1\r\n"
                               "Host: 127.0.0.1\r\nProxy-Authorization: Basic dXNlcjpwYXNz\r\n\r\n");
            const auto response=ReceiveUntil(client.value,"pong");
            Check(response.find("200 OK")!=std::string::npos,"authenticated HTTP request failed");
        }
        auth_destination.join();
        runtime.Stop();
        std::cout<<"PASS: HTTP absolute-form, CONNECT tunnel, proxy auth, counters, restart and stop\n";
        return 0;
    } catch(const std::exception& error) {
        std::cerr<<"FAIL: "<<error.what()<<'\n';
        return 1;
    }
}
