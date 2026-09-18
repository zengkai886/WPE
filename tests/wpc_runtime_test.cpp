#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>

#include "shell/wpc_runtime.h"

#include <chrono>
#include <iostream>
#include <stdexcept>
#include <string>
#include <thread>

namespace {
using wpe::shell::Json;
void Require(bool value, const char* message) { if (!value) throw std::runtime_error(message); }

std::string Get(std::uint16_t port, const std::string& path, const std::string& authorization = {}) {
    SOCKET socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    Require(socket != INVALID_SOCKET, "socket");
    sockaddr_in address{}; address.sin_family = AF_INET; address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    Require(connect(socket, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0, "connect");
    std::string request = "GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n";
    if (!authorization.empty()) request += "Authorization: " + authorization + "\r\n";
    request += "\r\n";
    Require(send(socket, request.data(), static_cast<int>(request.size()), 0) == static_cast<int>(request.size()), "send");
    std::string result; char buffer[4096];
    for (;;) { const auto count = recv(socket, buffer, sizeof(buffer), 0); if (count <= 0) break; result.append(buffer, static_cast<std::size_t>(count)); }
    closesocket(socket); return result;
}
} // namespace

int main() {
    try {
        WSADATA data{}; Require(WSAStartup(MAKEWORD(2, 2), &data) == 0, "WSAStartup");
        wpe::shell::WpcRuntime runtime;
        wpe::shell::WpcConfig config;
        config.port = 0; config.user = "admin"; config.password = "secret";
        config.servers = {{{"IsEnable", true}, {"ServerName", "node"}, {"ServerIP", "10.0.0.1"}, {"ServerPort", 1080},
                           {"ForgotURL", "/forgot"}, {"RegisterURL", "/register"}, {"VerifyURL", "/verify"},
                           {"_rules", {{{"IsEnable", true}, {"RuleType", 1}, {"RuleArgument", "example.com"}, {"RuleAction", 0}}}}}};
        config.notices = {{{"NoticeType", 2}, {"NoticeTitle", "maintenance"}, {"NoticeContent", "soon"},
                           {"NoticeMore", "/more"}, {"NoticeTime", "2026-09-19T00:00:00"}}};
        std::string error; Require(runtime.Start(std::move(config), error), error.c_str());
        const auto port = runtime.Stats().port; Require(port != 0, "ephemeral WPC port");
        const auto servers = Get(port, "/ProxyCap/GetServerList");
        Require(servers.rfind("HTTP/1.1 200", 0) == 0 && servers.find("\"ServerName\":\"node\"") != std::string::npos &&
                servers.find("\"RArgument\":\"example.com\"") != std::string::npos, "server feed");
        const auto notices = Get(port, "/ProxyCap/GetNoticeList");
        Require(notices.rfind("HTTP/1.1 200", 0) == 0 && notices.find("\"NoticeTitle\":\"maintenance\"") != std::string::npos, "notice feed");
        const auto unauthorized = Get(port, "/healthz");
        Require(unauthorized.rfind("HTTP/1.1 401", 0) == 0, "health auth");
        const auto authorized = Get(port, "/healthz", "Basic YWRtaW46c2VjcmV0");
        Require(authorized.rfind("HTTP/1.1 200", 0) == 0 && authorized.find("\"serverRequests\":1") != std::string::npos, "health status");
        runtime.Update(Json::array({{{"IsEnable", true}, {"ServerName", "updated"}, {"ServerIP", "10.0.0.2"}, {"ServerPort", 1081}}}), Json::array());
        const auto updated = Get(port, "/ProxyCap/GetServerList");
        Require(updated.find("\"ServerName\":\"updated\"") != std::string::npos && updated.find("\"ServerName\":\"node\"") == std::string::npos, "snapshot update");
        const auto stats = runtime.Stats(); Require(stats.server_requests == 2 && stats.notice_requests == 1 && stats.active == 0, "WPC counters");

        // A peer that connected but has not sent a request must not make
        // Stop() hang.  This covers the same shutdown path used by a browser
        // tab that is abandoned while the service is being disabled.
        SOCKET blocked = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        Require(blocked != INVALID_SOCKET, "blocked socket");
        sockaddr_in blocked_address{}; blocked_address.sin_family = AF_INET;
        blocked_address.sin_port = htons(port); blocked_address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        Require(connect(blocked, reinterpret_cast<const sockaddr*>(&blocked_address), sizeof(blocked_address)) == 0, "blocked connect");
        for (int attempt = 0; attempt != 100 && runtime.Stats().active == 0; ++attempt) Sleep(5);
        Require(runtime.Stats().active != 0, "blocked client accepted");
        const auto shutdown_started = std::chrono::steady_clock::now();
        runtime.Stop(); Require(!runtime.Running(), "WPC stop");
        const auto shutdown_time = std::chrono::steady_clock::now() - shutdown_started;
        closesocket(blocked);
        Require(shutdown_time < std::chrono::seconds(2), "WPC stop blocked by idle client");
        WSACleanup();
        std::cout << "PASS: WPC HTTP node/notice feeds, auth health, snapshot update and stop lifecycle\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL: " << error.what() << "\n"; return 1; }
}
