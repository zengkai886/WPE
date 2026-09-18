#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include "wpc_runtime.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <limits>
#include <sstream>
#include <string_view>

namespace wpe::shell {
namespace {
constexpr std::uintptr_t invalid_socket = std::numeric_limits<std::uintptr_t>::max();
SOCKET AsSocket(std::uintptr_t value) noexcept { return static_cast<SOCKET>(value); }
std::uintptr_t AsHandle(SOCKET value) noexcept { return static_cast<std::uintptr_t>(value); }

bool SendAll(SOCKET socket, std::string_view text) {
    const auto* data = reinterpret_cast<const std::uint8_t*>(text.data());
    auto size = text.size();
    while (size != 0) {
        const auto chunk = static_cast<int>(std::min<std::size_t>(size, 64 * 1024));
        const auto sent = send(socket, reinterpret_cast<const char*>(data), chunk, 0);
        if (sent <= 0) return false;
        data += sent;
        size -= static_cast<std::size_t>(sent);
    }
    return true;
}

std::string Lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

std::string Trim(std::string value) {
    const auto space = [](unsigned char c) { return std::isspace(c) != 0; };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), [&](char c) { return !space(c); }));
    value.erase(std::find_if(value.rbegin(), value.rend(), [&](char c) { return !space(c); }).base(), value.end());
    return value;
}

bool DecodeBase64(std::string_view encoded, std::string& decoded) {
    static constexpr std::array<int, 256> table = [] {
        std::array<int, 256> value{};
        value.fill(-1);
        for (int i = 0; i < 26; ++i) value[static_cast<unsigned>('A' + i)] = i;
        for (int i = 0; i < 26; ++i) value[static_cast<unsigned>('a' + i)] = i + 26;
        for (int i = 0; i < 10; ++i) value[static_cast<unsigned>('0' + i)] = i + 52;
        value[static_cast<unsigned>('+')] = 62;
        value[static_cast<unsigned>('/')] = 63;
        return value;
    }();
    unsigned accumulator = 0;
    int bits = 0;
    decoded.clear();
    for (const auto c : encoded) {
        if (c == '=') break;
        const auto v = table[static_cast<unsigned char>(c)];
        if (v < 0) return false;
        accumulator = (accumulator << 6U) | static_cast<unsigned>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            decoded.push_back(static_cast<char>((accumulator >> bits) & 0xffU));
        }
    }
    return true;
}

std::string HeaderValue(const std::vector<std::string>& headers, std::string_view wanted) {
    const auto key = Lower(std::string(wanted));
    for (const auto& line : headers) {
        const auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        if (Lower(Trim(line.substr(0, colon))) == key) return Trim(line.substr(colon + 1));
    }
    return {};
}

void Response(SOCKET socket, int code, std::string_view reason, std::string body = {},
              std::string_view content_type = "text/plain; charset=utf-8",
              std::string_view extra = {}) {
    std::string response = "HTTP/1.1 " + std::to_string(code) + " " + std::string(reason) + "\r\n";
    response += "Content-Type: " + std::string(content_type) + "\r\nContent-Length: " +
                std::to_string(body.size()) + "\r\nConnection: close\r\n";
    response += extra;
    response += "\r\n" + body;
    (void)SendAll(socket, response);
}

bool BindAddress(const std::string& text, std::uint16_t port, sockaddr_storage& address,
                 int& length, SOCKET& socket, std::string& error) {
    IN_ADDR v4{};
    IN6_ADDR v6{};
    if (InetPtonA(AF_INET, text.c_str(), &v4) == 1) {
        auto* value = reinterpret_cast<sockaddr_in*>(&address);
        value->sin_family = AF_INET;
        value->sin_addr = v4;
        value->sin_port = htons(port);
        length = sizeof(*value);
        socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    } else if (InetPtonA(AF_INET6, text.c_str(), &v6) == 1) {
        auto* value = reinterpret_cast<sockaddr_in6*>(&address);
        value->sin6_family = AF_INET6;
        value->sin6_addr = v6;
        value->sin6_port = htons(port);
        length = sizeof(*value);
        socket = ::socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (socket != INVALID_SOCKET) {
            BOOL only_v6 = TRUE;
            setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY,
                       reinterpret_cast<const char*>(&only_v6), sizeof(only_v6));
        }
    } else {
        error = "WPC 监听地址不是有效的 IPv4/IPv6 地址";
        return false;
    }
    if (socket == INVALID_SOCKET) {
        error = "WPC socket 创建失败";
        return false;
    }
    BOOL reuse = TRUE;
    setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
    if (bind(socket, reinterpret_cast<const sockaddr*>(&address), length) != 0 ||
        listen(socket, SOMAXCONN) != 0) {
        error = "WPC 监听 socket 启动失败 (WSA " + std::to_string(WSAGetLastError()) + ")";
        return false;
    }
    return true;
}
} // namespace

WpcRuntime::~WpcRuntime() { Stop(); }

bool WpcRuntime::Start(WpcConfig config, std::string& error) {
    std::lock_guard lock(lifecycle_);
    if (running_) { error = "WPC 服务已经在运行"; return false; }
    if (config.bind_address.empty()) config.bind_address = "127.0.0.1";
    if (config.user.empty() || config.password.empty()) { error = "WPC 管理账号和密码不能为空"; return false; }
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) { error = "WPC WSAStartup failed"; return false; }
    winsock_started_ = true;
    sockaddr_storage address{};
    int address_length = 0;
    SOCKET socket = INVALID_SOCKET;
    if (!BindAddress(config.bind_address, config.port, address, address_length, socket, error)) {
        if (socket != INVALID_SOCKET) Close(AsHandle(socket));
        WSACleanup(); winsock_started_ = false; return false;
    }
    int actual_length = sizeof(address);
    if (getsockname(socket, reinterpret_cast<sockaddr*>(&address), &actual_length) != 0) {
        error = "WPC 无法读取监听端口"; Close(AsHandle(socket)); WSACleanup(); winsock_started_ = false; return false;
    }
    const auto actual_port = address.ss_family == AF_INET
        ? ntohs(reinterpret_cast<const sockaddr_in*>(&address)->sin_port)
        : ntohs(reinterpret_cast<const sockaddr_in6*>(&address)->sin6_port);
    {
        std::lock_guard data_lock(data_mutex_);
        config_ = std::move(config);
    }
    accepted_ = completed_ = active_ = requests_ = responses_ = server_requests_ = notice_requests_ = errors_ = 0;
    port_ = actual_port;
    stopping_ = false;
    listener_.store(AsHandle(socket), std::memory_order_release);
    running_ = true;
    try { accept_thread_ = std::thread(&WpcRuntime::AcceptLoop, this); }
    catch (...) {
        running_ = false; stopping_ = true; listener_.store(invalid_socket, std::memory_order_release);
        Close(AsHandle(socket)); WSACleanup(); winsock_started_ = false; port_ = 0;
        error = "无法创建 WPC 监听线程"; return false;
    }
    return true;
}

void WpcRuntime::Stop() {
    std::lock_guard lock(lifecycle_);
    stopping_ = true;
    const auto listener = listener_.exchange(invalid_socket, std::memory_order_acq_rel);
    if (listener != invalid_socket) { shutdown(AsSocket(listener), SD_BOTH); Close(listener); }
    {
        std::lock_guard clients_lock(clients_mutex_);
        for (const auto client : active_clients_) {
            shutdown(AsSocket(client), SD_BOTH);
        }
    }
    if (accept_thread_.joinable()) accept_thread_.join();
    for (auto& client : clients_) if (client.joinable()) client.join();
    clients_.clear();
    {
        std::lock_guard clients_lock(clients_mutex_);
        active_clients_.clear();
    }
    running_ = false; port_ = 0;
    if (winsock_started_) { WSACleanup(); winsock_started_ = false; }
}

void WpcRuntime::Update(Json servers, Json notices) {
    if (!servers.is_array()) servers = Json::array();
    if (!notices.is_array()) notices = Json::array();
    std::lock_guard lock(data_mutex_);
    config_.servers = std::move(servers);
    config_.notices = std::move(notices);
}

WpcStats WpcRuntime::Stats() const noexcept {
    return {running_.load(std::memory_order_acquire), port_.load(std::memory_order_acquire),
            accepted_.load(std::memory_order_relaxed), completed_.load(std::memory_order_relaxed),
            active_.load(std::memory_order_relaxed), requests_.load(std::memory_order_relaxed),
            responses_.load(std::memory_order_relaxed), server_requests_.load(std::memory_order_relaxed),
            notice_requests_.load(std::memory_order_relaxed), errors_.load(std::memory_order_relaxed)};
}

bool WpcRuntime::Running() const noexcept { return running_.load(std::memory_order_acquire); }

void WpcRuntime::AcceptLoop() {
    while (!stopping_.load(std::memory_order_acquire)) {
        const auto listener = listener_.load(std::memory_order_acquire);
        if (listener == invalid_socket) break;
        fd_set read{}; FD_SET(AsSocket(listener), &read);
        timeval timeout{0, 100000};
        const auto selected = select(0, &read, nullptr, nullptr, &timeout);
        if (selected == SOCKET_ERROR) { if (!stopping_) errors_++; break; }
        if (selected == 0 || !FD_ISSET(AsSocket(listener), &read)) continue;
        const auto client = accept(AsSocket(listener), nullptr, nullptr);
        if (client == INVALID_SOCKET) { if (!stopping_) errors_++; continue; }
        // Bound an idle request so shutdown cannot wait forever on a peer that
        // connected and then stopped sending bytes.  Stop() also shuts down
        // the socket; the timeout is the portability fallback for Winsock's
        // cross-thread shutdown behavior.
        constexpr DWORD receive_timeout_ms = 500;
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&receive_timeout_ms), sizeof(receive_timeout_ms));
        accepted_++; active_++;
        const auto handle = AsHandle(client);
        {
            std::lock_guard clients_lock(clients_mutex_);
            active_clients_.push_back(handle);
        }
        try { clients_.emplace_back(&WpcRuntime::Client, this, handle); }
        catch (...) {
            {
                std::lock_guard clients_lock(clients_mutex_);
                active_clients_.erase(std::remove(active_clients_.begin(), active_clients_.end(), handle), active_clients_.end());
            }
            active_--; errors_++; Close(handle);
        }
    }
}

void WpcRuntime::Client(std::uintptr_t value) {
    const auto socket = AsSocket(value);
    const auto unregister = [this, value] {
        std::lock_guard clients_lock(clients_mutex_);
        active_clients_.erase(std::remove(active_clients_.begin(), active_clients_.end(), value), active_clients_.end());
    };
    try {
        std::string input;
        while (input.size() <= 64 * 1024 && input.find("\r\n\r\n") == std::string::npos) {
            std::array<char, 4096> chunk{};
            const auto received = recv(socket, chunk.data(), static_cast<int>(chunk.size()), 0);
            if (received <= 0) { errors_++; Close(value); unregister(); active_--; completed_++; return; }
            input.append(chunk.data(), static_cast<std::size_t>(received));
        }
        const auto end = input.find("\r\n\r\n");
        if (end == std::string::npos) { Response(socket, 431, "Request Header Fields Too Large"); errors_++; goto done; }
        std::istringstream lines(input.substr(0, end));
        std::string line, method, target, version;
        if (!std::getline(lines, line)) { Response(socket, 400, "Bad Request"); errors_++; goto done; }
        if (!line.empty() && line.back() == '\r') line.pop_back();
        std::istringstream request(line);
        if (!(request >> method >> target >> version) || version.rfind("HTTP/", 0) != 0) {
            Response(socket, 400, "Bad Request"); errors_++; goto done;
        }
        std::vector<std::string> headers;
        while (std::getline(lines, line)) { if (!line.empty() && line.back() == '\r') line.pop_back(); if (!line.empty()) headers.push_back(line); }
        const auto path_end = target.find('?');
        const auto path = target.substr(0, path_end);
        if (Lower(method) != "get") { Response(socket, 405, "Method Not Allowed"); errors_++; goto done; }
        Json body;
        bool public_endpoint = false;
        if (path == "/ProxyCap/GetServerList") {
            std::lock_guard lock(data_mutex_);
            body = Json::array();
            for (const auto& row : config_.servers) {
                if (!row.is_object() || !row.value("IsEnable", true)) continue;
                Json item{{"IsEnable",true},{"ServerName",row.value("ServerName","")},{"ServerIP",row.value("ServerIP","")},
                          {"ServerPort",row.value("ServerPort",1080)},{"ForgotURL",row.value("ForgotURL","")},
                          {"RegisterURL",row.value("RegisterURL","")},{"VerifyURL",row.value("VerifyURL","")},{"Rules",Json::array()}};
                for (const auto& rule : row.value("_rules", Json::array())) {
                    if (!rule.is_object() || !rule.value("IsEnable", true)) continue;
                    item["Rules"].push_back({{"IsEnable",true},{"RType",rule.value("RuleType",0)},
                        {"RArgument",rule.value("RuleArgument","")},{"RAction",rule.value("RuleAction",0)}});
                }
                body.push_back(std::move(item));
            }
            server_requests_++; public_endpoint = true;
        } else if (path == "/ProxyCap/GetNoticeList") {
            std::lock_guard lock(data_mutex_);
            body = Json::array();
            for (const auto& row : config_.notices) {
                if (!row.is_object()) continue;
                body.push_back({{"NoticeType",row.value("NoticeType",1)},{"NoticeTitle",row.value("NoticeTitle","")},
                    {"NoticeContent",row.value("NoticeContent","")},{"NoticeMore",row.value("NoticeMore","")},
                    {"NoticeTime",row.value("NoticeTime","")}});
            }
            notice_requests_++; public_endpoint = true;
        } else if (path == "/healthz" || path == "/" || path == "/index.html") {
            const auto authorization = HeaderValue(headers, "Authorization");
            const auto separator = authorization.find(' ');
            std::string decoded;
            bool valid = separator != std::string::npos && Lower(authorization.substr(0, separator)) == "basic" &&
                         DecodeBase64(Trim(authorization.substr(separator + 1)), decoded);
            std::string user, pass;
            if (valid) { const auto colon = decoded.find(':'); valid = colon != std::string::npos; if (valid) { user=decoded.substr(0,colon); pass=decoded.substr(colon+1); } }
            { std::lock_guard lock(data_mutex_); valid = valid && user == config_.user && pass == config_.password; }
            if (!valid) { Response(socket, 401, "Unauthorized", {}, "text/plain; charset=utf-8", "WWW-Authenticate: Basic realm=\"WPE64 WPC\"\r\n"); errors_++; goto done; }
            const auto stats = Stats();
            body = {{"ok",true},{"running",stats.running},{"port",stats.port},{"active",stats.active},
                    {"requests",stats.requests},{"responses",stats.responses},{"serverRequests",stats.server_requests},
                    {"noticeRequests",stats.notice_requests}};
        } else { Response(socket, 404, "Not Found"); errors_++; goto done; }
        {
            const auto text = body.dump();
            Response(socket, 200, "OK", text, "application/json; charset=utf-8");
            requests_++; responses_++;
            if (public_endpoint) { /* counters above are per endpoint; common request counter is separate */ }
        }
    } catch (...) { errors_++; }
done:
    Close(value); active_--; completed_++;
    unregister();
}

void WpcRuntime::Close(std::uintptr_t value) noexcept {
    const auto socket = AsSocket(value);
    if (socket != INVALID_SOCKET) { shutdown(socket, SD_BOTH); closesocket(socket); }
}

} // namespace wpe::shell
