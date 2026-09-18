#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include "http_proxy_runtime.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string_view>
#include <vector>

namespace wpe::shell {
namespace {
constexpr std::uintptr_t invalid_socket = std::numeric_limits<std::uintptr_t>::max();

SOCKET AsSocket(std::uintptr_t value) noexcept { return static_cast<SOCKET>(value); }
std::uintptr_t AsHandle(SOCKET value) noexcept { return static_cast<std::uintptr_t>(value); }

bool SendAll(SOCKET socket, const std::uint8_t* data, std::size_t size) {
    while (size != 0) {
        const auto chunk = static_cast<int>(std::min<std::size_t>(size, 64 * 1024));
        const auto sent = send(socket, reinterpret_cast<const char*>(data), chunk, 0);
        if (sent <= 0) return false;
        data += sent;
        size -= static_cast<std::size_t>(sent);
    }
    return true;
}

bool ReceiveChunk(SOCKET socket, char* data, std::size_t capacity, std::size_t& received) {
    const auto count = recv(socket, data, static_cast<int>(capacity), 0);
    if (count <= 0) return false;
    received = static_cast<std::size_t>(count);
    return true;
}

bool ConnectWithTimeout(SOCKET socket, const sockaddr* address, int length) {
    u_long non_blocking = 1;
    if (ioctlsocket(socket, FIONBIO, &non_blocking) != 0) return false;
    const auto result = connect(socket, address, length);
    const auto connect_error = result == 0 ? 0 : WSAGetLastError();
    if (result != 0 && connect_error != WSAEWOULDBLOCK && connect_error != WSAEINPROGRESS) {
        non_blocking = 0;
        ioctlsocket(socket, FIONBIO, &non_blocking);
        return false;
    }
    if (result != 0) {
        fd_set writable{}, excepted{};
        FD_SET(socket, &writable);
        FD_SET(socket, &excepted);
        timeval timeout{5, 0};
        if (select(0, nullptr, &writable, &excepted, &timeout) <= 0 || FD_ISSET(socket, &excepted)) {
            non_blocking = 0;
            ioctlsocket(socket, FIONBIO, &non_blocking);
            return false;
        }
        int status = 0;
        int status_size = sizeof(status);
        if (getsockopt(socket, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&status), &status_size) != 0 || status != 0) {
            non_blocking = 0;
            ioctlsocket(socket, FIONBIO, &non_blocking);
            return false;
        }
    }
    non_blocking = 0;
    return ioctlsocket(socket, FIONBIO, &non_blocking) == 0;
}

std::string Lower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

std::string Trim(std::string value) {
    const auto is_space = [](unsigned char character) { return std::isspace(character) != 0; };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), [&](char character) { return !is_space(character); }));
    value.erase(std::find_if(value.rbegin(), value.rend(), [&](char character) { return !is_space(character); }).base(), value.end());
    return value;
}

bool ParsePort(std::string_view text, std::uint16_t& port) {
    if (text.empty()) return false;
    unsigned value = 0;
    for (const auto character : text) {
        if (character < '0' || character > '9') return false;
        value = value * 10U + static_cast<unsigned>(character - '0');
        if (value > 65535U) return false;
    }
    if (value == 0) return false;
    port = static_cast<std::uint16_t>(value);
    return true;
}

bool SplitAuthority(std::string value, std::uint16_t default_port, std::string& host, std::uint16_t& port) {
    value = Trim(std::move(value));
    if (value.empty()) return false;
    if (value.front() == '[') {
        const auto close = value.find(']');
        if (close == std::string::npos) return false;
        host = value.substr(1, close - 1);
        if (close + 1 == value.size()) port = default_port;
        else if (value[close + 1] == ':' && ParsePort(std::string_view(value).substr(close + 2), port)) {}
        else return false;
        return !host.empty() && port != 0;
    }
    const auto colon = value.rfind(':');
    if (colon == std::string::npos) {
        host = std::move(value);
        port = default_port;
    } else {
        // An unbracketed value with more than one colon is an IPv6 literal;
        // it is valid only when the caller supplied it without a port.
        if (value.find(':') != colon) {
            host = std::move(value);
            port = default_port;
        } else {
            host = value.substr(0, colon);
            if (!ParsePort(std::string_view(value).substr(colon + 1), port)) return false;
        }
    }
    return !host.empty() && port != 0;
}

bool DecodeBase64(std::string_view encoded, std::string& decoded) {
    static constexpr std::array<int, 256> table = [] {
        std::array<int, 256> result{};
        result.fill(-1);
        for (int i = 0; i < 26; ++i) result[static_cast<unsigned>('A' + i)] = i;
        for (int i = 0; i < 26; ++i) result[static_cast<unsigned>('a' + i)] = 26 + i;
        for (int i = 0; i < 10; ++i) result[static_cast<unsigned>('0' + i)] = 52 + i;
        result[static_cast<unsigned>('+')] = 62;
        result[static_cast<unsigned>('/')] = 63;
        return result;
    }();
    int bits = 0;
    unsigned accumulator = 0;
    decoded.clear();
    for (const auto character : encoded) {
        if (character == '=') break;
        const auto value = table[static_cast<unsigned char>(character)];
        if (value < 0) return false;
        accumulator = (accumulator << 6U) | static_cast<unsigned>(value);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            decoded.push_back(static_cast<char>((accumulator >> bits) & 0xffU));
        }
    }
    return !decoded.empty();
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

void SendError(SOCKET socket, int code, std::string_view reason) {
    const auto body = std::string(reason);
    const auto response = "HTTP/1.1 " + std::to_string(code) + " " + std::string(reason) + "\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
    SendAll(socket, reinterpret_cast<const std::uint8_t*>(response.data()), response.size());
}

bool IsHttpProtocol(std::string value) {
    return Lower(Trim(std::move(value))) == "http";
}

bool PathMatches(std::string_view path, std::string rule) {
    rule = Trim(std::move(rule));
    if (!rule.empty() && rule.front() != '/') rule.insert(rule.begin(), '/');
    if (rule.empty() || rule == "/") return true;
    if (path == rule) return true;
    if (path.size() <= rule.size() || path.substr(0, rule.size()) != rule) return false;
    const auto next = path[rule.size()];
    return next == '/' || next == '?';
}

std::string JoinMappedPath(std::string_view request, std::string from, std::string to) {
    from = Trim(std::move(from));
    to = Trim(std::move(to));
    if (!from.empty() && from.front() != '/') from.insert(from.begin(), '/');
    if (!to.empty() && to.front() != '/') to.insert(to.begin(), '/');
    if (from.empty() || from == "/") {
        if (to.empty()) return std::string(request);
        if (request.empty()) return to;
        if (to.back() == '/' && request.front() == '/') return to + std::string(request.substr(1));
        if (to.back() != '/' && request.front() != '/') return to + "/" + std::string(request);
        return to + std::string(request);
    }
    auto suffix = request.substr(std::min(from.size(), request.size()));
    if (suffix.empty()) return to.empty() ? "/" : to;
    if (to.empty()) return suffix.front() == '/' ? std::string(suffix) : "/" + std::string(suffix);
    if (to.back() == '/' && suffix.front() == '/') return to + std::string(suffix.substr(1));
    if (to.back() != '/' && suffix.front() != '/' && suffix.front() != '?') return to + "/" + std::string(suffix);
    return to + std::string(suffix);
}

bool MapEndpointMatches(const std::string& host, std::uint16_t port, const std::string& rule_host,
                        std::uint16_t rule_port, std::string_view path, const std::string& rule_path) {
    return Lower(host) == Lower(Trim(rule_host)) && port == rule_port && PathMatches(path, rule_path);
}
} // namespace

HttpProxyRuntime::~HttpProxyRuntime() { Stop(); }

bool HttpProxyRuntime::Start(HttpProxyConfig config, std::string& error) {
    std::lock_guard lock(lifecycle_);
    if (running_) {
        error = "HTTP 代理已经在运行";
        return false;
    }
    if (config.require_auth && config.credentials.empty()) {
        error = "代理认证已启用，但没有可用账号";
        return false;
    }
    if (config.bind_address.empty()) config.bind_address = "0.0.0.0";
    if (config.max_connections == 0) config.max_connections = 1;
    if (config.max_connections > static_cast<std::size_t>(SOMAXCONN)) config.max_connections = SOMAXCONN;

    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        error = "WSAStartup failed";
        return false;
    }
    winsock_started_ = true;
    sockaddr_storage address{};
    int address_length = 0;
    SOCKET socket = INVALID_SOCKET;
    IN_ADDR ipv4{};
    IN6_ADDR ipv6{};
    if (InetPtonA(AF_INET, config.bind_address.c_str(), &ipv4) == 1) {
        auto* value = reinterpret_cast<sockaddr_in*>(&address);
        value->sin_family = AF_INET;
        value->sin_addr = ipv4;
        value->sin_port = htons(config.port);
        address_length = sizeof(*value);
        socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    } else if (InetPtonA(AF_INET6, config.bind_address.c_str(), &ipv6) == 1) {
        auto* value = reinterpret_cast<sockaddr_in6*>(&address);
        value->sin6_family = AF_INET6;
        value->sin6_addr = ipv6;
        value->sin6_port = htons(config.port);
        address_length = sizeof(*value);
        socket = ::socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (socket != INVALID_SOCKET) {
            BOOL only_v6 = TRUE;
            setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&only_v6), sizeof(only_v6));
        }
    } else {
        error = "HTTP 代理监听地址不是有效的 IPv4/IPv6 地址";
        WSACleanup();
        winsock_started_ = false;
        return false;
    }
    if (socket == INVALID_SOCKET) {
        error = "HTTP 代理 socket 创建失败";
        WSACleanup();
        winsock_started_ = false;
        return false;
    }
    BOOL reuse = TRUE;
    setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
    if (bind(socket, reinterpret_cast<const sockaddr*>(&address), address_length) != 0 ||
        listen(socket, static_cast<int>(std::min<std::size_t>(config.max_connections, SOMAXCONN))) != 0) {
        error = "HTTP 代理监听 socket 启动失败 (WSA " + std::to_string(WSAGetLastError()) + ")";
        Close(AsHandle(socket));
        WSACleanup();
        winsock_started_ = false;
        return false;
    }
    int address_size = sizeof(address);
    if (getsockname(socket, reinterpret_cast<sockaddr*>(&address), &address_size) != 0) {
        error = "HTTP 代理无法读取监听端口";
        Close(AsHandle(socket));
        WSACleanup();
        winsock_started_ = false;
        return false;
    }
    const auto family = reinterpret_cast<const sockaddr*>(&address)->sa_family;
    const auto actual_port = family == AF_INET
        ? ntohs(reinterpret_cast<const sockaddr_in*>(&address)->sin_port)
        : ntohs(reinterpret_cast<const sockaddr_in6*>(&address)->sin6_port);
    config_ = std::move(config);
    port_ = actual_port;
    accepted_ = completed_ = active_ = requests_ = responses_ = bytes_up_ = bytes_down_ = errors_ = 0;
    map_hits_ = map_misses_ = map_errors_ = 0;
    stopping_ = false;
    listener_.store(AsHandle(socket), std::memory_order_release);
    running_ = true;
    try {
        accept_thread_ = std::thread(&HttpProxyRuntime::AcceptLoop, this);
    } catch (...) {
        running_ = false;
        stopping_ = true;
        listener_.store(invalid_socket, std::memory_order_release);
        Close(AsHandle(socket));
        WSACleanup();
        winsock_started_ = false;
        port_ = 0;
        error = "无法创建 HTTP 代理监听线程";
        return false;
    }
    return true;
}

void HttpProxyRuntime::Stop() {
    std::lock_guard lock(lifecycle_);
    stopping_ = true;
    const auto listener = listener_.exchange(invalid_socket, std::memory_order_acq_rel);
    if (listener != invalid_socket) {
        shutdown(AsSocket(listener), SD_BOTH);
        Close(listener);
    }
    if (accept_thread_.joinable()) accept_thread_.join();
    for (auto& client : clients_) if (client.joinable()) client.join();
    clients_.clear();
    running_ = false;
    port_ = 0;
    if (winsock_started_) {
        WSACleanup();
        winsock_started_ = false;
    }
}

Socks5Stats HttpProxyRuntime::Stats() const noexcept {
    return {running_.load(std::memory_order_acquire), port_.load(std::memory_order_acquire),
            accepted_.load(std::memory_order_relaxed), completed_.load(std::memory_order_relaxed),
            active_.load(std::memory_order_relaxed), requests_.load(std::memory_order_relaxed),
            responses_.load(std::memory_order_relaxed), bytes_up_.load(std::memory_order_relaxed),
            bytes_down_.load(std::memory_order_relaxed), errors_.load(std::memory_order_relaxed),
            map_hits_.load(std::memory_order_relaxed), map_misses_.load(std::memory_order_relaxed),
            map_errors_.load(std::memory_order_relaxed)};
}

bool HttpProxyRuntime::Running() const noexcept { return running_.load(std::memory_order_acquire); }

void HttpProxyRuntime::AcceptLoop() {
    while (!stopping_.load(std::memory_order_acquire)) {
        const auto listener = listener_.load(std::memory_order_acquire);
        if (listener == invalid_socket) break;
        fd_set read{};
        FD_SET(AsSocket(listener), &read);
        timeval timeout{0, 100000};
        const auto selected = select(0, &read, nullptr, nullptr, &timeout);
        if (selected == SOCKET_ERROR) {
            if (!stopping_.load(std::memory_order_acquire)) errors_.fetch_add(1, std::memory_order_relaxed);
            break;
        }
        if (selected == 0 || !FD_ISSET(AsSocket(listener), &read)) continue;
        const auto client = accept(AsSocket(listener), nullptr, nullptr);
        if (client == INVALID_SOCKET) {
            if (!stopping_.load(std::memory_order_acquire)) errors_.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        accepted_.fetch_add(1, std::memory_order_relaxed);
        if (active_.load(std::memory_order_relaxed) >= config_.max_connections) {
            errors_.fetch_add(1, std::memory_order_relaxed);
            Close(AsHandle(client));
            continue;
        }
        active_.fetch_add(1, std::memory_order_relaxed);
        try {
            clients_.emplace_back(&HttpProxyRuntime::Client, this, AsHandle(client));
        } catch (...) {
            active_.fetch_sub(1, std::memory_order_relaxed);
            errors_.fetch_add(1, std::memory_order_relaxed);
            Close(AsHandle(client));
        }
    }
}

bool HttpProxyRuntime::ConnectTarget(const std::string& host, std::uint16_t port, std::uintptr_t& remote) {
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* addresses = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &addresses) != 0) return false;
    SOCKET connected = INVALID_SOCKET;
    for (auto* item = addresses; item; item = item->ai_next) {
        connected = ::socket(item->ai_family, item->ai_socktype, item->ai_protocol);
        if (connected == INVALID_SOCKET) continue;
        if (ConnectWithTimeout(connected, item->ai_addr, static_cast<int>(item->ai_addrlen))) break;
        Close(AsHandle(connected));
        connected = INVALID_SOCKET;
    }
    freeaddrinfo(addresses);
    if (connected == INVALID_SOCKET) return false;
    remote = AsHandle(connected);
    return true;
}

bool HttpProxyRuntime::HandleRequest(std::uintptr_t client, std::uintptr_t& remote) {
    const SOCKET socket = AsSocket(client);
    std::string input;
    std::size_t header_end = std::string::npos;
    while (input.size() <= 64 * 1024) {
        std::array<char, 4096> chunk{};
        std::size_t count = 0;
        if (!ReceiveChunk(socket, chunk.data(), chunk.size(), count)) return false;
        input.append(chunk.data(), count);
        header_end = input.find("\r\n\r\n");
        if (header_end != std::string::npos) break;
    }
    if (header_end == std::string::npos) {
        SendError(socket, 431, "Request Header Fields Too Large");
        return false;
    }
    const auto header_text = input.substr(0, header_end);
    const auto pending = input.substr(header_end + 4);
    std::istringstream lines(header_text);
    std::string request_line;
    if (!std::getline(lines, request_line)) return false;
    if (!request_line.empty() && request_line.back() == '\r') request_line.pop_back();
    std::istringstream request_parts(request_line);
    std::string method, target, version;
    if (!(request_parts >> method >> target >> version) || version.rfind("HTTP/", 0) != 0) {
        SendError(socket, 400, "Bad Request");
        return false;
    }
    std::vector<std::string> headers;
    for (std::string line; std::getline(lines, line);) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) headers.push_back(std::move(line));
    }
    if (config_.require_auth) {
        const auto authorization = HeaderValue(headers, "Proxy-Authorization");
        const auto scheme_end = authorization.find(' ');
        std::string decoded;
        bool valid = scheme_end != std::string::npos && Lower(authorization.substr(0, scheme_end)) == "basic" &&
                     DecodeBase64(Trim(authorization.substr(scheme_end + 1)), decoded);
        if (valid) {
            const auto separator = decoded.find(':');
            valid = separator != std::string::npos && std::any_of(config_.credentials.begin(), config_.credentials.end(), [&](const Socks5Credential& credential) {
                return credential.user == decoded.substr(0, separator) && credential.password == decoded.substr(separator + 1);
            });
        }
        if (!valid) {
            const std::string response="HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"WPE64\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            SendAll(socket, reinterpret_cast<const std::uint8_t*>(response.data()), response.size());
            return false;
        }
    }

    const auto is_connect = Lower(method) == "connect";
    std::string host, path, forwarded_target;
    std::uint16_t port = 0;
    if (is_connect) {
        if (!SplitAuthority(target, 443, host, port)) {
            SendError(socket, 400, "Bad CONNECT Target");
            return false;
        }
    } else {
        const auto lower_target = Lower(target);
        if (lower_target.rfind("http://", 0) == 0) {
            const auto authority_start = target.find("://") + 3;
            const auto slash = target.find('/', authority_start);
            const auto query = target.find('?', authority_start);
            const auto path_start = slash == std::string::npos ? query
                : query == std::string::npos ? slash : std::min(slash, query);
            const auto authority = target.substr(authority_start, path_start == std::string::npos ? std::string::npos : path_start - authority_start);
            if (!SplitAuthority(authority, 80, host, port)) {
                SendError(socket, 400, "Bad HTTP Target");
                return false;
            }
            path = path_start == std::string::npos ? "/" : (target[path_start] == '?' ? "/" + target.substr(path_start) : target.substr(path_start));
        } else if (!target.empty() && target.front() == '/') {
            if (!SplitAuthority(HeaderValue(headers, "Host"), 80, host, port)) {
                SendError(socket, 400, "Host Required");
                return false;
            }
            path = target;
        } else {
            SendError(socket, 501, "HTTPS Requires CONNECT");
            return false;
        }
        forwarded_target = path;
    }

    bool mapped_remote = false;
    // Mapping is intentionally applied only to ordinary HTTP requests.  A
    // CONNECT tunnel carries encrypted HTTPS bytes, so its host/path cannot be
    // inspected without terminating TLS and is forwarded unchanged.
    if (!is_connect && (config_.enable_local_map || config_.enable_remote_map)) {
        const HttpProxyConfig::LocalMapRule* local_match = nullptr;
        if (config_.enable_local_map) {
            for (const auto& rule : config_.local_maps) {
                if (rule.enabled && MapEndpointMatches(host, port, rule.host, rule.port, path, rule.remote_path)) {
                    local_match = &rule;
                    break;
                }
            }
        }
        if (local_match) {
            map_hits_.fetch_add(1, std::memory_order_relaxed);
            if (!IsHttpProtocol(local_match->protocol)) {
                map_errors_.fetch_add(1, std::memory_order_relaxed);
                SendError(socket, 501, "Unsupported Mapping Protocol");
                return false;
            }
            std::ifstream file(local_match->local_path, std::ios::binary | std::ios::ate);
            constexpr std::streamoff maximum_file_size = 64ll * 1024ll * 1024ll;
            const auto end = file ? file.tellg() : std::streampos(-1);
            if (!file || end < 0 || end > maximum_file_size) {
                map_errors_.fetch_add(1, std::memory_order_relaxed);
                SendError(socket, end > maximum_file_size ? 413 : 404,
                          end > maximum_file_size ? "Mapped File Too Large" : "Mapped File Not Found");
                return false;
            }
            std::vector<std::uint8_t> body(static_cast<std::size_t>(end));
            file.seekg(0, std::ios::beg);
            if (!body.empty() && !file.read(reinterpret_cast<char*>(body.data()), static_cast<std::streamsize>(body.size()))) {
                map_errors_.fetch_add(1, std::memory_order_relaxed);
                SendError(socket, 500, "Mapped File Read Failed");
                return false;
            }
            const auto response = std::string("HTTP/1.1 200 OK\r\nContent-Length: ") + std::to_string(body.size()) +
                "\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n";
            if (!SendAll(socket, reinterpret_cast<const std::uint8_t*>(response.data()), response.size()) ||
                (!body.empty() && !SendAll(socket, body.data(), body.size()))) {
                map_errors_.fetch_add(1, std::memory_order_relaxed);
                return false;
            }
            requests_.fetch_add(1, std::memory_order_relaxed);
            responses_.fetch_add(1, std::memory_order_relaxed);
            bytes_up_.fetch_add(pending.size(), std::memory_order_relaxed);
            bytes_down_.fetch_add(response.size() + body.size(), std::memory_order_relaxed);
            return true;
        }

        const HttpProxyConfig::RemoteMapRule* remote_match = nullptr;
        if (config_.enable_remote_map) {
            for (const auto& rule : config_.remote_maps) {
                if (rule.enabled && MapEndpointMatches(host, port, rule.host_from, rule.port_from, path, rule.path_from)) {
                    remote_match = &rule;
                    break;
                }
            }
        }
        if (remote_match) {
            map_hits_.fetch_add(1, std::memory_order_relaxed);
            if (!IsHttpProtocol(remote_match->protocol_from) || !IsHttpProtocol(remote_match->protocol_to) ||
                remote_match->host_to.empty() || remote_match->port_to == 0) {
                map_errors_.fetch_add(1, std::memory_order_relaxed);
                SendError(socket, 501, "Unsupported Mapping Protocol");
                return false;
            }
            host = remote_match->host_to;
            port = remote_match->port_to;
            path = JoinMappedPath(path, remote_match->path_from, remote_match->path_to);
            forwarded_target = path;
            mapped_remote = true;
        } else {
            map_misses_.fetch_add(1, std::memory_order_relaxed);
        }
    }
    if (!ConnectTarget(host, port, remote)) {
        if (mapped_remote) map_errors_.fetch_add(1, std::memory_order_relaxed);
        SendError(socket, 502, "Bad Gateway");
        return false;
    }
    if (is_connect) {
        const std::string established="HTTP/1.1 200 Connection Established\r\nProxy-Agent: WPE64\r\n\r\n";
        if (!SendAll(socket, reinterpret_cast<const std::uint8_t*>(established.data()), established.size())) return false;
        requests_.fetch_add(1, std::memory_order_relaxed);
        if (!pending.empty()) {
            if (!SendAll(AsSocket(remote), reinterpret_cast<const std::uint8_t*>(pending.data()), pending.size())) return false;
            bytes_up_.fetch_add(pending.size(), std::memory_order_relaxed);
        }
        Relay(client, remote);
        return true;
    }

    std::string mapped_host_header;
    if (mapped_remote) {
        mapped_host_header = host;
        if (mapped_host_header.find(':') != std::string::npos && mapped_host_header.front() != '[')
            mapped_host_header = "[" + mapped_host_header + "]";
        if (port != 80) mapped_host_header += ":" + std::to_string(port);
    }
    std::string forwarded=method+" "+forwarded_target+" "+version+"\r\n";
    bool host_header_written = false;
    for (const auto& line : headers) {
        const auto colon = line.find(':');
        const auto key = colon == std::string::npos ? std::string{} : Lower(Trim(line.substr(0, colon)));
        if (key == "proxy-connection" || key == "proxy-authorization" || key == "connection") continue;
        if (mapped_remote && key == "host") {
            forwarded += "Host: " + mapped_host_header + "\r\n";
            host_header_written = true;
            continue;
        }
        forwarded += line + "\r\n";
    }
    if (mapped_remote && !host_header_written) forwarded += "Host: " + mapped_host_header + "\r\n";
    forwarded += "Connection: close\r\n\r\n";
    if (!SendAll(AsSocket(remote), reinterpret_cast<const std::uint8_t*>(forwarded.data()), forwarded.size())) return false;
    requests_.fetch_add(1, std::memory_order_relaxed);
    if (!pending.empty()) {
        if (!SendAll(AsSocket(remote), reinterpret_cast<const std::uint8_t*>(pending.data()), pending.size())) return false;
        bytes_up_.fetch_add(pending.size(), std::memory_order_relaxed);
    }
    Relay(client, remote);
    return true;
}

void HttpProxyRuntime::Relay(std::uintptr_t client, std::uintptr_t remote) {
    const SOCKET left = AsSocket(client), right = AsSocket(remote);
    std::array<std::uint8_t, 64 * 1024> buffer{};
    while (!stopping_.load(std::memory_order_acquire)) {
        fd_set read{};
        FD_SET(left, &read);
        FD_SET(right, &read);
        timeval timeout{0, 100000};
        const auto selected = select(0, &read, nullptr, nullptr, &timeout);
        if (selected <= 0) {
            if (selected == SOCKET_ERROR) errors_.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        if (FD_ISSET(left, &read)) {
            const auto count = recv(left, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0);
            if (count <= 0 || !SendAll(right, buffer.data(), static_cast<std::size_t>(count))) break;
            bytes_up_.fetch_add(static_cast<std::uint64_t>(count), std::memory_order_relaxed);
        }
        if (FD_ISSET(right, &read)) {
            const auto count = recv(right, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0);
            if (count <= 0 || !SendAll(left, buffer.data(), static_cast<std::size_t>(count))) break;
            bytes_down_.fetch_add(static_cast<std::uint64_t>(count), std::memory_order_relaxed);
            responses_.fetch_add(1, std::memory_order_relaxed);
        }
    }
}

void HttpProxyRuntime::Client(std::uintptr_t client) {
    const SOCKET socket = AsSocket(client);
    DWORD timeout = 1000;
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    bool success = false;
    std::uintptr_t remote = invalid_socket;
    try { success = HandleRequest(client, remote); } catch (...) {}
    if (remote != invalid_socket) {
        shutdown(AsSocket(remote), SD_BOTH);
        Close(remote);
    }
    shutdown(socket, SD_BOTH);
    Close(client);
    if (!success) errors_.fetch_add(1, std::memory_order_relaxed);
    active_.fetch_sub(1, std::memory_order_relaxed);
    completed_.fetch_add(1, std::memory_order_relaxed);
}

void HttpProxyRuntime::Close(std::uintptr_t socket) noexcept {
    if (socket != invalid_socket) closesocket(AsSocket(socket));
}

} // namespace wpe::shell
