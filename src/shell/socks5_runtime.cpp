#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <winsock2.h>
#include <ws2tcpip.h>

#include "socks5_runtime.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>

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

bool ReceiveAll(SOCKET socket, std::uint8_t* data, std::size_t size) {
    while (size != 0) {
        const auto chunk = static_cast<int>(std::min<std::size_t>(size, 64 * 1024));
        const auto received = recv(socket, reinterpret_cast<char*>(data), chunk, 0);
        if (received <= 0) return false;
        data += received;
        size -= static_cast<std::size_t>(received);
    }
    return true;
}

bool ReceiveByte(SOCKET socket, std::uint8_t& value) {
    return ReceiveAll(socket, &value, sizeof(value));
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

std::string ErrorText(const char* operation, int code = WSAGetLastError()) {
    return std::string(operation) + " failed (WSA " + std::to_string(code) + ")";
}

int SockaddrLength(const sockaddr_storage& address) noexcept {
    return address.ss_family == AF_INET6 ? sizeof(sockaddr_in6) : sizeof(sockaddr_in);
}

std::uint16_t SockaddrPort(const sockaddr_storage& address) noexcept {
    return address.ss_family == AF_INET6
        ? ntohs(reinterpret_cast<const sockaddr_in6*>(&address)->sin6_port)
        : ntohs(reinterpret_cast<const sockaddr_in*>(&address)->sin_port);
}

void SetSockaddrPort(sockaddr_storage& address, std::uint16_t port) noexcept {
    if (address.ss_family == AF_INET6) reinterpret_cast<sockaddr_in6*>(&address)->sin6_port = htons(port);
    else reinterpret_cast<sockaddr_in*>(&address)->sin_port = htons(port);
}

bool EncodeSocksAddress(const sockaddr_storage& address, std::vector<std::uint8_t>& output) {
    output.clear();
    if (address.ss_family == AF_INET) {
        const auto* value = reinterpret_cast<const sockaddr_in*>(&address);
        output.push_back(1);
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(&value->sin_addr);
        output.insert(output.end(), bytes, bytes + sizeof(value->sin_addr));
    } else if (address.ss_family == AF_INET6) {
        const auto* value = reinterpret_cast<const sockaddr_in6*>(&address);
        output.push_back(4);
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(&value->sin6_addr);
        output.insert(output.end(), bytes, bytes + sizeof(value->sin6_addr));
    } else return false;
    const auto port = SockaddrPort(address);
    output.push_back(static_cast<std::uint8_t>(port >> 8));
    output.push_back(static_cast<std::uint8_t>(port & 0xff));
    return true;
}

} // namespace

Socks5Runtime::~Socks5Runtime() { Stop(); }

bool Socks5Runtime::Start(Socks5Config config, std::string& error) {
    std::lock_guard lock(lifecycle_);
    if (running_) {
        error = "SOCKS5 已经在运行";
        return false;
    }
    if (config.bind_address.empty()) config.bind_address = "0.0.0.0";
    if (config.max_connections == 0) config.max_connections = 1;
    if (config.max_connections > static_cast<std::size_t>(SOMAXCONN))
        config.max_connections = static_cast<std::size_t>(SOMAXCONN);
    if (config.require_auth && config.credentials.empty()) {
        error = "代理认证已启用，但没有可用账号";
        return false;
    }

    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) {
        error = ErrorText("WSAStartup");
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
            BOOL v6_only = TRUE;
            setsockopt(socket, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<const char*>(&v6_only), sizeof(v6_only));
        }
    } else {
        error = "代理监听地址不是有效的 IPv4/IPv6 地址";
        WSACleanup();
        winsock_started_ = false;
        return false;
    }
    if (socket == INVALID_SOCKET) {
        error = ErrorText("socket");
        WSACleanup();
        winsock_started_ = false;
        return false;
    }
    BOOL reuse = TRUE;
    setsockopt(socket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
    if (bind(socket, reinterpret_cast<const sockaddr*>(&address), address_length) != 0) {
        error = ErrorText("bind");
        Close(AsHandle(socket));
        WSACleanup();
        winsock_started_ = false;
        return false;
    }
    if (listen(socket, static_cast<int>(std::min<std::size_t>(config.max_connections, SOMAXCONN))) != 0) {
        error = ErrorText("listen");
        Close(AsHandle(socket));
        WSACleanup();
        winsock_started_ = false;
        return false;
    }
    int address_size = sizeof(address);
    if (getsockname(socket, reinterpret_cast<sockaddr*>(&address), &address_size) != 0) {
        error = ErrorText("getsockname");
        Close(AsHandle(socket));
        WSACleanup();
        winsock_started_ = false;
        return false;
    }
    config_ = std::move(config);
    const auto family = reinterpret_cast<const sockaddr*>(&address)->sa_family;
    const auto actual_port = family == AF_INET
        ? ntohs(reinterpret_cast<const sockaddr_in*>(&address)->sin_port)
        : ntohs(reinterpret_cast<const sockaddr_in6*>(&address)->sin6_port);
    port_.store(actual_port, std::memory_order_release);
    accepted_ = 0;
    completed_ = 0;
    active_ = 0;
    requests_ = 0;
    responses_ = 0;
    bytes_up_ = 0;
    bytes_down_ = 0;
    errors_ = 0;
    udp_requests_ = 0;
    udp_responses_ = 0;
    udp_active_ = 0;
    stopping_ = false;
    listener_.store(AsHandle(socket), std::memory_order_release);
    running_ = true;
    try {
        accept_thread_ = std::thread(&Socks5Runtime::AcceptLoop, this);
    } catch (...) {
        running_ = false;
        stopping_ = true;
        listener_.store(invalid_socket, std::memory_order_release);
        Close(AsHandle(socket));
        WSACleanup();
        winsock_started_ = false;
        port_ = 0;
        error = "无法创建代理监听线程";
        return false;
    }
    return true;
}

void Socks5Runtime::Stop() {
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

Socks5Stats Socks5Runtime::Stats() const noexcept {
    return {running_.load(std::memory_order_acquire), port_.load(std::memory_order_acquire),
            accepted_.load(std::memory_order_relaxed), completed_.load(std::memory_order_relaxed),
            active_.load(std::memory_order_relaxed), requests_.load(std::memory_order_relaxed),
            responses_.load(std::memory_order_relaxed), bytes_up_.load(std::memory_order_relaxed),
            bytes_down_.load(std::memory_order_relaxed), errors_.load(std::memory_order_relaxed),
            0, 0, 0,
            udp_requests_.load(std::memory_order_relaxed), udp_responses_.load(std::memory_order_relaxed),
            udp_active_.load(std::memory_order_relaxed)};
}

bool Socks5Runtime::Running() const noexcept { return running_.load(std::memory_order_acquire); }

void Socks5Runtime::AcceptLoop() {
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
            clients_.emplace_back(&Socks5Runtime::Client, this, AsHandle(client));
        } catch (...) {
            active_.fetch_sub(1, std::memory_order_relaxed);
            errors_.fetch_add(1, std::memory_order_relaxed);
            Close(AsHandle(client));
        }
    }
}

bool Socks5Runtime::Authenticate(std::uintptr_t client) const {
    const SOCKET socket = AsSocket(client);
    std::uint8_t version{}, methods{};
    if (!ReceiveByte(socket, version) || !ReceiveByte(socket, methods) || version != 5 || methods == 0)
        return false;
    std::vector<std::uint8_t> offered(methods);
    if (!ReceiveAll(socket, offered.data(), offered.size())) return false;
    std::uint8_t selected = 0xff;
    if (config_.require_auth) {
        if (std::find(offered.begin(), offered.end(), static_cast<std::uint8_t>(2)) != offered.end()) selected = 2;
    } else if (std::find(offered.begin(), offered.end(), static_cast<std::uint8_t>(0)) != offered.end()) {
        selected = 0;
    }
    const std::array<std::uint8_t, 2> choice{5, selected};
    if (!SendAll(socket, choice.data(), choice.size()) || selected == 0xff) return false;
    if (selected != 2) return true;

    std::uint8_t auth_version{}, user_size{};
    if (!ReceiveByte(socket, auth_version) || !ReceiveByte(socket, user_size) || auth_version != 1 || user_size == 0)
        return false;
    std::string user(user_size, '\0');
    if (!ReceiveAll(socket, reinterpret_cast<std::uint8_t*>(user.data()), user.size())) return false;
    std::uint8_t password_size{};
    if (!ReceiveByte(socket, password_size)) return false;
    std::string password(password_size, '\0');
    if (password_size != 0 && !ReceiveAll(socket, reinterpret_cast<std::uint8_t*>(password.data()), password.size())) return false;
    const auto valid = std::any_of(config_.credentials.begin(), config_.credentials.end(), [&](const Socks5Credential& credential) {
        return credential.user == user && credential.password == password;
    });
    const std::array<std::uint8_t, 2> result{1, static_cast<std::uint8_t>(valid ? 0 : 1)};
    SendAll(socket, result.data(), result.size());
    return valid;
}

bool Socks5Runtime::ConnectRequest(std::uintptr_t client, std::uintptr_t& remote) {
    const SOCKET socket = AsSocket(client);
    std::array<std::uint8_t, 4> header{};
    if (!ReceiveAll(socket, header.data(), header.size()) || header[0] != 5 || header[2] != 0 ||
        (header[1] != 1 && header[1] != 3))
        return false;
    std::string host;
    if (header[3] == 1) {
        std::array<std::uint8_t, 4> address{};
        if (!ReceiveAll(socket, address.data(), address.size())) return false;
        char text[INET_ADDRSTRLEN]{};
        IN_ADDR value{};
        std::memcpy(&value, address.data(), address.size());
        if (!InetNtopA(AF_INET, &value, text, sizeof(text))) return false;
        host = text;
    } else if (header[3] == 3) {
        std::uint8_t length{};
        if (!ReceiveByte(socket, length) || length == 0) return false;
        host.assign(length, '\0');
        if (!ReceiveAll(socket, reinterpret_cast<std::uint8_t*>(host.data()), host.size())) return false;
    } else if (header[3] == 4) {
        std::array<std::uint8_t, 16> address{};
        if (!ReceiveAll(socket, address.data(), address.size())) return false;
        char text[INET6_ADDRSTRLEN]{};
        IN6_ADDR value{};
        std::memcpy(&value, address.data(), address.size());
        if (!InetNtopA(AF_INET6, &value, text, sizeof(text))) return false;
        host = text;
    } else return false;
    std::array<std::uint8_t, 2> port{};
    if (!ReceiveAll(socket, port.data(), port.size())) return false;
    const auto destination_port = static_cast<std::uint16_t>((static_cast<std::uint16_t>(port[0]) << 8) | port[1]);
    if (host.empty() || (header[1] == 1 && destination_port == 0)) return false;

    if (header[1] == 3) {
        sockaddr_storage local{};
        int local_length = sizeof(local);
        if (getsockname(socket, reinterpret_cast<sockaddr*>(&local), &local_length) != 0 ||
            (local.ss_family != AF_INET && local.ss_family != AF_INET6)) return false;
        SOCKET udp = ::socket(local.ss_family, SOCK_DGRAM, IPPROTO_UDP);
        if (udp == INVALID_SOCKET) return false;
        BOOL reuse = TRUE;
        setsockopt(udp, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));
        SetSockaddrPort(local, 0);
        if (bind(udp, reinterpret_cast<const sockaddr*>(&local), SockaddrLength(local)) != 0) {
            Close(AsHandle(udp));
            return false;
        }
        sockaddr_storage bound{};
        int bound_length = sizeof(bound);
        if (getsockname(udp, reinterpret_cast<sockaddr*>(&bound), &bound_length) != 0) {
            Close(AsHandle(udp));
            return false;
        }
        std::vector<std::uint8_t> encoded;
        if (!EncodeSocksAddress(bound, encoded)) {
            Close(AsHandle(udp));
            return false;
        }
        std::vector<std::uint8_t> reply{5, 0, 0};
        reply.insert(reply.end(), encoded.begin(), encoded.end());
        if (!SendAll(socket, reply.data(), reply.size())) {
            Close(AsHandle(udp));
            return false;
        }
        udp_active_.fetch_add(1, std::memory_order_relaxed);
        const auto result = RelayUdp(client, AsHandle(udp));
        udp_active_.fetch_sub(1, std::memory_order_relaxed);
        Close(AsHandle(udp));
        return result;
    }

    const auto service = std::to_string(destination_port);
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* addresses = nullptr;
    if (getaddrinfo(host.c_str(), service.c_str(), &hints, &addresses) != 0) return false;
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
    const std::array<std::uint8_t, 10> reply{5, 0, 0, 1, 0, 0, 0, 0, 0, 0};
    if (!SendAll(socket, reply.data(), reply.size())) {
        Close(remote);
        remote = invalid_socket;
        return false;
    }
    requests_.fetch_add(1, std::memory_order_relaxed);
    return true;
}

bool Socks5Runtime::RelayUdp(std::uintptr_t client, std::uintptr_t udp_socket) {
    const SOCKET control = AsSocket(client);
    const SOCKET relay = AsSocket(udp_socket);
    std::array<std::uint8_t, 64 * 1024> buffer{};
    sockaddr_storage client_address{};
    int client_address_length = 0;
    bool client_address_known = false;

    const auto same_client = [](const sockaddr_storage& left, const sockaddr_storage& right) {
        if (left.ss_family != right.ss_family) return false;
        if (left.ss_family == AF_INET) {
            return reinterpret_cast<const sockaddr_in*>(&left)->sin_addr.S_un.S_addr ==
                   reinterpret_cast<const sockaddr_in*>(&right)->sin_addr.S_un.S_addr;
        }
        if (left.ss_family == AF_INET6) {
            return std::memcmp(&reinterpret_cast<const sockaddr_in6*>(&left)->sin6_addr,
                               &reinterpret_cast<const sockaddr_in6*>(&right)->sin6_addr,
                               sizeof(IN6_ADDR)) == 0;
        }
        return false;
    };

    while (!stopping_.load(std::memory_order_acquire)) {
        fd_set read{};
        FD_SET(control, &read);
        FD_SET(relay, &read);
        timeval timeout{0, 100000};
        const auto selected = select(0, &read, nullptr, nullptr, &timeout);
        if (selected == SOCKET_ERROR) {
            if (!stopping_.load(std::memory_order_acquire)) errors_.fetch_add(1, std::memory_order_relaxed);
            return false;
        }
        if (selected == 0) continue;
        if (FD_ISSET(control, &read)) {
            std::uint8_t probe{};
            const auto count = recv(control, reinterpret_cast<char*>(&probe), 1, MSG_PEEK);
            if (count <= 0) return true;
            return false;
        }
        if (!FD_ISSET(relay, &read)) continue;

        sockaddr_storage source{};
        int source_length = sizeof(source);
        const auto count = recvfrom(relay, reinterpret_cast<char*>(buffer.data()), static_cast<int>(buffer.size()), 0,
                                    reinterpret_cast<sockaddr*>(&source), &source_length);
        if (count <= 0) {
            if (!stopping_.load(std::memory_order_acquire)) errors_.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        const auto size = static_cast<std::size_t>(count);
        const auto same_endpoint = [&](const sockaddr_storage& left, const sockaddr_storage& right) {
            return same_client(left, right) && SockaddrPort(left) == SockaddrPort(right);
        };
        if (!client_address_known) {
            client_address = source;
            client_address_length = source_length;
            client_address_known = true;
        } else if (!same_endpoint(client_address, source)) {
            std::vector<std::uint8_t> encoded;
            if (!EncodeSocksAddress(source, encoded) || encoded.size() + 3 + size > buffer.size()) {
                errors_.fetch_add(1, std::memory_order_relaxed);
                continue;
            }
            std::vector<std::uint8_t> packet{0, 0, 0};
            packet.insert(packet.end(), encoded.begin(), encoded.end());
            packet.insert(packet.end(), buffer.begin(), buffer.begin() + count);
            if (sendto(relay, reinterpret_cast<const char*>(packet.data()), static_cast<int>(packet.size()), 0,
                       reinterpret_cast<const sockaddr*>(&client_address), client_address_length) != static_cast<int>(packet.size())) {
                errors_.fetch_add(1, std::memory_order_relaxed);
                continue;
            }
            udp_responses_.fetch_add(1, std::memory_order_relaxed);
            bytes_down_.fetch_add(static_cast<std::size_t>(count), std::memory_order_relaxed);
            continue;
        }

        if (size < 4 || buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0) {
            errors_.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        std::size_t offset = 4;
        sockaddr_storage destination{};
        bool destination_ready = false;
        if (buffer[3] == 1) {
            if (size < offset + 4 + 2) { errors_.fetch_add(1, std::memory_order_relaxed); continue; }
            auto* value = reinterpret_cast<sockaddr_in*>(&destination);
            value->sin_family = AF_INET;
            std::memcpy(&value->sin_addr, buffer.data() + offset, 4);
            offset += 4;
            value->sin_port = htons(static_cast<std::uint16_t>((buffer[offset] << 8) | buffer[offset + 1]));
            offset += 2;
            destination_ready = value->sin_port != 0;
        } else if (buffer[3] == 4) {
            if (size < offset + 16 + 2) { errors_.fetch_add(1, std::memory_order_relaxed); continue; }
            auto* value = reinterpret_cast<sockaddr_in6*>(&destination);
            value->sin6_family = AF_INET6;
            std::memcpy(&value->sin6_addr, buffer.data() + offset, 16);
            offset += 16;
            value->sin6_port = htons(static_cast<std::uint16_t>((buffer[offset] << 8) | buffer[offset + 1]));
            offset += 2;
            destination_ready = value->sin6_port != 0;
        } else if (buffer[3] == 3) {
            if (size < offset + 1) { errors_.fetch_add(1, std::memory_order_relaxed); continue; }
            const auto length = static_cast<std::size_t>(buffer[offset++]);
            if (length == 0 || size < offset + length + 2) { errors_.fetch_add(1, std::memory_order_relaxed); continue; }
            std::string host(reinterpret_cast<const char*>(buffer.data() + offset), length);
            offset += length;
            const auto port = static_cast<std::uint16_t>((buffer[offset] << 8) | buffer[offset + 1]);
            offset += 2;
            addrinfo hints{};
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_protocol = IPPROTO_UDP;
            addrinfo* addresses = nullptr;
            if (port == 0 || getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &addresses) != 0) {
                errors_.fetch_add(1, std::memory_order_relaxed);
                continue;
            }
            for (auto* item = addresses; item; item = item->ai_next) {
                if (item->ai_addrlen <= sizeof(destination) &&
                    (item->ai_family == AF_INET || item->ai_family == AF_INET6)) {
                    std::memcpy(&destination, item->ai_addr, static_cast<std::size_t>(item->ai_addrlen));
                    destination_ready = true;
                    break;
                }
            }
            freeaddrinfo(addresses);
        } else {
            errors_.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        if (!destination_ready || offset > size) {
            errors_.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        const auto payload_size = size - offset;
        const auto sent = sendto(relay, reinterpret_cast<const char*>(buffer.data() + offset), static_cast<int>(payload_size), 0,
                                  reinterpret_cast<const sockaddr*>(&destination), SockaddrLength(destination));
        if (sent != static_cast<int>(payload_size)) {
            errors_.fetch_add(1, std::memory_order_relaxed);
            continue;
        }
        udp_requests_.fetch_add(1, std::memory_order_relaxed);
        bytes_up_.fetch_add(payload_size, std::memory_order_relaxed);
    }
    return true;
}

void Socks5Runtime::Relay(std::uintptr_t client, std::uintptr_t remote) {
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

void Socks5Runtime::Client(std::uintptr_t client) {
    const SOCKET socket = AsSocket(client);
    DWORD timeout = 1000;
    setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&timeout), sizeof(timeout));
    bool success = false;
    std::uintptr_t remote = invalid_socket;
    try {
        if (Authenticate(client) && !config_.only_wpc && ConnectRequest(client, remote)) {
            success = true;
            Relay(client, remote);
        }
    } catch (...) {
        // A malformed peer or an allocation failure must retire only this
        // session; the listener remains available for other clients.
    }
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

void Socks5Runtime::Close(std::uintptr_t socket) noexcept {
    if (socket != invalid_socket) closesocket(AsSocket(socket));
}

} // namespace wpe::shell
