#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <WinSock2.h>
#include <Windows.h>
#include <array>
#include <cstring>

namespace {
bool NetworkRoundTrip() {
    WSADATA data{};
    if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return false;
    SOCKET listener = INVALID_SOCKET;
    SOCKET client = INVALID_SOCKET;
    SOCKET server = INVALID_SOCKET;
    bool success = false;
    do {
        listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (listener == INVALID_SOCKET) break;
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (bind(listener, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0 ||
            listen(listener, 1) != 0) break;
        int length = sizeof(address);
        if (getsockname(listener, reinterpret_cast<sockaddr*>(&address), &length) != 0) break;
        client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (client == INVALID_SOCKET ||
            connect(client, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) break;
        server = accept(listener, nullptr, nullptr);
        if (server == INVALID_SOCKET) break;
        constexpr char payload[] = "cross-process";
        if (send(client, payload, static_cast<int>(sizeof(payload) - 1), 0) !=
            static_cast<int>(sizeof(payload) - 1)) break;
        std::array<char, 32> received{};
        const int count = recv(server, received.data(), static_cast<int>(received.size()), 0);
        constexpr char filtered[] = "Cross-process";
        success = count == static_cast<int>(sizeof(filtered) - 1) &&
                  std::memcmp(received.data(), filtered, sizeof(filtered) - 1) == 0;
        // The production design deliberately resolves socket endpoints on the
        // writer thread, not in the target's send/recv call. Keep this fixture's
        // sockets alive long enough for that asynchronous lookup to complete.
        Sleep(200);
    } while (false);
    if (server != INVALID_SOCKET) closesocket(server);
    if (client != INVALID_SOCKET) closesocket(client);
    if (listener != INVALID_SOCKET) closesocket(listener);
    WSACleanup();
    return success;
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc != 3) return ERROR_INVALID_PARAMETER;
    const HANDLE start = OpenEventW(SYNCHRONIZE, FALSE, argv[1]);
    const HANDLE done = OpenEventW(EVENT_MODIFY_STATE, FALSE, argv[2]);
    if (!start || !done) {
        if (start) CloseHandle(start);
        if (done) CloseHandle(done);
        return static_cast<int>(GetLastError());
    }
    const DWORD wait = WaitForSingleObject(start, 20000);
    const bool success = wait == WAIT_OBJECT_0 && NetworkRoundTrip();
    (void)SetEvent(done);
    CloseHandle(done);
    CloseHandle(start);
    if (!success) return ERROR_GEN_FAILURE;
    Sleep(30000);
    return 0;
}
