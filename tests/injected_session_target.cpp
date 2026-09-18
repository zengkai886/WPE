#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <WinSock2.h>
#include <Windows.h>
#include <array>
#include <cstring>

namespace {
bool NetworkRoundTrip(HANDLE ready, HANDLE filter_send, HANDLE filter_send_done,
                      HANDLE replay, HANDLE replay_done, HANDLE send_list) {
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
        if (!success) break;
        if (!SetEvent(ready) || WaitForSingleObject(filter_send, 20000) != WAIT_OBJECT_0) {
            success = false;
            break;
        }
        // The second matching packet exercises Filter -> Send in the
        // production target: the original packet is delivered first, then
        // the configured send trigger must arrive on the same socket.
        if (send(client, payload, static_cast<int>(sizeof(payload) - 1), 0) !=
            static_cast<int>(sizeof(payload) - 1)) break;
        received.fill(0);
        const int filtered_again = recv(server, received.data(),
                                        static_cast<int>(received.size()), 0);
        success = filtered_again == static_cast<int>(sizeof(filtered) - 1) &&
                  std::memcmp(received.data(), filtered, sizeof(filtered) - 1) == 0;
        if (!success) break;
        constexpr char filter_replayed[] = "filter-send";
        received.fill(0);
        const int filter_replayed_count = recv(server, received.data(),
                                                static_cast<int>(received.size()), 0);
        success = filter_replayed_count == static_cast<int>(sizeof(filter_replayed) - 1) &&
                  std::memcmp(received.data(), filter_replayed, sizeof(filter_replayed) - 1) == 0;
        if (!success || !SetEvent(filter_send_done) ||
            WaitForSingleObject(replay, 20000) != WAIT_OBJECT_0) {
            success = false;
            break;
        }
        constexpr char replayed[] = "ipc-replay";
        received.fill(0);
        const int replayed_count = recv(server, received.data(),
                                        static_cast<int>(received.size()), 0);
        success = replayed_count == static_cast<int>(sizeof(replayed) - 1) &&
                  std::memcmp(received.data(), replayed, sizeof(replayed) - 1) == 0;
        if (!success || !SetEvent(replay_done) ||
            WaitForSingleObject(send_list, 20000) != WAIT_OBJECT_0) {
            success = false;
            break;
        }
        constexpr char listed[] = "list-replay";
        received.fill(0);
        const int listed_count = recv(server, received.data(),
                                      static_cast<int>(received.size()), 0);
        success = listed_count == static_cast<int>(sizeof(listed) - 1) &&
                  std::memcmp(received.data(), listed, sizeof(listed) - 1) == 0;
    } while (false);
    if (server != INVALID_SOCKET) closesocket(server);
    if (client != INVALID_SOCKET) closesocket(client);
    if (listener != INVALID_SOCKET) closesocket(listener);
    WSACleanup();
    return success;
}
} // namespace

int wmain(int argc, wchar_t** argv) {
    if (argc != 9) return ERROR_INVALID_PARAMETER;
    const HANDLE start = OpenEventW(SYNCHRONIZE, FALSE, argv[1]);
    const HANDLE ready = OpenEventW(EVENT_MODIFY_STATE, FALSE, argv[2]);
    const HANDLE filter_send = OpenEventW(SYNCHRONIZE, FALSE, argv[3]);
    const HANDLE filter_send_done = OpenEventW(EVENT_MODIFY_STATE, FALSE, argv[4]);
    const HANDLE replay = OpenEventW(SYNCHRONIZE, FALSE, argv[5]);
    const HANDLE replay_done = OpenEventW(EVENT_MODIFY_STATE, FALSE, argv[6]);
    const HANDLE send_list = OpenEventW(SYNCHRONIZE, FALSE, argv[7]);
    const HANDLE done = OpenEventW(EVENT_MODIFY_STATE, FALSE, argv[8]);
    if (!start || !ready || !filter_send || !filter_send_done || !replay ||
        !replay_done || !send_list || !done) {
        if (start) CloseHandle(start);
        if (ready) CloseHandle(ready);
        if (filter_send) CloseHandle(filter_send);
        if (filter_send_done) CloseHandle(filter_send_done);
        if (replay) CloseHandle(replay);
        if (replay_done) CloseHandle(replay_done);
        if (send_list) CloseHandle(send_list);
        if (done) CloseHandle(done);
        return static_cast<int>(GetLastError());
    }
    const DWORD wait = WaitForSingleObject(start, 20000);
    const bool success = wait == WAIT_OBJECT_0 &&
                         NetworkRoundTrip(ready, filter_send, filter_send_done,
                                          replay, replay_done, send_list);
    (void)SetEvent(done);
    CloseHandle(done);
    CloseHandle(send_list);
    CloseHandle(replay_done);
    CloseHandle(replay);
    CloseHandle(filter_send_done);
    CloseHandle(filter_send);
    CloseHandle(ready);
    CloseHandle(start);
    if (!success) return ERROR_GEN_FAILURE;
    Sleep(30000);
    return 0;
}
