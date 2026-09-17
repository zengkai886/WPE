#include "common/ipc_pipe.h"
#include "common/ipc_protocol.h"
#include <Aclapi.h>
#include <Windows.h>
#include <array>
#include <atomic>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>

namespace {
std::size_t checks = 0;
void Check(bool value, const char* message) {
    ++checks;
    if (!value) throw std::runtime_error(message);
}
template<class F> void Throws(F&& operation, const char* message) {
    bool threw = false;
    try { operation(); } catch (const wpe::ProtocolError&) { threw = true; }
    Check(threw, message);
}

std::vector<std::uint8_t> CurrentUserSid() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) throw std::runtime_error("OpenProcessToken");
    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);
    std::vector<std::uint8_t> buffer(size);
    if (!GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) {
        CloseHandle(token); throw std::runtime_error("GetTokenInformation");
    }
    const auto* user = reinterpret_cast<const TOKEN_USER*>(buffer.data());
    std::vector<std::uint8_t> sid(GetLengthSid(user->User.Sid));
    if (!CopySid(static_cast<DWORD>(sid.size()), sid.data(), user->User.Sid)) {
        CloseHandle(token); throw std::runtime_error("CopySid");
    }
    CloseHandle(token);
    return sid;
}

void CheckAcl(HANDLE pipe) {
    PACL dacl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const DWORD error = GetSecurityInfo(pipe, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
                                        nullptr, nullptr, &dacl, nullptr, &descriptor);
    if (error != ERROR_SUCCESS) throw std::runtime_error("GetSecurityInfo");
    struct LocalCloser { PSECURITY_DESCRIPTOR value; ~LocalCloser() { if (value) LocalFree(value); } } closer{descriptor};
    Check(dacl != nullptr, "pipe has an explicit DACL");
    ACL_SIZE_INFORMATION info{};
    Check(GetAclInformation(dacl, &info, sizeof(info), AclSizeInformation) != FALSE, "read DACL info");
    Check(info.AceCount == 1, "DACL contains only the current-user ACE");
    void* raw_ace = nullptr;
    Check(GetAce(dacl, 0, &raw_ace) != FALSE, "read current-user ACE");
    const auto* ace = static_cast<const ACCESS_ALLOWED_ACE*>(raw_ace);
    Check(ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE, "ACE allows access");
    Check((ace->Mask & FILE_ALL_ACCESS) == FILE_ALL_ACCESS, "ACE grants full control");
    const auto sid = CurrentUserSid();
    Check(EqualSid(const_cast<std::uint8_t*>(sid.data()),
                   const_cast<DWORD*>(&ace->SidStart)) != FALSE, "ACE belongs to current user");
}

void ExerciseControl(const std::string& session) {
    auto server = wpe::PipeEndpoint::CreateServer(session, wpe::PipeChannel::Control);
    CheckAcl(server.NativeHandle());
    std::exception_ptr server_error;
    std::thread worker([&] {
        try {
            server.Accept();
            const auto request = server.ReadFrame();
            Check(request.has_value(), "control request exists");
            wpe::IpcReader reader(*request);
            Check(reader.U8() == static_cast<std::uint8_t>(wpe::IpcCommand::Hello), "Hello command");
            Check(reader.I32() == wpe::IpcProtocol::Version, "Hello protocol version");
            Check(reader.Remaining() == 0, "Hello consumed");
            wpe::IpcWriter reply;
            reply.U8(static_cast<std::uint8_t>(wpe::IpcStatus::Ok));
            reply.I32(wpe::IpcProtocol::Version);
            reply.I32(static_cast<std::int32_t>(GetCurrentProcessId()));
            reply.Bool(sizeof(void*) == 8);
            server.WriteFrame(reply.ToArray());
            server.Flush();
        } catch (...) { server_error = std::current_exception(); }
    });
    auto client = wpe::PipeEndpoint::ConnectClient(session, wpe::PipeChannel::Control, 2000);
    wpe::IpcWriter hello;
    hello.U8(static_cast<std::uint8_t>(wpe::IpcCommand::Hello));
    hello.I32(wpe::IpcProtocol::Version);
    client.WriteFrame(hello.ToArray());
    const auto response = client.ReadFrame();
    Check(response.has_value(), "control response exists");
    wpe::IpcReader reply(*response);
    Check(reply.U8() == static_cast<std::uint8_t>(wpe::IpcStatus::Ok), "Hello status");
    Check(reply.I32() == wpe::IpcProtocol::Version, "reply protocol version");
    Check(reply.I32() == static_cast<std::int32_t>(GetCurrentProcessId()), "reply PID");
    Check(reply.Bool() == (sizeof(void*) == 8), "reply architecture");
    Check(reply.Remaining() == 0, "Hello reply consumed");
    client.Close();
    worker.join();
    if (server_error) std::rethrow_exception(server_error);
}

void ExerciseOutbound(const std::string& session, wpe::PipeChannel channel, std::size_t size) {
    auto server = wpe::PipeEndpoint::CreateServer(session, channel);
    std::vector<std::uint8_t> expected(size);
    for (std::size_t i = 0; i < expected.size(); ++i) expected[i] = static_cast<std::uint8_t>((i * 131U) & 0xffU);
    std::exception_ptr server_error;
    std::thread worker([&] {
        try {
            server.Accept();
            Check(server.ReadFrame() == wpe::Bytes(expected), "one-way channel payload");
            Check(!server.ReadFrame().has_value(), "one-way channel reports EOF");
        } catch (...) { server_error = std::current_exception(); }
    });
    auto client = wpe::PipeEndpoint::ConnectClient(session, channel, 2000);
    client.WriteFrame(expected);
    client.Flush();
    client.Close();
    worker.join();
    if (server_error) std::rethrow_exception(server_error);
}
} // namespace

int main() {
    try {
        const std::string session = "0123456789abcdef0123456789abcdef";
        Check(wpe::PipeEndpoint::FullName(session, wpe::PipeChannel::Control) ==
              L"\\\\.\\pipe\\WPE64-0123456789abcdef0123456789abcdef-ctl", "original N-format control pipe name");
        Check(wpe::PipeEndpoint::FullName("01234567-89ab-cdef-0123-456789abcdef",
              wpe::PipeChannel::Control) ==
              L"\\\\.\\pipe\\WPE64-01234567-89ab-cdef-0123-456789abcdef-ctl", "D-format control pipe name");
        Throws([&] { (void)wpe::PipeEndpoint::FullName("..\\escape", wpe::PipeChannel::Control); },
               "invalid session rejected");
        ExerciseControl(session);
        ExerciseOutbound(session, wpe::PipeChannel::Packet, 1024 * 1024 + 37);
        ExerciseOutbound(session, wpe::PipeChannel::Event, 8193);

        auto limit_server = wpe::PipeEndpoint::CreateServer("11234567-89ab-cdef-0123-456789abcdef",
                                                            wpe::PipeChannel::Control);
        Throws([&] { limit_server.WriteFrame(std::vector<std::uint8_t>(
            static_cast<std::size_t>(wpe::IpcProtocol::MaxControlFrame) + 1)); },
            "control frame limit enforced before I/O");
        limit_server.Close();
        auto accept_server = wpe::PipeEndpoint::CreateServer("3123456789abcdef0123456789abcdef",
                                                             wpe::PipeChannel::Control);
        Throws([&] { accept_server.Accept(25); }, "server accept timeout cancels overlapped operation");
        accept_server.Close();
        auto cancel_server = wpe::PipeEndpoint::CreateServer("4123456789abcdef0123456789abcdef",
                                                             wpe::PipeChannel::Control);
        std::atomic<bool> reading{false};
        std::exception_ptr cancel_error;
        std::thread cancelled_reader([&] {
            try {
                cancel_server.Accept();
                reading.store(true);
                Check(!cancel_server.ReadFrame().has_value(), "cancelled read becomes EOF");
            } catch (...) { cancel_error = std::current_exception(); reading.store(true); }
        });
        auto cancel_client = wpe::PipeEndpoint::ConnectClient("4123456789abcdef0123456789abcdef",
                                                              wpe::PipeChannel::Control, 2000);
        while (!reading.load()) Sleep(1);
        cancel_server.CancelPending();
        cancelled_reader.join();
        if (cancel_error) std::rethrow_exception(cancel_error);
        cancel_client.Close();
        cancel_server.Close();
        Throws([&] { (void)wpe::PipeEndpoint::ConnectClient(
            "21234567-89ab-cdef-0123-456789abcdef", wpe::PipeChannel::Control, 25); },
            "missing server times out");

        std::cout << "PASS: " << checks
                  << " real named-pipe transport checks; current-user ACL, ctl handshake, pkt/evt streams, EOF and limits\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
