#include "ipc_pipe.h"
#include "ipc_frame.h"
#include "ipc_protocol.h"
#include <Aclapi.h>
#include <algorithm>
#include <limits>
#include <sstream>
#include <vector>

namespace wpe {
namespace {
[[noreturn]] void Fail(const char* operation, DWORD error = GetLastError()) {
    std::ostringstream message;
    message << operation << " failed with Win32 error " << error;
    throw ProtocolError(message.str());
}

std::wstring WidenAscii(std::string_view text) {
    std::wstring result;
    result.reserve(text.size());
    for (const unsigned char c : text) {
        if (c > 0x7f) throw ProtocolError("Pipe session must be ASCII");
        result.push_back(static_cast<wchar_t>(c));
    }
    return result;
}

void ValidateSession(std::string_view session) {
    // Session IDs are generated before injection and are always canonical GUIDs.
    // Requiring that shape also prevents callers from escaping the pipe namespace.
    (void)Guid::Parse(session);
}

class CurrentUserSecurity final {
public:
    CurrentUserSecurity() {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) Fail("OpenProcessToken");
        struct TokenCloser { HANDLE value; ~TokenCloser() { if (value) CloseHandle(value); } } closer{token};

        DWORD needed = 0;
        if (GetTokenInformation(token, TokenUser, nullptr, 0, &needed) || GetLastError() != ERROR_INSUFFICIENT_BUFFER)
            Fail("GetTokenInformation(size)");
        token_user_.resize(needed);
        if (!GetTokenInformation(token, TokenUser, token_user_.data(), needed, &needed))
            Fail("GetTokenInformation(user)");
        const auto* user = reinterpret_cast<const TOKEN_USER*>(token_user_.data());
        if (!IsValidSid(user->User.Sid)) throw ProtocolError("Current token has an invalid user SID");

        const DWORD acl_size = static_cast<DWORD>(sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD) +
                                                   GetLengthSid(user->User.Sid));
        acl_.resize(acl_size);
        auto* acl = reinterpret_cast<PACL>(acl_.data());
        if (!InitializeAcl(acl, acl_size, ACL_REVISION)) Fail("InitializeAcl");
        if (!AddAccessAllowedAceEx(acl, ACL_REVISION, 0, FILE_ALL_ACCESS, user->User.Sid))
            Fail("AddAccessAllowedAceEx");
        if (!InitializeSecurityDescriptor(&descriptor_, SECURITY_DESCRIPTOR_REVISION))
            Fail("InitializeSecurityDescriptor");
        if (!SetSecurityDescriptorDacl(&descriptor_, TRUE, acl, FALSE))
            Fail("SetSecurityDescriptorDacl");
        attributes_.nLength = sizeof(attributes_);
        attributes_.lpSecurityDescriptor = &descriptor_;
        attributes_.bInheritHandle = FALSE;
    }

    SECURITY_ATTRIBUTES* Attributes() noexcept { return &attributes_; }

private:
    std::vector<std::uint8_t> token_user_;
    std::vector<std::uint8_t> acl_;
    SECURITY_DESCRIPTOR descriptor_{};
    SECURITY_ATTRIBUTES attributes_{};
};

DWORD ServerAccess(PipeChannel channel) {
    return (channel == PipeChannel::Control ? PIPE_ACCESS_DUPLEX : PIPE_ACCESS_INBOUND) |
           FILE_FLAG_FIRST_PIPE_INSTANCE;
}

DWORD ClientAccess(PipeChannel channel) {
    return channel == PipeChannel::Control ? GENERIC_READ | GENERIC_WRITE : GENERIC_WRITE;
}
} // namespace

PipeEndpoint::PipeEndpoint(HANDLE handle, PipeChannel channel, bool server) noexcept
    : handle_(handle), channel_(channel), server_(server) {}

PipeEndpoint::~PipeEndpoint() { Close(); }

PipeEndpoint::PipeEndpoint(PipeEndpoint&& other) noexcept
    : handle_(other.handle_), channel_(other.channel_), server_(other.server_), accepted_(other.accepted_) {
    other.handle_ = INVALID_HANDLE_VALUE;
    other.accepted_ = false;
}

PipeEndpoint& PipeEndpoint::operator=(PipeEndpoint&& other) noexcept {
    if (this != &other) {
        Close();
        handle_ = other.handle_;
        channel_ = other.channel_;
        server_ = other.server_;
        accepted_ = other.accepted_;
        other.handle_ = INVALID_HANDLE_VALUE;
        other.accepted_ = false;
    }
    return *this;
}

std::wstring PipeEndpoint::FullName(std::string_view session, PipeChannel channel) {
    ValidateSession(session);
    const auto short_name = channel == PipeChannel::Control ? IpcProtocol::ControlPipe(session) :
                            channel == PipeChannel::Packet ? IpcProtocol::PacketPipe(session) :
                                                             IpcProtocol::EventPipe(session);
    return L"\\\\.\\pipe\\" + WidenAscii(short_name);
}

PipeEndpoint PipeEndpoint::CreateServer(std::string_view session, PipeChannel channel) {
    const auto name = FullName(session, channel);
    CurrentUserSecurity security;
    const DWORD buffer_size = static_cast<DWORD>(channel == PipeChannel::Packet ?
        IpcProtocol::MaxPacketFrame + 4 : IpcProtocol::MaxControlFrame + 4);
    const HANDLE handle = CreateNamedPipeW(name.c_str(), ServerAccess(channel),
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
        1, buffer_size, buffer_size, 0, security.Attributes());
    if (handle == INVALID_HANDLE_VALUE) Fail("CreateNamedPipeW");
    return PipeEndpoint(handle, channel, true);
}

PipeEndpoint PipeEndpoint::ConnectClient(std::string_view session, PipeChannel channel,
                                         std::uint32_t timeout_ms) {
    const auto name = FullName(session, channel);
    const auto deadline = GetTickCount64() + timeout_ms;
    for (;;) {
        const HANDLE handle = CreateFileW(name.c_str(), ClientAccess(channel), 0, nullptr,
                                          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (handle != INVALID_HANDLE_VALUE) return PipeEndpoint(handle, channel, false);
        const DWORD error = GetLastError();
        if (error != ERROR_PIPE_BUSY && error != ERROR_FILE_NOT_FOUND) Fail("CreateFileW(pipe)", error);
        const auto now = GetTickCount64();
        if (now >= deadline) Fail("WaitNamedPipeW", ERROR_SEM_TIMEOUT);
        const auto remaining = deadline - now;
        const DWORD wait = static_cast<DWORD>(std::min<ULONGLONG>(remaining, 50));
        if (!WaitNamedPipeW(name.c_str(), wait)) {
            const DWORD wait_error = GetLastError();
            if (wait_error != ERROR_SEM_TIMEOUT && wait_error != ERROR_FILE_NOT_FOUND)
                Fail("WaitNamedPipeW", wait_error);
        }
    }
}

void PipeEndpoint::Accept() {
    if (!IsOpen() || !server_ || accepted_) throw ProtocolError("Pipe server is not ready to accept");
    if (!ConnectNamedPipe(handle_, nullptr) && GetLastError() != ERROR_PIPE_CONNECTED)
        Fail("ConnectNamedPipe");
    accepted_ = true;
}

std::int32_t PipeEndpoint::FrameLimit() const noexcept {
    return channel_ == PipeChannel::Packet ? IpcProtocol::MaxPacketFrame : IpcProtocol::MaxControlFrame;
}

Bytes PipeEndpoint::ReadFrame() {
    if (!IsOpen()) throw ProtocolError("Pipe is closed");
    return IpcFrame::Read([this](std::span<std::uint8_t> output) -> std::size_t {
        const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(output.size(),
            static_cast<std::size_t>(std::numeric_limits<DWORD>::max())));
        DWORD read = 0;
        if (ReadFile(handle_, output.data(), requested, &read, nullptr)) return read;
        const DWORD error = GetLastError();
        if (error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED) return 0;
        Fail("ReadFile(pipe)", error);
    }, FrameLimit());
}

void PipeEndpoint::WriteFrame(std::span<const std::uint8_t> payload) {
    if (!IsOpen()) throw ProtocolError("Pipe is closed");
    if (payload.size() > static_cast<std::size_t>(FrameLimit()))
        throw ProtocolError("Frame exceeds channel limit");
    IpcFrame::Write([this](std::span<const std::uint8_t> frame) -> std::size_t {
        if (frame.size() > static_cast<std::size_t>(std::numeric_limits<DWORD>::max()))
            throw ProtocolError("Pipe write exceeds DWORD length");
        DWORD written = 0;
        if (!WriteFile(handle_, frame.data(), static_cast<DWORD>(frame.size()), &written, nullptr))
            Fail("WriteFile(pipe)");
        return written;
    }, payload);
}

void PipeEndpoint::Flush() {
    if (!IsOpen()) throw ProtocolError("Pipe is closed");
    if (!FlushFileBuffers(handle_)) Fail("FlushFileBuffers(pipe)");
}

void PipeEndpoint::Close() noexcept {
    if (!IsOpen()) return;
    if (server_ && accepted_) DisconnectNamedPipe(handle_);
    CloseHandle(handle_);
    handle_ = INVALID_HANDLE_VALUE;
    accepted_ = false;
}

} // namespace wpe
