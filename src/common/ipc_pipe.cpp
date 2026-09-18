#include "ipc_pipe.h"
#include "ipc_frame.h"
#include "ipc_protocol.h"
#include <Aclapi.h>
#include <algorithm>
#include <limits>
#include <sstream>
#include <utility>
#include <vector>

namespace wpe {
namespace {
class Win32ProtocolError final : public ProtocolError {
public:
    Win32ProtocolError(std::string message, DWORD code) : ProtocolError(std::move(message)), code_(code) {}
    [[nodiscard]] DWORD Code() const noexcept { return code_; }
private:
    DWORD code_;
};

[[noreturn]] void Fail(const char* operation, DWORD error = GetLastError()) {
    std::ostringstream message;
    message << operation << " failed with Win32 error " << error;
    throw Win32ProtocolError(message.str(), error);
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
    // The original ShellLink uses Guid.ToString("N") (32 hex digits). Accept the
    // dashed "D" form as well for diagnostics, while rejecting namespace escapes.
    if (session.size() == 36) { (void)Guid::Parse(session); return; }
    if (session.size() != 32) throw ProtocolError("Pipe session requires a GUID");
    for (const unsigned char c : session) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            throw ProtocolError("Pipe session requires hexadecimal GUID digits");
    }
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
           FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED;
}

DWORD ClientAccess(PipeChannel channel) {
    return channel == PipeChannel::Control ? GENERIC_READ | GENERIC_WRITE : GENERIC_WRITE;
}

class OverlappedOperation final {
public:
    OverlappedOperation() {
        event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!event_) Fail("CreateEventW(overlapped)");
        value_.hEvent = event_;
    }
    ~OverlappedOperation() { if (event_) CloseHandle(event_); }
    OVERLAPPED* Value() noexcept { return &value_; }
    DWORD Complete(HANDLE handle, DWORD timeout, const char* operation) {
        const DWORD wait = WaitForSingleObject(event_, timeout);
        if (wait == WAIT_TIMEOUT) {
            if (!CancelIoEx(handle, &value_) && GetLastError() != ERROR_NOT_FOUND)
                Fail("CancelIoEx");
            WaitForSingleObject(event_, INFINITE);
            DWORD ignored = 0;
            (void)GetOverlappedResult(handle, &value_, &ignored, FALSE);
            Fail(operation, ERROR_SEM_TIMEOUT);
        }
        if (wait != WAIT_OBJECT_0) Fail("WaitForSingleObject(overlapped)");
        DWORD transferred = 0;
        if (!GetOverlappedResult(handle, &value_, &transferred, FALSE)) Fail(operation);
        return transferred;
    }
private:
    HANDLE event_{nullptr};
    OVERLAPPED value_{};
};

DWORD ReadOverlapped(HANDLE handle, void* buffer, DWORD size, DWORD timeout) {
    OverlappedOperation operation;
    DWORD transferred = 0;
    if (ReadFile(handle, buffer, size, &transferred, operation.Value())) return transferred;
    const DWORD error = GetLastError();
    if (error != ERROR_IO_PENDING) Fail("ReadFile(pipe)", error);
    return operation.Complete(handle, timeout, "ReadFile(pipe)");
}

DWORD WriteOverlapped(HANDLE handle, const void* buffer, DWORD size, DWORD timeout) {
    OverlappedOperation operation;
    DWORD transferred = 0;
    if (WriteFile(handle, buffer, size, &transferred, operation.Value())) return transferred;
    const DWORD error = GetLastError();
    if (error != ERROR_IO_PENDING) Fail("WriteFile(pipe)", error);
    return operation.Complete(handle, timeout, "WriteFile(pipe)");
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
                                          OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, nullptr);
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

void PipeEndpoint::Accept(std::uint32_t timeout_ms) {
    if (!IsOpen() || !server_ || accepted_) throw ProtocolError("Pipe server is not ready to accept");
    OverlappedOperation operation;
    if (ConnectNamedPipe(handle_, operation.Value())) {
        accepted_ = true;
        return;
    }
    const DWORD error = GetLastError();
    if (error == ERROR_PIPE_CONNECTED) {
        accepted_ = true;
        return;
    }
    if (error != ERROR_IO_PENDING) Fail("ConnectNamedPipe", error);
    (void)operation.Complete(handle_, timeout_ms, "ConnectNamedPipe");
    accepted_ = true;
}

std::int32_t PipeEndpoint::FrameLimit() const noexcept {
    return channel_ == PipeChannel::Packet ? IpcProtocol::MaxPacketFrame : IpcProtocol::MaxControlFrame;
}

Bytes PipeEndpoint::ReadFrame(std::uint32_t timeout_ms) {
    if (!IsOpen()) throw ProtocolError("Pipe is closed");
    return IpcFrame::Read([this, timeout_ms](std::span<std::uint8_t> output) -> std::size_t {
        const DWORD requested = static_cast<DWORD>(std::min<std::size_t>(output.size(),
            static_cast<std::size_t>(std::numeric_limits<DWORD>::max())));
        try { return ReadOverlapped(handle_, output.data(), requested, timeout_ms); }
        catch (const Win32ProtocolError& error) {
            if (error.Code() == ERROR_BROKEN_PIPE || error.Code() == ERROR_PIPE_NOT_CONNECTED ||
                error.Code() == ERROR_OPERATION_ABORTED || error.Code() == ERROR_INVALID_HANDLE) return 0;
            throw;
        }
    }, FrameLimit());
}

void PipeEndpoint::WriteFrame(std::span<const std::uint8_t> payload, std::uint32_t timeout_ms) {
    if (!IsOpen()) throw ProtocolError("Pipe is closed");
    if (payload.size() > static_cast<std::size_t>(FrameLimit()))
        throw ProtocolError("Frame exceeds channel limit");
    IpcFrame::Write([this, timeout_ms](std::span<const std::uint8_t> frame) -> std::size_t {
        if (frame.size() > static_cast<std::size_t>(std::numeric_limits<DWORD>::max()))
            throw ProtocolError("Pipe write exceeds DWORD length");
        return WriteOverlapped(handle_, frame.data(), static_cast<DWORD>(frame.size()), timeout_ms);
    }, payload);
}

void PipeEndpoint::Flush() {
    if (!IsOpen()) throw ProtocolError("Pipe is closed");
    if (!FlushFileBuffers(handle_)) Fail("FlushFileBuffers(pipe)");
}

void PipeEndpoint::CancelPending() noexcept {
    if (IsOpen()) (void)CancelIoEx(handle_, nullptr);
}

void PipeEndpoint::Close() noexcept {
    if (!IsOpen()) return;
    CancelPending();
    if (server_ && accepted_) DisconnectNamedPipe(handle_);
    CloseHandle(handle_);
    handle_ = INVALID_HANDLE_VALUE;
    accepted_ = false;
}

} // namespace wpe
