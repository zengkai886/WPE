#pragma once

#include "ipc_codec.h"
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <cstdint>
#include <string>
#include <string_view>

namespace wpe {

enum class PipeChannel : std::uint8_t { Control, Packet, Event };

// A blocking byte-mode named-pipe endpoint. The server side is created by the
// shell and the client side is opened by the injected process. Framing remains
// in IpcFrame so the transport does not depend on message-mode pipe semantics.
class PipeEndpoint {
public:
    PipeEndpoint() noexcept = default;
    ~PipeEndpoint();
    PipeEndpoint(const PipeEndpoint&) = delete;
    PipeEndpoint& operator=(const PipeEndpoint&) = delete;
    PipeEndpoint(PipeEndpoint&& other) noexcept;
    PipeEndpoint& operator=(PipeEndpoint&& other) noexcept;

    static PipeEndpoint CreateServer(std::string_view session, PipeChannel channel);
    static PipeEndpoint ConnectClient(std::string_view session, PipeChannel channel,
                                      std::uint32_t timeout_ms);

    void Accept(std::uint32_t timeout_ms = INFINITE);
    Bytes ReadFrame();
    void WriteFrame(std::span<const std::uint8_t> payload);
    void Flush();
    // Cancels outstanding overlapped operations without destroying the handle;
    // the owner can then join its I/O threads before calling Close.
    void CancelPending() noexcept;
    void Close() noexcept;

    [[nodiscard]] HANDLE NativeHandle() const noexcept { return handle_; }
    [[nodiscard]] PipeChannel Channel() const noexcept { return channel_; }
    [[nodiscard]] bool IsServer() const noexcept { return server_; }
    [[nodiscard]] bool IsOpen() const noexcept { return handle_ != INVALID_HANDLE_VALUE; }

    static std::wstring FullName(std::string_view session, PipeChannel channel);

private:
    PipeEndpoint(HANDLE handle, PipeChannel channel, bool server) noexcept;
    [[nodiscard]] std::int32_t FrameLimit() const noexcept;

    HANDLE handle_{INVALID_HANDLE_VALUE};
    PipeChannel channel_{PipeChannel::Control};
    bool server_{false};
    bool accepted_{false};
};

} // namespace wpe
