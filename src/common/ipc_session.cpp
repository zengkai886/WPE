#include "ipc_session.h"
#include <Windows.h>
#include <algorithm>
#include <stdexcept>
#include <utility>

namespace wpe {
namespace {
std::uint64_t Tick() noexcept { return GetTickCount64(); }

Text AsText(std::string_view value) {
    std::u16string text;
    text.reserve(value.size());
    for (const unsigned char c : value) text.push_back(static_cast<char16_t>(c));
    return text;
}

std::uint32_t Remaining(std::uint64_t deadline) {
    const auto now = Tick();
    if (now >= deadline) throw ProtocolError("Timed out waiting for IPC channels");
    return static_cast<std::uint32_t>(std::min<std::uint64_t>(deadline - now, INFINITE - 1ULL));
}
} // namespace

ByteBuffer IpcOk() {
    IpcWriter writer;
    writer.U8(static_cast<std::uint8_t>(IpcStatus::Ok));
    return writer.ToArray();
}

ByteBuffer IpcError(std::string_view message) {
    return IpcError(AsText(message));
}

ByteBuffer IpcError(const Text& message) {
    IpcWriter writer;
    writer.U8(static_cast<std::uint8_t>(IpcStatus::Error));
    writer.Str(message);
    return writer.ToArray();
}

ShellIpcSession::ShellIpcSession(std::string session, FrameHandler packet_handler,
                                 FrameHandler event_handler, StateHandler state_handler,
                                 ShellSessionOptions options)
    : session_(std::move(session)),
      control_(PipeEndpoint::CreateServer(session_, PipeChannel::Control)),
      packet_(PipeEndpoint::CreateServer(session_, PipeChannel::Packet)),
      event_(PipeEndpoint::CreateServer(session_, PipeChannel::Event)),
      packet_handler_(std::move(packet_handler)), event_handler_(std::move(event_handler)),
      state_handler_(std::move(state_handler)), options_(options) {
    if (options_.heartbeat_interval.count() <= 0) throw ProtocolError("Heartbeat interval must be positive");
}

ShellIpcSession::~ShellIpcSession() { Stop(); }

void ShellIpcSession::Accept(std::uint32_t timeout_ms) {
    if (State() != IpcLinkState::Idle) throw ProtocolError("IPC session has already started");
    SetState(IpcLinkState::Attaching);
    const auto deadline = Tick() + timeout_ms;
    try {
        control_.Accept(Remaining(deadline));
        packet_.Accept(Remaining(deadline));
        event_.Accept(Remaining(deadline));
    } catch (...) {
        SetState(IpcLinkState::Disconnected);
        throw;
    }
}

void ShellIpcSession::Start() {
    if (State() != IpcLinkState::Attaching) throw ProtocolError("IPC channels are not connected");
    IpcWriter hello;
    hello.U8(static_cast<std::uint8_t>(IpcCommand::Hello));
    hello.I32(IpcProtocol::Version);
    const auto response = Call(hello.ToArray());
    IpcReader reader(response);
    const auto status = static_cast<IpcStatus>(reader.U8());
    if (status == IpcStatus::VersionMismatch) {
        const auto target_version = reader.I32();
        throw ProtocolError("IPC version mismatch: target=" + std::to_string(target_version));
    }
    if (status != IpcStatus::Ok) throw ProtocolError("IPC Hello failed");
    if (reader.I32() != IpcProtocol::Version) throw ProtocolError("IPC Hello returned inconsistent version");
    target_pid_ = reader.I32();
    target_is_64_ = reader.Bool();
    if (reader.Remaining() != 0) throw ProtocolError("IPC Hello response has trailing fields");

    running_.store(true);
    packet_thread_ = std::thread(&ShellIpcSession::PacketLoop, this);
    event_thread_ = std::thread(&ShellIpcSession::EventLoop, this);
    heartbeat_thread_ = std::thread(&ShellIpcSession::HeartbeatLoop, this);
    SetState(IpcLinkState::Attached);
}

ByteBuffer ShellIpcSession::Call(std::span<const std::uint8_t> request) {
    std::lock_guard lock(control_mutex_);
    if (State() == IpcLinkState::Disconnected ||
        (State() == IpcLinkState::Attached && !running_.load()))
        throw ProtocolError("IPC session is stopping");
    return CallUnlocked(request);
}

ByteBuffer ShellIpcSession::CallUnlocked(std::span<const std::uint8_t> request) {
    control_.WriteFrame(request);
    const auto response = control_.ReadFrame();
    if (!response) throw ProtocolError("Target disconnected from control pipe");
    return *response;
}

void ShellIpcSession::ValidateVoidResponse(std::span<const std::uint8_t> response) {
    IpcReader reader(response);
    const auto status = static_cast<IpcStatus>(reader.U8());
    if (status == IpcStatus::Ok) {
        if (reader.Remaining() != 0) throw ProtocolError("Void response has trailing fields");
        return;
    }
    const auto text = reader.Str();
    std::string message = "Target command failed";
    if (text) {
        message += ": ";
        for (const char16_t c : *text) message.push_back(c <= 0x7f ? static_cast<char>(c) : '?');
    }
    throw ProtocolError(message);
}

void ShellIpcSession::CallVoid(std::span<const std::uint8_t> request) {
    ValidateVoidResponse(Call(request));
}

void ShellIpcSession::Detach() {
    {
        // Keep the control gate until running_ is cleared. Otherwise the
        // heartbeat can slip in after the Detach reply, send Ping to a target
        // that is already exiting, and block forever waiting for its reply.
        std::lock_guard lock(control_mutex_);
        if (State() == IpcLinkState::Attached) {
            IpcWriter request;
            request.U8(static_cast<std::uint8_t>(IpcCommand::Detach));
            try { ValidateVoidResponse(CallUnlocked(request.ToArray())); }
            catch (...) { /* a dead target is already detached */ }
        }
        running_.store(false);
        heartbeat_wait_.notify_all();
    }
    Stop();
}

void ShellIpcSession::SetState(IpcLinkState state) noexcept {
    const auto previous = state_.exchange(state);
    if (previous == state || !state_handler_) return;
    try { state_handler_(state); } catch (...) {}
}

void ShellIpcSession::MarkDisconnected() noexcept {
    running_.store(false);
    heartbeat_wait_.notify_all();
    control_.CancelPending();
    packet_.CancelPending();
    event_.CancelPending();
    SetState(IpcLinkState::Disconnected);
}

void ShellIpcSession::PacketLoop() noexcept {
    try {
        while (running_.load()) {
            auto frame = packet_.ReadFrame();
            if (!frame) break;
            if (packet_handler_) { try { packet_handler_(std::move(*frame)); } catch (...) {} }
        }
    } catch (...) {}
    if (running_.load()) MarkDisconnected();
}

void ShellIpcSession::EventLoop() noexcept {
    try {
        while (running_.load()) {
            auto frame = event_.ReadFrame();
            if (!frame) break;
            if (event_handler_) { try { event_handler_(std::move(*frame)); } catch (...) {} }
        }
    } catch (...) {}
    if (running_.load()) MarkDisconnected();
}

void ShellIpcSession::HeartbeatLoop() noexcept {
    std::unique_lock wait_lock(heartbeat_wait_mutex_);
    while (running_.load()) {
        if (heartbeat_wait_.wait_for(wait_lock, options_.heartbeat_interval,
                                    [&] { return !running_.load(); })) break;
        wait_lock.unlock();
        try {
            IpcWriter request;
            request.U8(static_cast<std::uint8_t>(IpcCommand::Ping));
            std::lock_guard control_lock(control_mutex_);
            if (!running_.load()) break;
            ValidateVoidResponse(CallUnlocked(request.ToArray()));
        } catch (...) {
            if (running_.load()) MarkDisconnected();
            break;
        }
        wait_lock.lock();
    }
}

void ShellIpcSession::Stop() noexcept {
    running_.store(false);
    heartbeat_wait_.notify_all();
    control_.CancelPending();
    packet_.CancelPending();
    event_.CancelPending();
    const auto self = std::this_thread::get_id();
    if (packet_thread_.joinable() && packet_thread_.get_id() != self) packet_thread_.join();
    if (event_thread_.joinable() && event_thread_.get_id() != self) event_thread_.join();
    if (heartbeat_thread_.joinable() && heartbeat_thread_.get_id() != self) heartbeat_thread_.join();
    control_.Close();
    packet_.Close();
    event_.Close();
    if (State() == IpcLinkState::Attached || State() == IpcLinkState::Attaching)
        SetState(IpcLinkState::Disconnected);
}

TargetIpcSession::TargetIpcSession(std::string session, std::uint32_t connect_timeout_ms,
                                   TargetSessionOptions options)
    : control_(PipeEndpoint::ConnectClient(session, PipeChannel::Control, connect_timeout_ms)),
      packet_(PipeEndpoint::ConnectClient(session, PipeChannel::Packet, connect_timeout_ms)),
      event_(PipeEndpoint::ConnectClient(session, PipeChannel::Event, connect_timeout_ms)),
      options_(options) {
    if (options_.heartbeat_timeout.count() <= 0 || options_.watchdog_poll.count() <= 0)
        throw ProtocolError("Target heartbeat timings must be positive");
}

TargetIpcSession::~TargetIpcSession() { Stop(); }

ByteBuffer TargetIpcSession::Dispatch(std::span<const std::uint8_t> request,
                                      const CommandHandler& handler,
                                      const LifecycleHandler& hello_handler) {
    IpcReader reader(request);
    const auto command = static_cast<IpcCommand>(reader.U8());
    if (command == IpcCommand::Hello) {
        const auto requested = reader.I32();
        IpcWriter response;
        if (requested != options_.protocol_version) {
            response.U8(static_cast<std::uint8_t>(IpcStatus::VersionMismatch));
            response.I32(options_.protocol_version);
        } else {
            response.U8(static_cast<std::uint8_t>(IpcStatus::Ok));
            response.I32(options_.protocol_version);
            response.I32(static_cast<std::int32_t>(GetCurrentProcessId()));
            response.Bool(sizeof(void*) == 8);
            if (hello_handler) hello_handler();
        }
        return response.ToArray();
    }
    if (command == IpcCommand::Ping) return IpcOk();
    if (command == IpcCommand::Detach) {
        detached_.store(true);
        return IpcOk();
    }
    if (!handler) return IpcError("Command is not implemented");
    return handler(command, reader);
}

void TargetIpcSession::Run(CommandHandler handler, TimeoutHandler timeout_handler,
                           LifecycleHandler hello_handler, LifecycleHandler exit_handler) {
    if (running_.exchange(true)) throw ProtocolError("Target IPC loop is already running");
    timed_out_.store(false);
    detached_.store(false);
    last_command_tick_.store(Tick());
    watchdog_thread_ = std::thread(&TargetIpcSession::WatchdogLoop, this, std::cref(timeout_handler));
    try {
        while (running_.load()) {
            const auto request = control_.ReadFrame();
            if (!request) break;
            last_command_tick_.store(Tick()); // every command is a heartbeat
            ByteBuffer response;
            dispatching_.store(true);
            try { response = Dispatch(*request, handler, hello_handler); }
            catch (const std::exception& error) { response = IpcError(error.what()); }
            catch (...) { response = IpcError("Unknown target command failure"); }
            dispatching_.store(false);
            last_command_tick_.store(Tick());
            control_.WriteFrame(response);
            control_.Flush();
            if (detached_.load()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                break; // reply is visible before hooks/executors are torn down
            }
        }
    } catch (...) {
        if (running_.load() && !timed_out_.load()) {
            running_.store(false);
            control_.CancelPending();
        }
    }
    running_.store(false);
    if (watchdog_thread_.joinable()) watchdog_thread_.join();
    // A producer can be blocked in an overlapped pkt/evt write after the shell
    // has closed its reader. Cancel those writes before lifecycle cleanup joins
    // producer threads.
    packet_.CancelPending();
    event_.CancelPending();
    if (exit_handler) {
        try { exit_handler(); } catch (...) {}
    }
}

void TargetIpcSession::WatchdogLoop(const TimeoutHandler& timeout_handler) noexcept {
    while (running_.load()) {
        std::this_thread::sleep_for(options_.watchdog_poll);
        if (!running_.load()) break;
        if (dispatching_.load()) continue;
        const auto elapsed = Tick() - last_command_tick_.load();
        if (elapsed <= static_cast<std::uint64_t>(options_.heartbeat_timeout.count())) continue;
        timed_out_.store(true);
        running_.store(false);
        control_.CancelPending();
        packet_.CancelPending();
        event_.CancelPending();
        if (timeout_handler) { try { timeout_handler(); } catch (...) {} }
        break;
    }
}

void TargetIpcSession::SendPacketFrame(std::span<const std::uint8_t> frame) {
    std::lock_guard lock(packet_mutex_);
    packet_.WriteFrame(frame);
}

void TargetIpcSession::SendEventFrame(std::span<const std::uint8_t> frame) {
    std::lock_guard lock(event_mutex_);
    // Event delivery must not pin target teardown forever after the shell has
    // disappeared. The original stream is lossy/bounded as well; a stalled
    // reader is therefore an event failure, not permission to hang the host.
    event_.WriteFrame(frame, 500);
}

void TargetIpcSession::Stop() noexcept {
    running_.store(false);
    control_.CancelPending();
    packet_.CancelPending();
    event_.CancelPending();
    if (watchdog_thread_.joinable() && watchdog_thread_.get_id() != std::this_thread::get_id())
        watchdog_thread_.join();
    control_.Close();
    packet_.Close();
    event_.Close();
}

} // namespace wpe
