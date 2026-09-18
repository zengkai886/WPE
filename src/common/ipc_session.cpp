#include "ipc_session.h"
#include <Windows.h>
#include <algorithm>
#include <stdexcept>
#include <utility>
#include <vector>

namespace wpe {
namespace {
constexpr std::size_t kEventQueueMaxCount = 8192;
constexpr std::size_t kEventQueueMaxBytes = 16U * 1024U * 1024U;

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

ByteBuffer EventDropLog(std::uint64_t dropped) {
    IpcWriter writer;
    writer.U8(static_cast<std::uint8_t>(IpcEvent::Log));
    writer.Str(AsText("WpeCore.SendEvent"));
    std::u16string message = u"\u4e8b\u4ef6\u6d41\u79ef\u538b\uff0c\u4e22\u5f03\u4e86 ";
    const auto count = std::to_string(dropped);
    for (const char c : count) message.push_back(static_cast<char16_t>(c));
    message += u" \u6761\uff08\u65e5\u5fd7 / \u5165\u5e93 / \u7edf\u8ba1\uff09";
    writer.Str(Text{std::move(message)});
    return writer.ToArray();
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
    event_writer_thread_ = std::thread(&TargetIpcSession::EventWriterLoop, this);
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
    event_accepting_.store(true);
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
    // A producer can be blocked in an overlapped packet write after the shell
    // has closed its reader. Cancel it before lifecycle cleanup joins the
    // packet writer. Events are queued, so leave that channel alive until the
    // exit handler has enqueued its final HookState and the queue gets a brief
    // opportunity to drain.
    packet_.CancelPending();
    if (exit_handler) {
        try { exit_handler(); } catch (...) {}
    }
    event_accepting_.store(false);
    FlushEvents(std::chrono::milliseconds(200));
    StopEventWriter();
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
    // A stalled/disappeared shell may back-pressure the dedicated writer, but
    // must not make StopHook/Detach wait forever while joining that writer.
    try {
        packet_.WriteFrame(frame, 500);
    } catch (...) {
        // A timed-out framed write can leave a partial prefix/payload in the
        // byte stream. Continuing would corrupt every following packet frame,
        // so fail the target session and let its lifecycle path remove hooks.
        running_.store(false);
        control_.CancelPending();
        packet_.CancelPending();
        event_.CancelPending();
        throw;
    }
}

void TargetIpcSession::SendEventFrame(std::span<const std::uint8_t> frame) {
    if (frame.size() > static_cast<std::size_t>(IpcProtocol::MaxControlFrame))
        throw ProtocolError("Event frame exceeds protocol limit");
    if (!event_accepting_.load() || !event_writer_running_.load()) return;

    ByteBuffer copy(frame.begin(), frame.end());
    {
        std::lock_guard lock(event_queue_mutex_);
        if (!event_accepting_.load() || !event_writer_running_.load()) return;
        event_queue_bytes_ += copy.size();
        event_queue_.push_back(std::move(copy));

        // Match the original queue: enqueue first, then evict the oldest
        // entries. One individually oversized frame is therefore retained.
        while ((event_queue_.size() > kEventQueueMaxCount ||
                event_queue_bytes_ > kEventQueueMaxBytes) &&
               event_queue_.size() > 1) {
            event_queue_bytes_ -= event_queue_.front().size();
            event_queue_.pop_front();
            ++event_queue_dropped_;
        }
    }
    event_queue_changed_.notify_one();
}

void TargetIpcSession::EventWriterLoop() noexcept {
    for (;;) {
        std::vector<ByteBuffer> batch;
        {
            std::unique_lock lock(event_queue_mutex_);
            event_queue_changed_.wait_for(lock, std::chrono::milliseconds(50), [&] {
                return !event_writer_running_.load() || !event_queue_.empty();
            });
            if (!event_writer_running_.load() && event_queue_.empty()) break;
            if (event_queue_.empty()) continue;

            batch.reserve(event_queue_.size());
            while (!event_queue_.empty()) {
                event_queue_bytes_ -= event_queue_.front().size();
                batch.push_back(std::move(event_queue_.front()));
                event_queue_.pop_front();
            }
            event_writing_ = true;
        }

        std::size_t written = 0;
        try {
            for (; written < batch.size(); ++written)
                event_.WriteFrame(batch[written], 500);

            std::uint64_t dropped = 0;
            {
                std::lock_guard lock(event_queue_mutex_);
                dropped = std::exchange(event_queue_dropped_, 0);
            }
            if (dropped != 0) event_.WriteFrame(EventDropLog(dropped), 500);
        } catch (...) {
            // A timeout may have left a partial frame in the byte stream. Do
            // not attempt another event write on a now-corrupt stream. Make
            // the control loop leave so the normal lifecycle removes hooks.
            {
                std::lock_guard lock(event_queue_mutex_);
                event_queue_dropped_ += static_cast<std::uint64_t>(batch.size() - written);
                event_queue_dropped_ += static_cast<std::uint64_t>(event_queue_.size());
                event_queue_.clear();
                event_queue_bytes_ = 0;
                event_accepting_.store(false);
                event_writer_running_.store(false);
            }
            running_.store(false);
            control_.CancelPending();
            packet_.CancelPending();
            event_.CancelPending();
        }

        {
            std::lock_guard lock(event_queue_mutex_);
            event_writing_ = false;
        }
        event_queue_idle_.notify_all();
        if (!event_writer_running_.load()) break;
    }

    {
        std::lock_guard lock(event_queue_mutex_);
        event_writing_ = false;
    }
    event_queue_idle_.notify_all();
}

void TargetIpcSession::FlushEvents(std::chrono::milliseconds timeout) noexcept {
    std::unique_lock lock(event_queue_mutex_);
    static_cast<void>(event_queue_idle_.wait_for(lock, timeout, [&] {
        return (event_queue_.empty() && !event_writing_) || !event_writer_running_.load();
    }));
}

void TargetIpcSession::StopEventWriter() noexcept {
    {
        std::lock_guard lock(event_queue_mutex_);
        event_writer_running_.store(false);
        event_queue_dropped_ += static_cast<std::uint64_t>(event_queue_.size());
        event_queue_.clear();
        event_queue_bytes_ = 0;
    }
    event_queue_changed_.notify_all();
    event_.CancelPending();
    if (event_writer_thread_.joinable() &&
        event_writer_thread_.get_id() != std::this_thread::get_id())
        event_writer_thread_.join();
    {
        std::lock_guard lock(event_queue_mutex_);
        event_writing_ = false;
    }
    event_queue_idle_.notify_all();
}

void TargetIpcSession::Stop() noexcept {
    running_.store(false);
    event_accepting_.store(false);
    control_.CancelPending();
    packet_.CancelPending();
    StopEventWriter();
    if (watchdog_thread_.joinable() && watchdog_thread_.get_id() != std::this_thread::get_id())
        watchdog_thread_.join();
    control_.Close();
    packet_.Close();
    event_.Close();
}

} // namespace wpe
