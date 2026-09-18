#pragma once

#include "ipc_pipe.h"
#include "ipc_protocol.h"
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

namespace wpe {

enum class IpcLinkState : std::uint8_t { Idle, Attaching, Attached, Disconnected };

struct ShellSessionOptions {
    std::chrono::milliseconds heartbeat_interval{1000};
    // Control requests must not wait forever for a target handler that has
    // crashed or deadlocked.  Packet/event streams remain cancellation based.
    std::uint32_t control_timeout_ms{10000};
};

class ShellIpcSession final {
public:
    using FrameHandler = std::function<void(ByteBuffer)>;
    using StateHandler = std::function<void(IpcLinkState)>;

    ShellIpcSession(std::string session, FrameHandler packet_handler,
                    FrameHandler event_handler, StateHandler state_handler = {},
                    ShellSessionOptions options = {});
    ~ShellIpcSession();
    ShellIpcSession(const ShellIpcSession&) = delete;
    ShellIpcSession& operator=(const ShellIpcSession&) = delete;

    // The three server instances already exist when this waits, allowing the
    // target to connect ctl/pkt/evt in its original sequential order.
    void Accept(std::uint32_t timeout_ms);
    void Start();
    ByteBuffer Call(std::span<const std::uint8_t> request);
    void CallVoid(std::span<const std::uint8_t> request);
    void Detach();
    void Stop() noexcept;

    [[nodiscard]] IpcLinkState State() const noexcept { return state_.load(); }
    [[nodiscard]] std::int32_t TargetPid() const noexcept { return target_pid_; }
    [[nodiscard]] bool TargetIs64() const noexcept { return target_is_64_; }
    [[nodiscard]] const std::string& Session() const noexcept { return session_; }

private:
    ByteBuffer CallUnlocked(std::span<const std::uint8_t> request);
    static void ValidateVoidResponse(std::span<const std::uint8_t> response);
    void SetState(IpcLinkState state) noexcept;
    void MarkDisconnected() noexcept;
    void PacketLoop() noexcept;
    void EventLoop() noexcept;
    void HeartbeatLoop() noexcept;

    std::string session_;
    PipeEndpoint control_;
    PipeEndpoint packet_;
    PipeEndpoint event_;
    FrameHandler packet_handler_;
    FrameHandler event_handler_;
    StateHandler state_handler_;
    ShellSessionOptions options_;
    std::mutex control_mutex_;
    std::mutex heartbeat_wait_mutex_;
    std::condition_variable heartbeat_wait_;
    std::atomic<IpcLinkState> state_{IpcLinkState::Idle};
    std::atomic<bool> running_{false};
    std::thread packet_thread_;
    std::thread event_thread_;
    std::thread heartbeat_thread_;
    std::int32_t target_pid_{0};
    bool target_is_64_{false};
};

struct TargetSessionOptions {
    std::chrono::milliseconds heartbeat_timeout{3000};
    std::chrono::milliseconds watchdog_poll{50};
    std::int32_t protocol_version{IpcProtocol::Version};
};

class TargetIpcSession final {
public:
    using CommandHandler = std::function<ByteBuffer(IpcCommand, IpcReader&)>;
    using TimeoutHandler = std::function<void()>;
    using LifecycleHandler = std::function<void()>;

    TargetIpcSession(std::string session, std::uint32_t connect_timeout_ms,
                     TargetSessionOptions options = {});
    ~TargetIpcSession();
    TargetIpcSession(const TargetIpcSession&) = delete;
    TargetIpcSession& operator=(const TargetIpcSession&) = delete;

    // Runs the target control loop on the caller's dedicated thread. Built-ins
    // are Hello, Ping and Detach; other commands are passed to handler.
    void Run(CommandHandler handler, TimeoutHandler timeout_handler = {},
             LifecycleHandler hello_handler = {}, LifecycleHandler exit_handler = {});
    void SendPacketFrame(std::span<const std::uint8_t> frame);
    void SendEventFrame(std::span<const std::uint8_t> frame);
    void Stop() noexcept;

    [[nodiscard]] bool TimedOut() const noexcept { return timed_out_.load(); }
    [[nodiscard]] bool Detached() const noexcept { return detached_.load(); }

private:
    ByteBuffer Dispatch(std::span<const std::uint8_t> request, const CommandHandler& handler,
                        const LifecycleHandler& hello_handler);
    void WatchdogLoop(const TimeoutHandler& timeout_handler) noexcept;
    void EventWriterLoop() noexcept;
    void FlushEvents(std::chrono::milliseconds timeout) noexcept;
    void StopEventWriter() noexcept;

    PipeEndpoint control_;
    PipeEndpoint packet_;
    PipeEndpoint event_;
    TargetSessionOptions options_;
    std::mutex packet_mutex_;
    std::mutex event_queue_mutex_;
    std::condition_variable event_queue_changed_;
    std::condition_variable event_queue_idle_;
    std::deque<ByteBuffer> event_queue_;
    std::size_t event_queue_bytes_{};
    std::uint64_t event_queue_dropped_{};
    bool event_writing_{};
    std::atomic<bool> event_accepting_{false};
    std::atomic<bool> event_writer_running_{true};
    std::atomic<bool> running_{false};
    std::atomic<bool> timed_out_{false};
    std::atomic<bool> detached_{false};
    std::atomic<bool> dispatching_{false};
    std::atomic<std::uint64_t> last_command_tick_{0};
    std::thread watchdog_thread_;
    std::thread event_writer_thread_;
};

ByteBuffer IpcOk();
ByteBuffer IpcError(const Text& message);
ByteBuffer IpcError(std::string_view message);

} // namespace wpe
