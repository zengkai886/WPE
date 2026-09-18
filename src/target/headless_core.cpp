#include "headless_core.h"
#include "common/ipc_session.h"
#include <algorithm>
#include <stdexcept>
#include <string>
#include <utility>

namespace wpe {
namespace {

void RequireEnd(const IpcReader& reader, const char* what) {
    if (reader.Remaining() != 0) throw ProtocolError(std::string(what) + " has trailing fields");
}

std::size_t ReadCount(IpcReader& reader, const char* what) {
    const auto count = reader.I32();
    if (count < 0 || count > 100000) throw ProtocolError(std::string(what) + " count is invalid");
    return static_cast<std::size_t>(count);
}

Text AsText(std::string_view value) {
    std::u16string result;
    result.reserve(value.size());
    for (const auto c : value) result.push_back(static_cast<unsigned char>(c));
    return result;
}

FilterSnapshot ReadFilter(IpcReader& reader) {
    FilterSnapshot item;
    item.enabled = reader.Bool();
    item.id = reader.Guid_();
    item.name = reader.Str();
    item.appoint_header = reader.Bool(); item.header = reader.Str();
    item.appoint_socket = reader.Bool(); item.socket = reader.Str();
    item.appoint_length = reader.Bool(); item.length = reader.Str();
    item.appoint_port = reader.Bool(); item.port = reader.Str();
    item.mode = reader.I32();
    item.action = reader.I32();
    item.execute = reader.Bool();
    item.execute_type = reader.I32();
    item.execute_id = reader.Guid_();
    for (auto& flag : item.functions) flag = reader.Bool();
    item.start_from = reader.I32();
    item.progression_done = reader.Bool();
    item.progression_continuous = reader.Bool();
    item.progression_step = reader.I32();
    item.progression_carry = reader.Bool();
    item.progression_carry_number = reader.I32();
    item.progression_position = reader.Str();
    item.progression_count = reader.I32();
    item.exclude_position = reader.Str();
    item.random_position = reader.Str();
    item.search = reader.Str();
    item.modify = reader.Str();
    return item;
}

ReplayPacketSnapshot ReadPacket(IpcReader& reader) {
    ReplayPacketSnapshot item;
    item.socket = reader.I32();
    item.packet_type = reader.I32();
    item.from = reader.Str();
    item.to = reader.Str();
    item.bytes = reader.Bytes();
    return item;
}

} // namespace

HeadlessCore::HeadlessCore(IHookController& hooks, EventSender event_sender,
                           HeadlessCoreOptions options)
    : hooks_(hooks), event_sender_(std::move(event_sender)), options_(options) {
    if (options_.stats_interval.count() <= 0)
        throw ProtocolError("Stats interval must be positive");
}

HeadlessCore::~HeadlessCore() { Shutdown(); }

void HeadlessCore::OnHello() {
    try {
        const auto detected = hooks_.DetectWinsock(false);
        std::lock_guard lock(mutex_);
        support_ = detected;
    } catch (const std::exception& error) {
        EmitFatal(std::string("DetectWinsock: ") + error.what());
    } catch (...) {
        EmitFatal("DetectWinsock: unknown failure");
    }

    bool create_thread = false;
    bool installed = false;
    {
        std::lock_guard lock(mutex_);
        installed = hook_installed_;
        if (!started_ && !stopping_) {
            started_ = true;
            create_thread = true;
        }
    }
    EmitHookState(installed);
    if (create_thread) stats_thread_ = std::thread(&HeadlessCore::StatsLoop, this);
}

ByteBuffer HeadlessCore::HandleCommand(IpcCommand command, IpcReader& reader) {
    switch (command) {
    case IpcCommand::StartHook:
        StartHook(reader);
        return IpcOk();
    case IpcCommand::StopHook:
        StopHook(reader);
        return IpcOk();
    case IpcCommand::SetConfig: {
        const auto kind = static_cast<ConfigKind>(reader.U8());
        const auto payload = reader.Bytes();
        RequireEnd(reader, "SetConfig command");
        if (!payload) throw ProtocolError("SetConfig payload cannot be null");
        ApplyConfig(kind, *payload);
        return IpcOk();
    }
    case IpcCommand::SendPacket: {
        auto packet = ReadPacket(reader);
        RequireEnd(reader, "SendPacket command");
        if (!packet.bytes) throw ProtocolError("SendPacket bytes cannot be null");
        IpcWriter response;
        response.U8(static_cast<std::uint8_t>(IpcStatus::Ok));
        response.Bool(hooks_.SendPacket(packet));
        return response.ToArray();
    }
    case IpcCommand::GetSocketInfo: {
        const auto socket = reader.I32();
        RequireEnd(reader, "GetSocketInfo command");
        const auto info = hooks_.GetSocketInfo(socket);
        IpcWriter response;
        response.U8(static_cast<std::uint8_t>(IpcStatus::Ok));
        response.Str(info.from);
        response.Str(info.to);
        return response.ToArray();
    }
    case IpcCommand::ResetStats:
        ResetStats(reader);
        return IpcOk();
    default:
        return IpcError("Command is not implemented by target core");
    }
}

void HeadlessCore::StartHook(IpcReader& reader) {
    RequireEnd(reader, "StartHook command");
    {
        std::lock_guard lock(mutex_);
        if (hook_installed_) return;
    }
    try {
        const auto detected = hooks_.DetectWinsock(true);
        std::lock_guard lock(mutex_);
        support_ = detected;
    } catch (const std::exception& error) {
        EmitFatal(std::string("DetectWinsock: ") + error.what());
    } catch (...) {
        EmitFatal("DetectWinsock: unknown failure");
    }
    hooks_.StartHook();
    {
        std::lock_guard lock(mutex_);
        hook_installed_ = true;
    }
    EmitHookState(true);
}

void HeadlessCore::StopHook(IpcReader& reader) {
    RequireEnd(reader, "StopHook command");
    bool was_installed = false;
    {
        std::lock_guard lock(mutex_);
        was_installed = hook_installed_;
        hook_installed_ = false;
    }
    if (!was_installed) return;
    try { hooks_.StopHook(); } catch (...) {}
    EmitHookState(false);
}

void HeadlessCore::ApplyConfig(ConfigKind kind, std::span<const std::uint8_t> payload) {
    IpcReader reader(payload);
    std::optional<std::array<bool, 12>> hook_flags;
    std::optional<bool> speed_mode;
    std::optional<std::vector<FilterSnapshot>> filters;
    std::int32_t filter_execute = 0;
    bool filter_speed_mode = false;
    {
        std::lock_guard lock(mutex_);
        auto fresh_config = config_;
        switch (kind) {
        case ConfigKind::HookFlags:
            for (auto& flag : fresh_config.hook_flags) flag = reader.Bool();
            break;
        case ConfigKind::Filters: {
            const auto count = ReadCount(reader, "Filter snapshot");
            std::vector<FilterSnapshot> fresh;
            fresh.reserve(count);
            for (std::size_t i = 0; i < count; ++i) {
                auto item = ReadFilter(reader);
                const auto old = std::find_if(config_.filters.begin(), config_.filters.end(),
                    [&](const FilterSnapshot& candidate) { return candidate.id == item.id; });
                if (old != config_.filters.end()) item.execution_count = old->execution_count;
                fresh.push_back(std::move(item));
            }
            fresh_config.filters = std::move(fresh);
            break;
        }
        case ConfigKind::Runtime: {
            RuntimeSnapshot fresh;
            fresh.speed_mode = reader.Bool();
            fresh.system_socket = reader.I32();
            fresh.list_execute = reader.I32();
            fresh.filter_execute = reader.I32();
            if (reader.Bool()) fresh.selected_packet = ReadPacket(reader);
            fresh_config.runtime = std::move(fresh);
            break;
        }
        case ConfigKind::Sends: {
            const auto count = ReadCount(reader, "Send snapshot");
            std::vector<SendSnapshot> fresh;
            fresh.reserve(count);
            for (std::size_t i = 0; i < count; ++i) {
                SendSnapshot item;
                item.enabled = reader.Bool(); item.id = reader.Guid_(); item.name = reader.Str();
                item.system_socket = reader.Bool(); item.loop_count = std::max(1, reader.I32());
                item.loop_interval = std::max(0, reader.I32()); item.notes = reader.Str();
                const auto packets = ReadCount(reader, "Send packet snapshot");
                item.packets.reserve(packets);
                for (std::size_t k = 0; k < packets; ++k) item.packets.push_back(ReadPacket(reader));
                const auto old = std::find_if(config_.sends.begin(), config_.sends.end(),
                    [&](const SendSnapshot& candidate) { return candidate.id == item.id; });
                if (old != config_.sends.end()) {
                    item.execution_count = old->execution_count;
                    item.success_count = old->success_count;
                    item.fail_count = old->fail_count;
                }
                fresh.push_back(std::move(item));
            }
            fresh_config.sends = std::move(fresh);
            break;
        }
        case ConfigKind::Robots: {
            const auto count = ReadCount(reader, "Robot snapshot");
            std::vector<RobotSnapshot> fresh;
            fresh.reserve(count);
            for (std::size_t i = 0; i < count; ++i) {
                RobotSnapshot item;
                item.enabled = reader.Bool(); item.id = reader.Guid_(); item.name = reader.Str();
                const auto instructions = ReadCount(reader, "Robot instruction snapshot");
                item.instructions.reserve(instructions);
                for (std::size_t k = 0; k < instructions; ++k)
                    item.instructions.push_back({reader.I32(), reader.Str()});
                const auto old = std::find_if(config_.robots.begin(), config_.robots.end(),
                    [&](const RobotSnapshot& candidate) { return candidate.id == item.id; });
                if (old != config_.robots.end()) item.execution_count = old->execution_count;
                fresh.push_back(std::move(item));
            }
            fresh_config.robots = std::move(fresh);
            break;
        }
        default:
            throw ProtocolError("Unknown configuration snapshot kind");
        }
        RequireEnd(reader, "Configuration snapshot");
        config_ = std::move(fresh_config);
        if (kind == ConfigKind::HookFlags) hook_flags = config_.hook_flags;
        if (kind == ConfigKind::Runtime) speed_mode = config_.runtime.speed_mode;
        if (kind == ConfigKind::Filters || kind == ConfigKind::Runtime) {
            filters = config_.filters;
            filter_execute = config_.runtime.filter_execute;
            filter_speed_mode = config_.runtime.speed_mode;
        }
    }
    if (hook_flags) hooks_.ConfigureHookFlags(*hook_flags);
    if (speed_mode) hooks_.ConfigureSpeedMode(*speed_mode);
    if (filters) hooks_.ConfigureFilters(*filters, filter_execute, filter_speed_mode);
}

void HeadlessCore::ResetStats(IpcReader& reader) {
    const auto raw = reader.U8();
    RequireEnd(reader, "ResetStats command");
    constexpr std::uint8_t valid = 1U | 2U | 4U | 8U;
    if ((raw & ~valid) != 0) throw ProtocolError("ResetStats mask has unknown bits");
    const bool reset_live_packets =
        (raw & static_cast<std::uint8_t>(ResetWhat::PacketCounters)) != 0;
    {
        std::lock_guard lock(mutex_);
        if ((raw & static_cast<std::uint8_t>(ResetWhat::FilterStats)) != 0) {
            counters_.filter_globals.fill(0);
            for (auto& item : config_.filters) item.execution_count = 0;
        }
        if (reset_live_packets) counters_.packets.fill(0);
        if ((raw & static_cast<std::uint8_t>(ResetWhat::SendCounts)) != 0)
            for (auto& item : config_.sends)
                item.execution_count = item.success_count = item.fail_count = 0;
        if ((raw & static_cast<std::uint8_t>(ResetWhat::RobotCounts)) != 0)
            for (auto& item : config_.robots) item.execution_count = 0;
    }
    if (reset_live_packets) hooks_.ResetLivePacketCounters();
    if ((raw & static_cast<std::uint8_t>(ResetWhat::FilterStats)) != 0)
        hooks_.ResetLiveFilterStats();
}

void HeadlessCore::Emit(ByteBuffer event) noexcept {
    if (!event_sender_) return;
    try { event_sender_(std::move(event)); } catch (...) {}
}

void HeadlessCore::EmitHookState(bool on) noexcept {
    WinsockSupport support;
    {
        std::lock_guard lock(mutex_);
        support = support_;
    }
    IpcWriter writer;
    writer.U8(static_cast<std::uint8_t>(IpcEvent::HookState));
    writer.Bool(on); writer.Bool(support.ws1); writer.Bool(support.ws2); writer.Bool(support.msws);
    Emit(writer.ToArray());
}

void HeadlessCore::EmitFatal(std::string_view message) noexcept {
    try {
        IpcWriter writer;
        writer.U8(static_cast<std::uint8_t>(IpcEvent::Fatal));
        writer.Str(AsText(message));
        Emit(writer.ToArray());
    } catch (...) {}
}

ByteBuffer HeadlessCore::EncodeStatsEvent() const {
    const auto live_packets = hooks_.LivePacketCounters();
    const auto live_filters = hooks_.LiveFilterStats();
    std::lock_guard lock(mutex_);
    IpcWriter writer;
    writer.U8(static_cast<std::uint8_t>(IpcEvent::Stats));
    writer.Bool(counters_.send_list_running);
    writer.Bool(counters_.robot_list_running);
    writer.I32(static_cast<std::int32_t>(config_.filters.size()));
    for (const auto& item : config_.filters) {
        writer.Guid_(item.id);
        auto count = item.execution_count;
        if (live_filters) {
            const auto found = std::find_if(live_filters->filters.begin(), live_filters->filters.end(),
                [&](const auto& candidate) { return candidate.first == item.id; });
            if (found != live_filters->filters.end()) count = found->second;
        }
        writer.I64(count);
    }
    writer.I32(static_cast<std::int32_t>(config_.sends.size()));
    for (const auto& item : config_.sends) {
        writer.Guid_(item.id); writer.I64(item.execution_count);
        writer.I64(item.success_count); writer.I64(item.fail_count);
    }
    for (const auto value : live_filters ? live_filters->globals : counters_.filter_globals)
        writer.I64(value);
    writer.I32(static_cast<std::int32_t>(config_.robots.size()));
    for (const auto& item : config_.robots) { writer.Guid_(item.id); writer.I64(item.execution_count); }
    const auto& packets = live_packets ? *live_packets : counters_.packets;
    for (const auto value : packets) writer.I64(value);
    return writer.ToArray();
}

void HeadlessCore::StatsLoop() noexcept {
    std::unique_lock lock(mutex_);
    while (!stopping_) {
        if (stop_wait_.wait_for(lock, options_.stats_interval, [&] { return stopping_; })) break;
        lock.unlock();
        try { Emit(EncodeStatsEvent()); } catch (...) {}
        lock.lock();
    }
}

void HeadlessCore::Shutdown() noexcept {
    bool stop_hook = false;
    {
        std::lock_guard lock(mutex_);
        if (stopping_) return;
        stopping_ = true;
        stop_hook = hook_installed_;
        hook_installed_ = false;
    }
    stop_wait_.notify_all();
    if (stats_thread_.joinable()) {
        if (stats_thread_.get_id() == std::this_thread::get_id()) stats_thread_.detach();
        else stats_thread_.join();
    }
    if (stop_hook) {
        try { hooks_.StopHook(); } catch (...) {}
        EmitHookState(false);
    }
}

bool HeadlessCore::HookInstalled() const { std::lock_guard lock(mutex_); return hook_installed_; }
WinsockSupport HeadlessCore::Support() const { std::lock_guard lock(mutex_); return support_; }
TargetConfigurationSnapshot HeadlessCore::Configuration() const { std::lock_guard lock(mutex_); return config_; }
TargetCounters HeadlessCore::Counters() const {
    const auto live_packets = hooks_.LivePacketCounters();
    std::lock_guard lock(mutex_);
    auto result = counters_;
    if (live_packets) result.packets = *live_packets;
    return result;
}

void HeadlessCore::SetFilterExecutionCount(const Guid& id, std::int64_t count) {
    std::lock_guard lock(mutex_);
    const auto item = std::find_if(config_.filters.begin(), config_.filters.end(),
        [&](const FilterSnapshot& candidate) { return candidate.id == id; });
    if (item != config_.filters.end()) item->execution_count = count;
}
void HeadlessCore::SetSendCounts(const Guid& id, std::int64_t executed,
                                 std::int64_t succeeded, std::int64_t failed) {
    std::lock_guard lock(mutex_);
    const auto item = std::find_if(config_.sends.begin(), config_.sends.end(),
        [&](const SendSnapshot& candidate) { return candidate.id == id; });
    if (item != config_.sends.end()) {
        item->execution_count = executed; item->success_count = succeeded; item->fail_count = failed;
    }
}
void HeadlessCore::SetRobotExecutionCount(const Guid& id, std::int64_t count) {
    std::lock_guard lock(mutex_);
    const auto item = std::find_if(config_.robots.begin(), config_.robots.end(),
        [&](const RobotSnapshot& candidate) { return candidate.id == id; });
    if (item != config_.robots.end()) item->execution_count = count;
}
void HeadlessCore::SetFilterGlobal(std::size_t index, std::int64_t count) {
    std::lock_guard lock(mutex_);
    if (index >= counters_.filter_globals.size()) throw ProtocolError("Filter counter index out of range");
    counters_.filter_globals[index] = count;
}
void HeadlessCore::SetPacketCounter(std::size_t index, std::int64_t count) {
    std::lock_guard lock(mutex_);
    if (index >= counters_.packets.size()) throw ProtocolError("Packet counter index out of range");
    counters_.packets[index] = count;
}
void HeadlessCore::SetListRunning(bool sends, bool robots) {
    std::lock_guard lock(mutex_);
    counters_.send_list_running = sends;
    counters_.robot_list_running = robots;
}

} // namespace wpe
