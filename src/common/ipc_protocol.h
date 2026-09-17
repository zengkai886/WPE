#pragma once
#include <cstdint>
#include <string>
#include <string_view>

namespace wpe {
struct IpcProtocol {
    static constexpr std::int32_t Version = 4;
    static constexpr std::int32_t MaxControlFrame = 1024 * 1024;
    static constexpr std::int32_t MaxPacketFrame = 16 * 1024 * 1024;
    static std::string ControlPipe(std::string_view session) { return "WPE64-" + std::string(session) + "-ctl"; }
    static std::string PacketPipe(std::string_view session) { return "WPE64-" + std::string(session) + "-pkt"; }
    static std::string EventPipe(std::string_view session) { return "WPE64-" + std::string(session) + "-evt"; }
};
enum class IpcCommand : std::uint8_t {
    Hello=1, Ping=2, StartHook=3, StopHook=4, SetConfig=5, SendPacket=6, GetSocketInfo=7,
    Detach=8, GetFootprint=9, ResetStats=10, StartSend=20, StartSendList=22, StopSendList=23,
    StartRobot=24, StartRobotList=26, StopRobotList=27
};
enum class IpcEvent : std::uint8_t { Log=1, FilterLog=2, Stats=3, Dropped=4, HookState=5, StoreAdded=6, Fatal=7 };
enum class ConfigKind : std::uint8_t { HookFlags=1, Filters=2, Runtime=3, Sends=4, Robots=5 };
enum class IpcStatus : std::uint8_t { Ok=0, Error=1, VersionMismatch=2 };
enum class ResetWhat : std::uint8_t { FilterStats=1, PacketCounters=2, SendCounts=4, RobotCounts=8 };
} // namespace wpe
