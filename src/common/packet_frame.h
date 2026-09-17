#pragma once
#include "ipc_codec.h"

namespace wpe {
struct Packet {
    std::int64_t id{};
    std::int64_t time_ticks{};
    std::int64_t socket{};
    std::uint8_t packet_type{};
    std::uint8_t filter_action{};
    Text from;
    Text to;
    Bytes raw;
    Bytes modified;
    bool operator==(const Packet&) const = default;
};
class PacketFrame {
public:
    static constexpr std::uint8_t FlagSameBuffer = 1;
    static ByteBuffer Encode(const Packet& packet);
    static Packet Decode(std::span<const std::uint8_t> payload);
};
} // namespace wpe
