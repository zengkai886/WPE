#include "packet_frame.h"

namespace wpe {
ByteBuffer PacketFrame::Encode(const Packet& packet) {
    const bool same = packet.raw == packet.modified;
    IpcWriter writer;
    writer.I64(packet.id); writer.I64(packet.time_ticks); writer.I64(packet.socket);
    writer.U8(packet.packet_type); writer.U8(packet.filter_action);
    writer.U8(same ? FlagSameBuffer : 0);
    writer.Str(packet.from); writer.Str(packet.to); writer.Bytes(packet.raw);
    if (!same) writer.Bytes(packet.modified);
    return writer.ToArray();
}
Packet PacketFrame::Decode(std::span<const std::uint8_t> payload) {
    IpcReader reader(payload);
    Packet packet;
    packet.id = reader.I64(); packet.time_ticks = reader.I64(); packet.socket = reader.I64();
    packet.packet_type = reader.U8(); packet.filter_action = reader.U8();
    const auto flags = reader.U8();
    packet.from = reader.Str(); packet.to = reader.Str(); packet.raw = reader.Bytes();
    packet.modified = (flags & FlagSameBuffer) != 0 ? packet.raw : reader.Bytes();
    return packet;
}
} // namespace wpe
