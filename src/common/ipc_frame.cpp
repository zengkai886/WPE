#include "ipc_frame.h"
#include <array>
#include <limits>

namespace wpe {
namespace {
bool ReadExactly(const IpcFrame::ReadOperation& read, std::span<std::uint8_t> output) {
    std::size_t position = 0;
    while (position < output.size()) {
        const auto count = read(output.subspan(position));
        if (count > output.size() - position) throw ProtocolError("Transport returned too many bytes");
        if (count == 0) {
            if (position == 0) return false;
            throw ProtocolError("EOF inside frame");
        }
        position += count;
    }
    return true;
}
} // namespace
ByteBuffer IpcFrame::Encode(std::span<const std::uint8_t> payload) {
    if (payload.size() > static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max()))
        throw ProtocolError("Frame exceeds signed 32-bit wire length");
    ByteBuffer result;
    result.reserve(4 + payload.size());
    const auto size = static_cast<std::uint32_t>(payload.size());
    for (unsigned shift = 0; shift < 32; shift += 8) result.push_back(static_cast<std::uint8_t>(size >> shift));
    result.insert(result.end(),payload.begin(),payload.end());
    return result;
}
void IpcFrame::Write(const WriteOperation& write, std::span<const std::uint8_t> payload) {
    const auto frame = Encode(payload);
    if (write(frame) != frame.size()) throw ProtocolError("Incomplete frame write");
}
Bytes IpcFrame::Read(const ReadOperation& read, std::int32_t max_length) {
    std::array<std::uint8_t,4> header{};
    if (!ReadExactly(read,header)) return std::nullopt;
    IpcReader reader(header);
    const auto length = reader.I32();
    if (length < 0 || length > max_length) throw ProtocolError("Invalid frame length");
    ByteBuffer payload(static_cast<std::size_t>(length));
    if (length != 0 && !ReadExactly(read,payload)) throw ProtocolError("EOF before frame body");
    return payload;
}
} // namespace wpe
