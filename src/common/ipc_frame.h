#pragma once
#include "ipc_codec.h"
#include <functional>

namespace wpe {
class IpcFrame {
public:
    // Read returns 0 only for EOF; OS errors must throw. Partial reads are allowed.
    using ReadOperation = std::function<std::size_t(std::span<std::uint8_t>)>;
    // A frame is presented to the transport exactly once. Short writes fail.
    using WriteOperation = std::function<std::size_t(std::span<const std::uint8_t>)>;
    static ByteBuffer Encode(std::span<const std::uint8_t> payload);
    static void Write(const WriteOperation& write, std::span<const std::uint8_t> payload);
    static Bytes Read(const ReadOperation& read, std::int32_t max_length);
};
} // namespace wpe
