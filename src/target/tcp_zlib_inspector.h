#pragma once

#include "common/ipc_codec.h"
#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace wpe {

// A directional TCP four-tuple.  The capture layer supplies the local and
// peer endpoint strings (including ports), while direction keeps the two
// half-stream decoders independent.  No packet bytes are persisted here.
struct TcpFlowKey {
    std::string source;
    std::string destination;
    std::uint8_t protocol{6};
    bool operator==(const TcpFlowKey&) const = default;
};

enum class TcpFlowDirection : std::uint8_t {
    SourceToDestination = 0,
    DestinationToSource = 1,
};

enum class TcpZlibStatus : std::uint8_t {
    FrameDecoded,
    TlsSessionKeyRequired,
    UnknownProtocol,
    FlowReassemblyError,
    InvalidFrameLength,
    FrameTooLarge,
    ZlibHeaderError,
    ZlibInflateError,
    DecompressedPayloadTooLarge,
    JsonParseError,
    NestedBodyParseError,
};

struct TcpZlibEvent {
    TcpFlowKey flow;
    TcpFlowDirection direction{TcpFlowDirection::SourceToDestination};
    TcpZlibStatus status{TcpZlibStatus::UnknownProtocol};
    std::uint32_t compressed_size{};
    std::uint32_t decompressed_size{};
    std::string normalized_json;
    std::string error;

    // Compact, redacted JSON suitable for the existing read-only Log event.
    [[nodiscard]] std::string ToLogJson() const;
};

// Incremental decoder for the observed [uint32_be length][zlib payload]
// framing.  It accepts arbitrary TCP chunk boundaries and emits every complete
// frame, including multiple frames from one feed call.
class ZlibFrameDecoder final {
public:
    static constexpr std::size_t MaxCompressedFrame = 16U * 1024U * 1024U;
    static constexpr std::size_t MaxDecompressedPayload = 64U * 1024U * 1024U;
    static constexpr std::size_t MaxBufferedBytes = 64U * 1024U * 1024U;

    struct Frame {
        std::uint32_t compressed_size{};
        ByteBuffer payload;
    };

    [[nodiscard]] std::vector<Frame> Feed(std::span<const std::uint8_t> bytes);
    void Reset() noexcept;
    [[nodiscard]] std::size_t BufferedBytes() const noexcept { return buffer_.size(); }

private:
    ByteBuffer buffer_;
};

// Per-flow protocol classifier and business JSON normalizer.  It deliberately
// exposes only read-only events; it never alters captured bytes or network I/O.
class TcpZlibInspector final {
public:
    TcpZlibInspector();
    ~TcpZlibInspector();
    TcpZlibInspector(const TcpZlibInspector&) = delete;
    TcpZlibInspector& operator=(const TcpZlibInspector&) = delete;

    [[nodiscard]] std::vector<TcpZlibEvent> Feed(
        const TcpFlowKey& flow,
        TcpFlowDirection direction,
        std::span<const std::uint8_t> bytes);
    void ResetFlow(const TcpFlowKey& flow) noexcept;
    void ResetAll() noexcept;
    [[nodiscard]] std::size_t FlowCount() const noexcept;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

[[nodiscard]] const char* TcpZlibStatusName(TcpZlibStatus status) noexcept;

} // namespace wpe
