#include "tcp_zlib_inspector.h"

#define MINIZ_NO_ARCHIVE_APIS
#define MINIZ_NO_ARCHIVE_WRITING_APIS
#define MINIZ_NO_STDIO
#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#define MINIZ_HEADER_FILE_ONLY
#include "miniz/miniz.h"
#include "nlohmann/json.hpp"

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <chrono>
#include <limits>
#include <mutex>
#include <optional>
#include <iterator>
#include <sstream>
#include <unordered_map>
#include <utility>

namespace wpe {
namespace {

using Json = nlohmann::json;

constexpr std::size_t kInflateChunk = 64U * 1024U;

struct FlowHash {
    std::size_t operator()(const TcpFlowKey& key) const noexcept {
        const auto mix = [](std::size_t seed, std::string_view value) {
            for (const auto ch : value) {
                seed ^= static_cast<unsigned char>(ch) + static_cast<std::size_t>(0x9e3779b9U) +
                        (seed << 6U) + (seed >> 2U);
            }
            return seed;
        };
        auto result = mix(0, key.source);
        result = mix(result, key.destination);
        return result ^ (static_cast<std::size_t>(key.protocol) * 0x9e3779b9U);
    }
};

struct FlowDirectionKey {
    TcpFlowKey flow;
    TcpFlowDirection direction{};
    bool operator==(const FlowDirectionKey&) const = default;
};

struct FlowDirectionHash {
    std::size_t operator()(const FlowDirectionKey& key) const noexcept {
        return FlowHash{}(key.flow) ^ (static_cast<std::size_t>(key.direction) * 0x85ebca6bU);
    }
};

enum class ProtocolState : std::uint8_t { Unknown, Business, Tls };

struct StreamState {
    ByteBuffer buffer;
    ProtocolState protocol{ProtocolState::Unknown};
    bool tls_record_reported{};
    std::chrono::steady_clock::time_point last_activity{std::chrono::steady_clock::now()};
};

bool IsSensitiveKey(std::string_view key) {
    std::string normalized;
    normalized.reserve(key.size());
    for (const auto ch : key) {
        if (ch == '-' || ch == '_') continue;
        normalized.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return normalized == "accesstoken" || normalized == "token" ||
           normalized == "authorization" || normalized == "cookie" ||
           normalized == "openid" || normalized == "password" ||
           normalized == "secret" || normalized == "privatekey";
}

void MaskJson(Json& value) {
    if (value.is_object()) {
        for (auto it = value.begin(); it != value.end(); ++it) {
            if (IsSensitiveKey(it.key())) it.value() = "<redacted>";
            else MaskJson(it.value());
        }
    } else if (value.is_array()) {
        for (auto& item : value) MaskJson(item);
    }
}

std::string RedactText(std::string value) {
    // Nested body text is normally JSON and is parsed above.  If it is not,
    // avoid leaking a credential-shaped value into the debug log.
    const auto lower = [&] {
        std::string result = value;
        std::transform(result.begin(), result.end(), result.begin(), [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
        return result;
    }();
    static constexpr std::array<std::string_view, 8> needles = {
        "access_token", "authorization", "cookie", "password",
        "private_key", "openid", "secret", "token"};
    for (const auto needle : needles)
        if (lower.find(needle) != std::string::npos) return "<redacted>";
    return value;
}

std::string ErrorText(const char* text) { return text ? std::string(text) : std::string("unknown error"); }

bool IsTlsHeader(std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.size() < 3) return false;
    return bytes[0] >= 0x14 && bytes[0] <= 0x17 && bytes[1] == 0x03 && bytes[2] <= 0x04;
}

bool CouldBeTlsPrefix(std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.empty() || bytes[0] < 0x14 || bytes[0] > 0x17) return false;
    if (bytes.size() == 1) return true;
    if (bytes[1] != 0x03) return false;
    return bytes.size() < 3 || bytes[2] <= 0x04;
}

bool ZlibHeaderLooksValid(std::span<const std::uint8_t> bytes) noexcept {
    if (bytes.size() < 2) return false;
    const auto cmf = bytes[0];
    const auto flg = bytes[1];
    return (cmf & 0x0fU) == 8U && ((static_cast<unsigned>(cmf) << 8U) + flg) % 31U == 0U;
}

std::optional<ByteBuffer> InflateZlib(std::span<const std::uint8_t> compressed,
                                      std::string& error) {
    mz_stream stream{};
    if (mz_inflateInit(&stream) != MZ_OK) {
        error = "inflate_init_failed";
        return std::nullopt;
    }
    struct End final {
        mz_streamp stream{};
        ~End() { if (stream) (void)mz_inflateEnd(stream); }
    } end{&stream};

    ByteBuffer output;
    output.reserve((std::min)(compressed.size() * 4U, ZlibFrameDecoder::MaxDecompressedPayload));
    stream.next_in = compressed.data();
    stream.avail_in = static_cast<unsigned int>(compressed.size());
    for (;;) {
        const auto old_size = output.size();
        output.resize(old_size + kInflateChunk);
        stream.next_out = output.data() + old_size;
        stream.avail_out = static_cast<unsigned int>(kInflateChunk);
        const auto result = mz_inflate(&stream, MZ_NO_FLUSH);
        const auto produced = kInflateChunk - stream.avail_out;
        output.resize(old_size + produced);
        if (output.size() > ZlibFrameDecoder::MaxDecompressedPayload) {
            error = "decompressed_payload_too_large";
            return std::nullopt;
        }
        if (result == MZ_STREAM_END) return output;
        if (result != MZ_OK) {
            error = ErrorText(mz_error(result));
            return std::nullopt;
        }
        if (produced == 0 && stream.avail_in == 0) {
            error = "inflate_no_progress";
            return std::nullopt;
        }
    }
}

Json NormalizeJson(std::span<const std::uint8_t> plain, bool& nested_error,
                   std::string& nested_raw) {
    nested_error = false;
    nested_raw.clear();
    Json outer = Json::parse(std::string(reinterpret_cast<const char*>(plain.data()), plain.size()));
    MaskJson(outer);
    if (!outer.is_object()) return outer;
    const auto body = outer.find("body");
    if (body != outer.end() && body->is_string()) {
        const auto raw = body->get<std::string>();
        try {
            Json nested = Json::parse(raw);
            MaskJson(nested);
            outer["body"] = std::move(nested);
        } catch (const std::exception& error) {
            nested_error = true;
            nested_raw = RedactText(raw);
            outer["body_raw"] = nested_raw;
            outer["body_parse_error"] = error.what();
            outer["body"] = "<unparsed>";
        }
    }
    return outer;
}

TcpZlibEvent MakeEvent(const TcpFlowKey& flow, TcpFlowDirection direction,
                       TcpZlibStatus status) {
    TcpZlibEvent event;
    event.flow = flow;
    event.direction = direction;
    event.status = status;
    return event;
}

} // namespace

const char* TcpZlibStatusName(TcpZlibStatus status) noexcept {
    switch (status) {
    case TcpZlibStatus::FrameDecoded: return "frame_decoded";
    case TcpZlibStatus::TlsSessionKeyRequired: return "tls_session_key_required";
    case TcpZlibStatus::UnknownProtocol: return "unknown_protocol";
    case TcpZlibStatus::FlowReassemblyError: return "flow_reassembly_error";
    case TcpZlibStatus::InvalidFrameLength: return "invalid_frame_length";
    case TcpZlibStatus::FrameTooLarge: return "frame_too_large";
    case TcpZlibStatus::ZlibHeaderError: return "zlib_header_error";
    case TcpZlibStatus::ZlibInflateError: return "zlib_inflate_error";
    case TcpZlibStatus::DecompressedPayloadTooLarge: return "decompressed_payload_too_large";
    case TcpZlibStatus::JsonParseError: return "json_parse_error";
    case TcpZlibStatus::NestedBodyParseError: return "nested_body_parse_error";
    }
    return "unknown";
}

std::string TcpZlibEvent::ToLogJson() const {
    Json value = {
        {"status", TcpZlibStatusName(status)},
        {"source", flow.source},
        {"destination", flow.destination},
        {"protocol", flow.protocol},
        {"direction", direction == TcpFlowDirection::SourceToDestination ? "source_to_destination" : "destination_to_source"},
        {"compressed_size", compressed_size},
        {"decompressed_size", decompressed_size},
    };
    if (!normalized_json.empty()) {
        try { value["message"] = Json::parse(normalized_json); }
        catch (...) { value["message_raw"] = RedactText(normalized_json); }
    }
    if (!error.empty()) value["error"] = error;
    return value.dump();
}

std::vector<ZlibFrameDecoder::Frame> ZlibFrameDecoder::Feed(
    std::span<const std::uint8_t> bytes) {
    if (!bytes.empty()) buffer_.insert(buffer_.end(), bytes.begin(), bytes.end());
    if (buffer_.size() > MaxBufferedBytes) {
        buffer_.clear();
        return {};
    }
    std::vector<Frame> frames;
    while (buffer_.size() >= 4) {
        const auto size = (static_cast<std::uint32_t>(buffer_[0]) << 24U) |
                          (static_cast<std::uint32_t>(buffer_[1]) << 16U) |
                          (static_cast<std::uint32_t>(buffer_[2]) << 8U) |
                          static_cast<std::uint32_t>(buffer_[3]);
        if (size == 0 || size > MaxCompressedFrame) {
            buffer_.clear();
            return {};
        }
        const auto total = static_cast<std::size_t>(size) + 4U;
        if (buffer_.size() < total) break;
        Frame frame;
        frame.compressed_size = size;
        frame.payload.assign(buffer_.begin() + 4, buffer_.begin() + static_cast<std::ptrdiff_t>(total));
        frames.push_back(std::move(frame));
        buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(total));
    }
    return frames;
}

void ZlibFrameDecoder::Reset() noexcept { buffer_.clear(); }

struct TcpZlibInspector::Impl final {
    static constexpr std::chrono::minutes kFlowTimeout{5};
    static constexpr std::size_t kMaximumFlows = 4096;
    mutable std::mutex mutex;
    std::unordered_map<FlowDirectionKey, StreamState, FlowDirectionHash> flows;

    std::vector<TcpZlibEvent> Feed(const TcpFlowKey& flow, TcpFlowDirection direction,
                                   std::span<const std::uint8_t> bytes) {
        std::lock_guard lock(mutex);
        const auto now = std::chrono::steady_clock::now();
        for (auto it = flows.begin(); it != flows.end();) {
            if (now - it->second.last_activity > kFlowTimeout) it = flows.erase(it);
            else ++it;
        }
        auto& stream = flows[{flow, direction}];
        stream.last_activity = now;
        if (flows.size() > kMaximumFlows) {
            auto oldest = flows.begin();
            for (auto it = std::next(flows.begin()); it != flows.end(); ++it)
                if (it->second.last_activity < oldest->second.last_activity) oldest = it;
            if (!(oldest->first.flow == flow && oldest->first.direction == direction))
                flows.erase(oldest);
        }
        if (!bytes.empty()) stream.buffer.insert(stream.buffer.end(), bytes.begin(), bytes.end());
        std::vector<TcpZlibEvent> events;
        const auto event = [&](TcpZlibStatus status) { return MakeEvent(flow, direction, status); };
        if (stream.buffer.size() > ZlibFrameDecoder::MaxBufferedBytes) {
            auto item = event(TcpZlibStatus::FlowReassemblyError);
            item.error = "stream_buffer_limit_exceeded";
            events.push_back(std::move(item));
            stream.buffer.clear();
            stream.protocol = ProtocolState::Unknown;
            return events;
        }
        if (stream.protocol == ProtocolState::Unknown) {
            if (IsTlsHeader(stream.buffer)) stream.protocol = ProtocolState::Tls;
            else if (CouldBeTlsPrefix(stream.buffer)) return events;
            else stream.protocol = ProtocolState::Business;
        }
        if (stream.protocol == ProtocolState::Tls) {
            while (!stream.buffer.empty()) {
                if (stream.buffer.size() < 5) return events;
                if (!IsTlsHeader(stream.buffer)) {
                    auto item = event(TcpZlibStatus::UnknownProtocol);
                    item.error = "tls_record_header_invalid";
                    events.push_back(std::move(item));
                    stream.buffer.clear();
                    stream.protocol = ProtocolState::Unknown;
                    break;
                }
                const auto size = (static_cast<std::size_t>(stream.buffer[3]) << 8U) |
                                  static_cast<std::size_t>(stream.buffer[4]);
                if (size > ZlibFrameDecoder::MaxCompressedFrame) {
                    auto item = event(TcpZlibStatus::FrameTooLarge);
                    item.error = "tls_record_too_large";
                    events.push_back(std::move(item));
                    stream.buffer.clear();
                    break;
                }
                if (stream.buffer.size() < size + 5U) return events;
                stream.buffer.erase(stream.buffer.begin(), stream.buffer.begin() +
                                    static_cast<std::ptrdiff_t>(size + 5U));
                auto item = event(TcpZlibStatus::TlsSessionKeyRequired);
                item.compressed_size = static_cast<std::uint32_t>(size);
                item.error = "TLS Application Data requires a supplied session key";
                events.push_back(std::move(item));
            }
            return events;
        }

        while (stream.buffer.size() >= 4) {
            const auto size = (static_cast<std::uint32_t>(stream.buffer[0]) << 24U) |
                              (static_cast<std::uint32_t>(stream.buffer[1]) << 16U) |
                              (static_cast<std::uint32_t>(stream.buffer[2]) << 8U) |
                              static_cast<std::uint32_t>(stream.buffer[3]);
            if (size == 0) {
                auto item = event(TcpZlibStatus::InvalidFrameLength);
                item.error = "compressed_size_zero";
                events.push_back(std::move(item));
                stream.buffer.clear();
                stream.protocol = ProtocolState::Unknown;
                break;
            }
            if (size > ZlibFrameDecoder::MaxCompressedFrame) {
                auto item = event(TcpZlibStatus::FrameTooLarge);
                item.compressed_size = size;
                item.error = "compressed_frame_limit_exceeded";
                events.push_back(std::move(item));
                stream.buffer.clear();
                stream.protocol = ProtocolState::Unknown;
                break;
            }
            const auto total = static_cast<std::size_t>(size) + 4U;
            if (stream.buffer.size() < total) break;
            const auto compressed = std::span<const std::uint8_t>(stream.buffer).subspan(4, size);
            ByteBuffer plain;
            std::string error;
            auto item = event(TcpZlibStatus::FrameDecoded);
            item.compressed_size = size;
            if (!ZlibHeaderLooksValid(compressed)) {
                item.status = TcpZlibStatus::ZlibHeaderError;
                item.error = "invalid_zlib_header";
                events.push_back(std::move(item));
                stream.buffer.erase(stream.buffer.begin(), stream.buffer.begin() +
                                    static_cast<std::ptrdiff_t>(total));
                continue;
            }
            const auto inflated = InflateZlib(compressed, error);
            stream.buffer.erase(stream.buffer.begin(), stream.buffer.begin() +
                                static_cast<std::ptrdiff_t>(total));
            if (!inflated) {
                item.status = error == "decompressed_payload_too_large"
                    ? TcpZlibStatus::DecompressedPayloadTooLarge : TcpZlibStatus::ZlibInflateError;
                item.error = std::move(error);
                events.push_back(std::move(item));
                continue;
            }
            plain = std::move(*inflated);
            item.decompressed_size = static_cast<std::uint32_t>(
                (std::min)(plain.size(), static_cast<std::size_t>((std::numeric_limits<std::uint32_t>::max)())));
            bool nested_error = false;
            std::string nested_raw;
            try {
                auto normalized = NormalizeJson(plain, nested_error, nested_raw);
                item.normalized_json = normalized.dump();
                if (nested_error) {
                    item.status = TcpZlibStatus::NestedBodyParseError;
                    item.error = "body_json_parse_failed";
                }
            } catch (const std::exception& json_error) {
                item.status = TcpZlibStatus::JsonParseError;
                item.error = json_error.what();
            }
            events.push_back(std::move(item));
        }
        return events;
    }
};

TcpZlibInspector::TcpZlibInspector() : impl_(std::make_unique<Impl>()) {}
TcpZlibInspector::~TcpZlibInspector() = default;

std::vector<TcpZlibEvent> TcpZlibInspector::Feed(
    const TcpFlowKey& flow, TcpFlowDirection direction,
    std::span<const std::uint8_t> bytes) {
    if (flow.protocol != 6) return {};
    return impl_->Feed(flow, direction, bytes);
}

void TcpZlibInspector::ResetFlow(const TcpFlowKey& flow) noexcept {
    std::lock_guard lock(impl_->mutex);
    for (auto it = impl_->flows.begin(); it != impl_->flows.end();) {
        if (it->first.flow == flow) it = impl_->flows.erase(it);
        else ++it;
    }
}

void TcpZlibInspector::ResetAll() noexcept {
    std::lock_guard lock(impl_->mutex);
    impl_->flows.clear();
}

std::size_t TcpZlibInspector::FlowCount() const noexcept {
    std::lock_guard lock(impl_->mutex);
    return impl_->flows.size();
}

} // namespace wpe
