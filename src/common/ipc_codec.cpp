#include "ipc_codec.h"
#include <algorithm>
#include <bit>
#include <limits>

namespace wpe {
namespace {
constexpr std::array<std::size_t, 16> guid_order{3,2,1,0,5,4,7,6,8,9,10,11,12,13,14,15};
std::uint8_t Hex(char c) {
    if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<std::uint8_t>(c - 'A' + 10);
    throw ProtocolError("Invalid GUID hex digit");
}
void AppendUtf8(ByteBuffer& out, std::uint32_t cp) {
    if (cp < 0x80) { out.push_back(static_cast<std::uint8_t>(cp)); return; }
    if (cp < 0x800) {
        out.push_back(static_cast<std::uint8_t>(0xc0 | (cp >> 6)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<std::uint8_t>(0xe0 | (cp >> 12)));
        out.push_back(static_cast<std::uint8_t>(0x80 | ((cp >> 6) & 63)));
    } else {
        out.push_back(static_cast<std::uint8_t>(0xf0 | (cp >> 18)));
        out.push_back(static_cast<std::uint8_t>(0x80 | ((cp >> 12) & 63)));
        out.push_back(static_cast<std::uint8_t>(0x80 | ((cp >> 6) & 63)));
    }
    out.push_back(static_cast<std::uint8_t>(0x80 | (cp & 63)));
}
ByteBuffer EncodeUtf8(std::u16string_view text) {
    ByteBuffer out;
    for (std::size_t i = 0; i < text.size(); ++i) {
        std::uint32_t cp = text[i];
        if (cp >= 0xd800 && cp <= 0xdbff) {
            if (i + 1 < text.size() && text[i+1] >= 0xdc00 && text[i+1] <= 0xdfff) {
                cp = 0x10000 + ((cp - 0xd800) << 10) + (text[++i] - 0xdc00);
            } else { cp = 0xfffd; }
        } else if (cp >= 0xdc00 && cp <= 0xdfff) { cp = 0xfffd; }
        AppendUtf8(out, cp);
    }
    return out;
}
std::u16string DecodeFrameworkUtf8(std::span<const std::uint8_t> bytes) {
    // Framework 4.8 consumes the second continuation before rejecting invalid
    // E0/ED/F0/F4 prefixes. Modern UTF-8 libraries group these errors differently.
    std::u16string out;
    std::size_t cursor = 0;
    const auto continuation = [](std::uint8_t b) { return (b & 0xc0) == 0x80; };
    while (cursor < bytes.size()) {
        const auto first = bytes[cursor++];
        if (first < 128) { out.push_back(static_cast<char16_t>(first)); continue; }
        unsigned count;
        if (first >= 0xc2 && first <= 0xdf) count = 2;
        else if (first >= 0xe0 && first <= 0xef) count = 3;
        else if (first >= 0xf0 && first <= 0xf4) count = 4;
        else { out.push_back(u'\ufffd'); continue; }
        if (cursor == bytes.size() || !continuation(bytes[cursor])) {
            out.push_back(u'\ufffd'); continue;
        }
        const auto second = bytes[cursor++];
        if ((first == 0xe0 && second < 0xa0) || (first == 0xed && second >= 0xa0) ||
            (first == 0xf0 && second < 0x90) || (first == 0xf4 && second >= 0x90)) {
            out.push_back(u'\ufffd'); continue;
        }
        std::uint32_t cp = ((first & (0x7fU >> count)) << 6) | (second & 63U);
        bool complete = true;
        for (unsigned i = 2; i < count; ++i) {
            if (cursor == bytes.size() || !continuation(bytes[cursor])) { complete = false; break; }
            cp = (cp << 6) | (bytes[cursor++] & 63U);
        }
        if (!complete) { out.push_back(u'\ufffd'); continue; }
        if (cp < 0x10000) { out.push_back(static_cast<char16_t>(cp)); }
        else {
            cp -= 0x10000;
            out.push_back(static_cast<char16_t>(0xd800 + (cp >> 10)));
            out.push_back(static_cast<char16_t>(0xdc00 + (cp & 0x3ff)));
        }
    }
    return out;
}
} // namespace

Guid Guid::Parse(std::string_view text) {
    if (text.size() != 36 || text[8] != '-' || text[13] != '-' || text[18] != '-' || text[23] != '-')
        throw ProtocolError("GUID requires canonical 8-4-4-4-12 text");
    Guid value;
    std::size_t pos = 0;
    for (auto& b : value.canonical) {
        if (pos == 8 || pos == 13 || pos == 18 || pos == 23) ++pos;
        b = static_cast<std::uint8_t>((Hex(text[pos]) << 4) | Hex(text[pos+1]));
        pos += 2;
    }
    return value;
}
std::string Guid::ToString() const {
    constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(36);
    for (std::size_t i = 0; i < canonical.size(); ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) out.push_back('-');
        out.push_back(digits[canonical[i] >> 4]);
        out.push_back(digits[canonical[i] & 15]);
    }
    return out;
}
void IpcWriter::U8(std::uint8_t value) { buffer_.push_back(value); }
void IpcWriter::Bool(bool value) { U8(value ? 1 : 0); }
void IpcWriter::I32(std::int32_t value) {
    const auto bits = std::bit_cast<std::uint32_t>(value);
    for (unsigned shift = 0; shift < 32; shift += 8) U8(static_cast<std::uint8_t>(bits >> shift));
}
void IpcWriter::I64(std::int64_t value) {
    const auto bits = std::bit_cast<std::uint64_t>(value);
    for (unsigned shift = 0; shift < 64; shift += 8) U8(static_cast<std::uint8_t>(bits >> shift));
}
void IpcWriter::Str(const Text& value) {
    if (!value) { I32(-1); return; }
    Bytes(EncodeUtf8(*value));
}
void IpcWriter::Bytes(const wpe::Bytes& value) {
    if (!value) { I32(-1); return; }
    if (value->size() > static_cast<std::size_t>(std::numeric_limits<std::int32_t>::max()))
        throw ProtocolError("Field exceeds signed 32-bit wire length");
    I32(static_cast<std::int32_t>(value->size()));
    buffer_.insert(buffer_.end(), value->begin(), value->end());
}
void IpcWriter::Guid_(const Guid& value) {
    I32(16);
    for (auto index : guid_order) U8(value.canonical[index]);
}
IpcReader::IpcReader(std::span<const std::uint8_t> buffer, std::size_t start)
    : buffer_(buffer), position_(start) {
    if (start > buffer.size()) throw ProtocolError("Reader start out of bounds");
}
void IpcReader::Need(std::size_t count) const {
    if (count > Remaining()) throw ProtocolError("Frame content out of bounds");
}
std::uint8_t IpcReader::U8() { Need(1); return buffer_[position_++]; }
bool IpcReader::Bool() { return U8() != 0; }
std::int32_t IpcReader::I32() {
    Need(4);
    std::uint32_t bits = 0;
    for (unsigned shift = 0; shift < 32; shift += 8) bits |= std::uint32_t(buffer_[position_++]) << shift;
    return std::bit_cast<std::int32_t>(bits);
}
std::int64_t IpcReader::I64() {
    Need(8);
    std::uint64_t bits = 0;
    for (unsigned shift = 0; shift < 64; shift += 8) bits |= std::uint64_t(buffer_[position_++]) << shift;
    return std::bit_cast<std::int64_t>(bits);
}
Text IpcReader::Str() {
    const auto count = I32();
    if (count < 0) return std::nullopt;
    const auto n = static_cast<std::size_t>(count);
    Need(n);
    auto result = DecodeFrameworkUtf8(buffer_.subspan(position_, n));
    position_ += n;
    return result;
}
wpe::Bytes IpcReader::Bytes() {
    const auto count = I32();
    if (count < 0) return std::nullopt;
    const auto n = static_cast<std::size_t>(count);
    Need(n);
    const auto view = buffer_.subspan(position_, n);
    ByteBuffer result(view.begin(), view.end());
    position_ += n;
    return result;
}
Guid IpcReader::Guid_() {
    const auto data = Bytes();
    if (!data || data->size() != 16) throw ProtocolError("GUID requires 16 bytes");
    Guid value;
    for (std::size_t i = 0; i < 16; ++i) value.canonical[guid_order[i]] = (*data)[i];
    return value;
}
} // namespace wpe
