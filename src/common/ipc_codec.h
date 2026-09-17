#pragma once
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace wpe {
using ByteBuffer = std::vector<std::uint8_t>;
using Bytes = std::optional<ByteBuffer>;
// UTF-16 preserves C# code units, including unpaired surrogates on input.
using Text = std::optional<std::u16string>;

class ProtocolError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct Guid {
    // Canonical textual/RFC order in memory; wire conversion is explicit.
    std::array<std::uint8_t, 16> canonical{};
    static Guid Parse(std::string_view text);
    std::string ToString() const;
    bool operator==(const Guid&) const = default;
};

class IpcWriter {
public:
    void U8(std::uint8_t value);
    void Bool(bool value);
    void I32(std::int32_t value);
    void I64(std::int64_t value);
    void Str(const Text& value);
    void Bytes(const wpe::Bytes& value);
    void Guid_(const Guid& value);
    std::size_t Length() const noexcept { return buffer_.size(); }
    ByteBuffer ToArray() const { return buffer_; }
private:
    ByteBuffer buffer_;
};

class IpcReader {
public:
    // The input must outlive the reader and must not change while it is read.
    explicit IpcReader(std::span<const std::uint8_t> buffer, std::size_t start = 0);
    std::uint8_t U8();
    bool Bool();
    std::int32_t I32();
    std::int64_t I64();
    Text Str();
    wpe::Bytes Bytes();
    Guid Guid_();
    std::size_t Remaining() const noexcept { return buffer_.size() - position_; }
private:
    void Need(std::size_t count) const;
    std::span<const std::uint8_t> buffer_;
    std::size_t position_;
};
} // namespace wpe
