#include "common/ipc_codec.h"
#include <iostream>
#include <stdexcept>

int main() {
    try {
        wpe::IpcWriter writer;
        writer.I32(0x12345678);
        writer.Str(std::nullopt);
        writer.Str(std::u16string{});
        const wpe::ByteBuffer expected{0x78,0x56,0x34,0x12,0xff,0xff,0xff,0xff,0,0,0,0};
        if (writer.ToArray() != expected) throw std::runtime_error("Little endian / null / empty mismatch");
        wpe::IpcReader reader(expected);
        if (reader.I32() != 0x12345678 || reader.Str().has_value() || reader.Str() != wpe::Text(u""))
            throw std::runtime_error("Reader mismatch");
        std::cout << "PASS: codec smoke (LE, null distinct from empty)\n";
        return 0;
    } catch (const std::exception& error) { std::cerr << error.what() << '\n'; return 1; }
}
