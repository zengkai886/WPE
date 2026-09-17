#include "common/ipc_codec.h"
#include "common/ipc_frame.h"
#include "common/ipc_protocol.h"
#include "common/packet_frame.h"
#include <algorithm>
#include <fstream>
#include <iostream>
#include <limits>
#include <map>
#include <sstream>

namespace {
std::size_t assertions = 0;
void Check(bool pass, std::string_view message) {
    ++assertions;
    if (!pass) throw std::runtime_error(std::string(message));
}
template<class F> void Throws(F&& f, std::string_view message) {
    bool failed = false;
    try { f(); } catch (const wpe::ProtocolError&) { failed = true; }
    Check(failed, message);
}
std::vector<std::string> Split(const std::string& text, char delimiter) {
    std::vector<std::string> parts;
    std::size_t pos = 0;
    for (;;) {
        const auto end = text.find(delimiter, pos);
        parts.push_back(text.substr(pos, end == std::string::npos ? end : end - pos));
        if (end == std::string::npos) return parts;
        pos = end + 1;
    }
}
constexpr std::string_view base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
wpe::Bytes Unbytes(std::string_view text) {
    if (text == "~") return std::nullopt;
    wpe::ByteBuffer result;
    std::uint32_t bits = 0;
    unsigned held = 0;
    for (char c : text) {
        if (c == '=') break;
        const auto digit = base64.find(c);
        if (digit == std::string_view::npos) throw std::runtime_error("Invalid fixture base64");
        bits = (bits << 6) | static_cast<std::uint32_t>(digit);
        held += 6;
        if (held >= 8) { held -= 8; result.push_back(static_cast<std::uint8_t>(bits >> held)); }
    }
    return result;
}
std::string B64(const wpe::ByteBuffer& bytes) {
    std::string out;
    std::uint32_t bits = 0;
    unsigned held = 0;
    for (auto b : bytes) {
        bits = (bits << 8) | b;
        held += 8;
        while (held >= 6) { held -= 6; out.push_back(base64[(bits >> held) & 63]); }
    }
    if (held) out.push_back(base64[(bits << (6-held)) & 63]);
    while (out.size() % 4) out.push_back('=');
    return out;
}
wpe::Text Text(std::string_view encoded) {
    const auto bytes = Unbytes(encoded);
    if (!bytes) return std::nullopt;
    if (bytes->size() % 2) throw std::runtime_error("Invalid fixture UTF-16");
    std::u16string result;
    for (std::size_t i = 0; i < bytes->size(); i += 2)
        result.push_back(static_cast<char16_t>((*bytes)[i] | (std::uint16_t((*bytes)[i+1]) << 8)));
    return result;
}
std::map<std::string, unsigned> EnumValues() {
#define WPE_ID(T, N) {#T "." #N, static_cast<unsigned>(wpe::T::N)}
    return {
        WPE_ID(IpcCommand, Hello), WPE_ID(IpcCommand, Ping), WPE_ID(IpcCommand, StartHook),
        WPE_ID(IpcCommand, StopHook), WPE_ID(IpcCommand, SetConfig), WPE_ID(IpcCommand, SendPacket),
        WPE_ID(IpcCommand, GetSocketInfo), WPE_ID(IpcCommand, Detach), WPE_ID(IpcCommand, GetFootprint),
        WPE_ID(IpcCommand, ResetStats), WPE_ID(IpcCommand, StartSend), WPE_ID(IpcCommand, StartSendList),
        WPE_ID(IpcCommand, StopSendList), WPE_ID(IpcCommand, StartRobot), WPE_ID(IpcCommand, StartRobotList),
        WPE_ID(IpcCommand, StopRobotList), WPE_ID(IpcEvent, Log), WPE_ID(IpcEvent, FilterLog),
        WPE_ID(IpcEvent, Stats), WPE_ID(IpcEvent, Dropped), WPE_ID(IpcEvent, HookState),
        WPE_ID(IpcEvent, StoreAdded), WPE_ID(IpcEvent, Fatal), WPE_ID(ConfigKind, HookFlags),
        WPE_ID(ConfigKind, Filters), WPE_ID(ConfigKind, Runtime), WPE_ID(ConfigKind, Sends),
        WPE_ID(ConfigKind, Robots), WPE_ID(IpcStatus, Ok), WPE_ID(IpcStatus, Error),
        WPE_ID(IpcStatus, VersionMismatch), WPE_ID(ResetWhat, FilterStats),
        WPE_ID(ResetWhat, PacketCounters), WPE_ID(ResetWhat, SendCounts), WPE_ID(ResetWhat, RobotCounts)
    };
#undef WPE_ID
}
std::string ReadSequence(const wpe::ByteBuffer& bytes, std::int32_t max) {
    std::size_t pos = 0;
    auto source = [&](std::span<std::uint8_t> target) -> std::size_t {
        if (pos == bytes.size()) return 0;
        target[0] = bytes[pos++];
        return 1; // Exercise every possible fragmentation boundary.
    };
    std::string result;
    for (unsigned i = 0; i < 4; ++i) {
        if (i) result += ',';
        try {
            const auto frame = wpe::IpcFrame::Read(source, max);
            if (!frame) { result += "EOF"; break; }
            result += "OK:" + B64(*frame);
        } catch (const wpe::ProtocolError&) { result += "IO"; break; }
    }
    return result;
}
void EdgeCases() {
    wpe::IpcWriter negative;
    negative.I32(-2); negative.I32(std::numeric_limits<std::int32_t>::min()); negative.U8(255);
    const auto data = negative.ToArray();
    wpe::IpcReader reader(data);
    Check(!reader.Str() && !reader.Bytes() && reader.Bool(), "Any negative length is null / nonzero bool");
    Throws([&] { (void)reader.U8(); }, "Exhausted reader");
    Throws([&] { wpe::IpcReader invalid(data, data.size()+1); }, "Invalid offset");
    wpe::IpcWriter huge; huge.I32(std::numeric_limits<std::int32_t>::max());
    const auto huge_data = huge.ToArray();
    Throws([&] { wpe::IpcReader r(huge_data); (void)r.Bytes(); }, "Large field bounds before allocation");
    wpe::IpcWriter short_guid; short_guid.Bytes(wpe::ByteBuffer{1,2,3});
    const auto short_data = short_guid.ToArray();
    Throws([&] { wpe::IpcReader r(short_data); (void)r.Guid_(); }, "Malformed GUID length");
    const auto guid = wpe::Guid::Parse("00112233-4455-6677-8899-aabbccddeeff");
    wpe::IpcWriter gw; gw.Guid_(guid);
    Check(gw.ToArray() == wpe::ByteBuffer({16,0,0,0,0x33,0x22,0x11,0,0x55,0x44,0x77,0x66,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff}), "GUID length and mixed byte order");
    wpe::Packet packet; packet.raw=wpe::ByteBuffer{9}; packet.modified=packet.raw;
    auto encoded = wpe::PacketFrame::Encode(packet);
    encoded[26] |= 0x80; encoded.push_back(42);
    Check(wpe::PacketFrame::Decode(encoded) == packet, "Original ignores unknown flags/trailing fields");
    std::size_t calls=0;
    const wpe::ByteBuffer payload{1,2};
    wpe::IpcFrame::Write([&](std::span<const std::uint8_t> frame) {
        ++calls; Check(wpe::ByteBuffer(frame.begin(),frame.end()) == wpe::ByteBuffer({2,0,0,0,1,2}), "Single write contains header+body");
        return frame.size();
    }, payload);
    Check(calls==1, "Exactly one writer call");
    Throws([&] { wpe::IpcFrame::Write([](std::span<const std::uint8_t>) { return std::size_t(0); }, payload); }, "Short write is an error");
}
} // namespace

int main(int argc, char** argv) {
    std::string current = "edge-cases";
    try {
        EdgeCases();
        if (argc == 1) { std::cout << "PASS: " << assertions << " protocol edge assertions\n"; return 0; }
        if (argc != 3) throw std::runtime_error("Usage: wpe64-parity-test [vectors.tsv native-packets.tsv]");
        std::ifstream input(argv[1], std::ios::binary);
        std::ofstream output(argv[2], std::ios::binary);
        if (!input || !output) throw std::runtime_error("Cannot open fixture/output");
        const auto enums = EnumValues();
        std::size_t rows=0, packets=0;
        std::string line;
        while (std::getline(input,line)) {
            if (!line.empty() && line.back()=='\r') line.pop_back();
            const auto f = Split(line,'\t');
            current = f.at(1);
            ++rows;
            if (f[0]=="primitive") {
                wpe::IpcWriter w;
                w.U8(static_cast<std::uint8_t>(std::stoul(f[2]))); w.Bool(f[3]=="1");
                w.I32(std::stoi(f[4])); w.I64(std::stoll(f[5])); w.Str(Text(f[6]));
                w.Bytes(Unbytes(f[7])); w.Guid_(wpe::Guid::Parse(f[8]));
                const auto expected = *Unbytes(f[9]);
                Check(w.ToArray()==expected,"Primitive wire bytes");
                wpe::IpcReader r(expected);
                Check(r.U8()==std::stoul(f[2]),"u8 decode"); Check(r.Bool()==(f[3]=="1"),"bool decode");
                Check(r.I32()==std::stoi(f[4]),"i32 decode"); Check(r.I64()==std::stoll(f[5]),"i64 decode");
                (void)r.Str(); // String decoding is checked against dedicated oracle rows below.
                Check(r.Bytes()==Unbytes(f[7]),"bytes decode"); Check(r.Guid_().ToString()==f[8],"GUID decode");
                Check(r.Remaining()==0,"Primitive consumed");
            } else if (f[0]=="packet") {
                wpe::Packet p{std::stoll(f[2]),std::stoll(f[3]),std::stoll(f[4]),
                    static_cast<std::uint8_t>(std::stoul(f[5])),static_cast<std::uint8_t>(std::stoul(f[6])),
                    Text(f[7]),Text(f[8]),Unbytes(f[9]),Unbytes(f[10])};
                const auto encoded = wpe::PacketFrame::Encode(p);
                Check(encoded==*Unbytes(f[11]),"Packet wire bytes");
                Check(wpe::PacketFrame::Decode(*Unbytes(f[11]))==p,"Packet decoded fields");
                output << f[1] << '\t' << B64(encoded) << '\n'; ++packets;
            } else if (f[0]=="frame") {
                Check(wpe::IpcFrame::Encode(*Unbytes(f[2]))==*Unbytes(f[3]),"Frame wire bytes");
            } else if (f[0]=="read") {
                Check(ReadSequence(*Unbytes(f[2]),std::stoi(f[3]))==f[4],"Fragmented stream behavior");
            } else if (f[0]=="decode-string") {
                const auto bytes=*Unbytes(f[2]); wpe::IpcReader r(bytes);
                Check(r.Str()==Text(f[3]),"Framework UTF-8 fallback");
            } else if (f[0]=="decode-packet") {
                if (f[3]=="IO") Throws([&] { (void)wpe::PacketFrame::Decode(*Unbytes(f[2])); },"Truncated packet");
                else Check(wpe::PacketFrame::Encode(wpe::PacketFrame::Decode(*Unbytes(f[2])))==*Unbytes(f[2]),"Valid packet");
            } else if (f[0]=="enum") {
                Check(enums.at(f[1])==std::stoul(f[4]),"Wire enum id");
            } else if (f[0]=="constant") {
                const std::map<std::string,std::int32_t> constants{{"version",wpe::IpcProtocol::Version},{"max-control",wpe::IpcProtocol::MaxControlFrame},{"max-packet",wpe::IpcProtocol::MaxPacketFrame}};
                Check(constants.at(f[2])==std::stoi(f[3]),"Protocol constant");
            } else if (f[0]=="pipe") {
                const auto name=f[1]=="control" ? wpe::IpcProtocol::ControlPipe(f[2]) : f[1]=="packet" ? wpe::IpcProtocol::PacketPipe(f[2]) : wpe::IpcProtocol::EventPipe(f[2]);
                Check(name==f[3],"Pipe name");
            } else throw std::runtime_error("Unknown oracle row");
        }
        if (!input.eof()) throw std::runtime_error("Fixture read failed");
        output.flush(); if (!output) throw std::runtime_error("Native output write failed");
        Check(rows==74684 && packets==600,"Fixture corpus must be complete");
        std::cout << "PASS: " << rows << " original C# vectors; " << assertions << " assertions; " << packets << " native packet frames. Pointer bits=" << sizeof(void*)*8 << '\n';
        return 0;
    } catch (const std::exception& error) { std::cerr << "FAIL at " << current << ": " << error.what() << '\n'; return 1; }
}
