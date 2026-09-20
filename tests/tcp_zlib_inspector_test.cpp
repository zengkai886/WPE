#include "target/tcp_zlib_inspector.h"

#define MINIZ_NO_ARCHIVE_APIS
#define MINIZ_NO_ARCHIVE_WRITING_APIS
#define MINIZ_NO_STDIO
#define MINIZ_NO_ZLIB_COMPATIBLE_NAMES
#define MINIZ_HEADER_FILE_ONLY
#include "miniz/miniz.h"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>

using namespace wpe;

namespace {

void Require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

ByteBuffer Frame(std::string_view text) {
    ByteBuffer compressed(1024);
    mz_ulong compressed_size = static_cast<mz_ulong>(compressed.size());
    const auto result = mz_compress(compressed.data(), &compressed_size,
                                    reinterpret_cast<const unsigned char*>(text.data()),
                                    static_cast<mz_ulong>(text.size()));
    Require(result == MZ_OK, "sample JSON compression failed");
    compressed.resize(static_cast<std::size_t>(compressed_size));
    ByteBuffer frame(4 + compressed.size());
    const auto size = static_cast<std::uint32_t>(compressed.size());
    frame[0] = static_cast<std::uint8_t>(size >> 24U);
    frame[1] = static_cast<std::uint8_t>(size >> 16U);
    frame[2] = static_cast<std::uint8_t>(size >> 8U);
    frame[3] = static_cast<std::uint8_t>(size);
    std::copy(compressed.begin(), compressed.end(), frame.begin() + 4);
    return frame;
}

TcpFlowKey Flow(std::string source = "10.0.0.1:4000",
                std::string destination = "10.0.0.2:5000") {
    return {std::move(source), std::move(destination), 6};
}

void TestSplitAndStickyFrames() {
    const auto first = Frame(R"({"type":2,"seq_id":12,"cmd_id":5000,"body":"{\"ret\":0,\"token\":\"secret\"}"})");
    const auto second = Frame(R"({"type":2,"seq_id":13,"cmd_id":5001,"body":{"ret":0}})");
    ByteBuffer combined = first;
    combined.insert(combined.end(), second.begin(), second.end());

    TcpZlibInspector inspector;
    std::vector<TcpZlibEvent> events;
    for (const auto byte : combined) {
        const ByteBuffer chunk{byte};
        auto partial = inspector.Feed(Flow(), TcpFlowDirection::SourceToDestination, chunk);
        events.insert(events.end(), partial.begin(), partial.end());
    }
    Require(events.size() == 2, "split/sticky frames must both decode");
    Require(events[0].status == TcpZlibStatus::FrameDecoded,
            "first frame status");
    Require(events[0].normalized_json.find("<redacted>") != std::string::npos,
            "nested token must be redacted");
    Require(events[1].normalized_json.find("5001") != std::string::npos,
            "second command must be normalized");
    Require(inspector.FlowCount() == 1, "one direction must use one flow decoder");
}

void TestIndependentDirectionsAndFlows() {
    TcpZlibInspector inspector;
    const auto frame = Frame(R"({"cmd_id":9000,"body":{"ret":0}})");
    auto a = inspector.Feed(Flow(), TcpFlowDirection::SourceToDestination, frame);
    auto b = inspector.Feed(Flow(), TcpFlowDirection::DestinationToSource, frame);
    auto c = inspector.Feed(Flow("10.0.0.3:4000", "10.0.0.4:5000"),
                            TcpFlowDirection::SourceToDestination, frame);
    Require(a.size() == 1 && b.size() == 1 && c.size() == 1,
            "directions and four-tuples must be isolated");
    Require(inspector.FlowCount() == 3, "flow table must keep independent directions");
}

void TestTlsAndErrors() {
    TcpZlibInspector inspector;
    const auto flow = Flow();
    const ByteBuffer tls = {0x17, 0x03, 0x03, 0x00, 0x03, 0x01, 0x02, 0x03};
    auto tls_events = inspector.Feed(flow, TcpFlowDirection::SourceToDestination, tls);
    Require(tls_events.size() == 1 &&
                tls_events[0].status == TcpZlibStatus::TlsSessionKeyRequired,
            "TLS must not be sent to zlib");
    ByteBuffer invalid = {0x00, 0x00, 0x00, 0x00};
    auto invalid_events = inspector.Feed(Flow("10.0.0.5:1", "10.0.0.6:2"),
                                         TcpFlowDirection::SourceToDestination, invalid);
    Require(invalid_events.size() == 1 &&
                invalid_events[0].status == TcpZlibStatus::InvalidFrameLength,
            "zero length must be reported");
    Require(inspector.Feed(flow, TcpFlowDirection::SourceToDestination, {}).empty(),
            "TLS stream should not emit without another complete record");
}

} // namespace

int main() {
    try {
        TestSplitAndStickyFrames();
        TestIndependentDirectionsAndFlows();
        TestTlsAndErrors();
        std::cout << "PASS: TCP reassembly, zlib framing, JSON normalization and TLS classification\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "FAIL: " << error.what() << '\n';
        return 1;
    }
}
