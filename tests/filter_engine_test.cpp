#include "target/filter_engine.h"
#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <iostream>
#include <string_view>
#include <thread>

namespace {
int checks = 0;

void Check(bool condition, const char* message) {
    ++checks;
    if (!condition) {
        std::cerr << "FAIL: " << message << '\n';
        std::exit(1);
    }
}

wpe::Text Text(std::string_view value) {
    std::u16string result;
    for (const unsigned char character : value) result.push_back(static_cast<char16_t>(character));
    return result;
}

wpe::FilterSnapshot Base(std::string_view id) {
    wpe::FilterSnapshot filter;
    filter.enabled = true;
    filter.id = wpe::Guid::Parse(id);
    filter.name = Text("golden-filter");
    filter.functions.fill(true);
    filter.mode = 0;
    filter.action = static_cast<std::int32_t>(wpe::FilterAction::Replace);
    filter.search = Text("0|10,1|2*,2|**");
    filter.modify = Text("1|7f");
    filter.progression_step = 1;
    filter.progression_carry_number = 1;
    return filter;
}

wpe::FilterContext Context(std::int64_t socket = 42, std::uint8_t type = 1) {
    wpe::FilterContext context;
    context.socket = socket;
    context.packet_type = type;
    context.ports[0] = 443;
    context.ports[1] = 51000;
    context.port_count = 2;
    return context;
}
} // namespace

int main() {
    wpe::FilterEngine engine;
    auto filter = Base("00112233-4455-6677-8899-aabbccddeeff");
    engine.Publish({filter}, 0, false);

    const std::vector<std::uint8_t> packet{0x10, 0x2a, 0xff, 0x40};
    auto result = engine.Apply(Context(), packet);
    Check(result.action == wpe::FilterAction::Replace, "normal wildcard match applies replace");
    Check(result.bytes == std::vector<std::uint8_t>({0x10, 0x7f, 0xff, 0x40}),
          "normal replacement uses absolute position");
    Check(result.logs.size() == 1 && result.logs[0].matches == 1 &&
          result.logs[0].packet_length == 4,
          "non-speed mode emits one compact filter log");

    result = engine.Apply(Context(), std::vector<std::uint8_t>{0x11, 0x2a, 0xff});
    Check(result.action == wpe::FilterAction::None, "normal mismatch is ignored");
    filter.exclude_position = Text("1");
    engine.Publish({filter}, 0, false);
    result = engine.Apply(Context(), packet);
    Check(result.action == wpe::FilterAction::None, "excluded position inverts match");

    filter.exclude_position = Text("");
    filter.appoint_socket = true;
    filter.socket = Text("7; 42;99");
    filter.appoint_length = true;
    filter.length = Text("1-3;4;10-20");
    filter.appoint_port = true;
    filter.port = Text("80;400-450");
    filter.appoint_header = true;
    filter.header = Text("10 2A");
    engine.Publish({filter}, 0, false);
    Check(engine.Apply(Context(), packet).action == wpe::FilterAction::Replace,
          "socket length port and header gates accept matching packet");
    Check(engine.Apply(Context(43), packet).action == wpe::FilterAction::None,
          "socket gate rejects other socket");
    auto wrong_port = Context(); wrong_port.ports = {81, 82};
    Check(engine.Apply(wrong_port, packet).action == wpe::FilterAction::None,
          "port gate rejects absent range");

    auto advanced = Base("11112233-4455-6677-8899-aabbccddeeff");
    advanced.mode = 1;
    advanced.start_from = 1;
    advanced.search = Text("0|aa,1|bb");
    advanced.modify = Text("1|cc");
    engine.Publish({advanced}, 0, false);
    result = engine.Apply(Context(), std::vector<std::uint8_t>{0xaa,0xbb,0x00,0xaa,0xbb});
    Check(result.action == wpe::FilterAction::Replace, "advanced pattern matches");
    Check(result.bytes == std::vector<std::uint8_t>({0xaa,0xcc,0x00,0xaa,0xcc}),
          "advanced position-relative replace applies to every non-overlapping match");
    Check(result.logs.size() == 1 && result.logs.back().matches == 2,
          "advanced log records match count");

    auto change = Base("21112233-4455-6677-8899-aabbccddeeff");
    change.action = static_cast<std::int32_t>(wpe::FilterAction::Change);
    change.search = Text("0|10");
    change.modify = Text("0|aa,3|dd");
    engine.Publish({change}, 0, false);
    result = engine.Apply(Context(), packet);
    Check(result.action == wpe::FilterAction::Change, "change action matches");
    Check(result.bytes == std::vector<std::uint8_t>({0xaa,0x00,0x00,0xdd}),
          "change builds packet through highest modification index");

    auto intercept = Base("31112233-4455-6677-8899-aabbccddeeff");
    intercept.action = static_cast<std::int32_t>(wpe::FilterAction::Intercept);
    intercept.search = Text("0|10");
    intercept.modify = Text("");
    engine.Publish({intercept}, 0, false);
    result = engine.Apply(Context(), packet);
    Check(result.action == wpe::FilterAction::Intercept && result.bytes == packet,
          "intercept preserves bytes for capture");
    intercept.action = static_cast<std::int32_t>(wpe::FilterAction::NoModifyDisplay);
    engine.Publish({intercept}, 0, false);
    Check(engine.Apply(Context(), packet).action == wpe::FilterAction::NoModifyDisplay,
          "display-only action matches without changing bytes");
    intercept.action = static_cast<std::int32_t>(wpe::FilterAction::NoModifyNoDisplay);
    engine.Publish({intercept}, 0, false);
    Check(engine.Apply(Context(), packet).action == wpe::FilterAction::NoModifyNoDisplay,
          "no-display action matches without changing bytes");

    auto progression = Base("41112233-4455-6677-8899-aabbccddeeff");
    progression.search = Text("0|ff");
    progression.modify = Text("");
    progression.progression_position = Text("1");
    progression.progression_step = 1;
    progression.progression_continuous = true;
    progression.progression_carry = true;
    engine.Publish({progression}, 0, false);
    result = engine.Apply(Context(), std::vector<std::uint8_t>{0xff,0xff});
    Check(result.bytes == std::vector<std::uint8_t>({0x00,0x00}),
          "progression wraps and carries to previous byte");
    result = engine.Apply(Context(), std::vector<std::uint8_t>{0xff,0x01});
    Check(result.bytes == std::vector<std::uint8_t>({0xff,0x03}),
          "continuous progression increments multiplier");
    engine.Publish({progression}, 0, false);
    result = engine.Apply(Context(), std::vector<std::uint8_t>{0xff,0x01});
    Check(result.bytes == std::vector<std::uint8_t>({0xff,0x04}),
          "snapshot publication shares progression state by GUID");

    auto random = Base("51112233-4455-6677-8899-aabbccddeeff");
    random.search = Text("0|10"); random.modify = Text(""); random.random_position = Text("1");
    engine.Publish({random}, 0, false);
    result = engine.Apply(Context(), packet);
    Check(result.action == wpe::FilterAction::Replace && result.bytes[1] != packet[1],
          "random replacement always differs from original byte");

    auto first = Base("61112233-4455-6677-8899-aabbccddeeff");
    first.search = Text("0|10"); first.modify = Text("1|11");
    auto second = Base("71112233-4455-6677-8899-aabbccddeeff");
    second.search = Text("0|10"); second.modify = Text("1|22");
    engine.ResetStats();
    engine.Publish({first, second}, 0, false);
    Check(engine.Apply(Context(), packet).bytes[1] == 0x11, "priority mode stops after first action");
    engine.Publish({first, second}, 1, false);
    Check(engine.Apply(Context(), packet).bytes[1] == 0x22, "sequence mode applies all replace filters");

    auto stats = engine.Stats();
    Check(stats.filters.size() == 2 && stats.filters[0].second == 2 && stats.filters[1].second == 1,
          "per-filter execution counters are live");
    Check(stats.globals[0] == 3 && stats.globals[1] == 3, "global execute and replace counters are live");
    engine.Publish({first, second}, 1, true);
    stats = engine.Stats();
    Check(stats.filters[0].second == 2 && stats.filters[1].second == 1,
          "snapshot publication preserves counts by GUID");
    Check(engine.Apply(Context(), packet).logs.empty(),
          "speed mode suppresses filter log events");
    engine.ResetStats();
    stats = engine.Stats();
    Check(stats.filters[0].second == 0 && stats.filters[1].second == 0,
          "filter reset clears item counts");
    Check(std::all_of(stats.globals.begin(), stats.globals.end(), [](auto value) { return value == 0; }),
          "filter reset clears global counts");

    first.enabled = false;
    engine.Publish({first}, 0, false);
    Check(engine.Apply(Context(), packet).action == wpe::FilterAction::None,
          "disabled filter is ineffective");
    first.enabled = true;
    first.functions.fill(false);
    first.functions[0] = true;
    engine.Publish({first}, 0, false);
    Check(engine.Apply(Context(42, 0), packet).action == wpe::FilterAction::Replace,
          "WS1 send maps to Send function flag");
    Check(engine.Apply(Context(42, 1), packet).action == wpe::FilterAction::Replace,
          "WS2 send maps to Send function flag");
    Check(engine.Apply(Context(42, 2), packet).action == wpe::FilterAction::None,
          "sendto requires its distinct function flag");

    auto whitespace_search = Base("81112233-4455-6677-8899-aabbccddeeff");
    whitespace_search.search = Text(" , ");
    whitespace_search.modify = Text("0|aa");
    engine.Publish({whitespace_search}, 0, false);
    Check(engine.Apply(Context(), packet).bytes[0] == 0xaa,
          "normal whitespace-only search preserves original vacuous-match behavior");
    whitespace_search.search = Text("bad");
    engine.Publish({whitespace_search}, 0, false);
    Check(engine.Apply(Context(), packet).action == wpe::FilterAction::None,
          "malformed normal search is rejected instead of becoming a vacuous match");

    auto nested = Base("a1112233-4455-6677-8899-aabbccddeeff");
    nested.search = Text("0|10");
    nested.modify = Text("2|ee");
    nested.name = Text("nested-filter");
    auto parent = Base("b1112233-4455-6677-8899-aabbccddeeff");
    parent.search = Text("0|10");
    parent.modify = Text("");
    parent.action = static_cast<std::int32_t>(wpe::FilterAction::NoModifyDisplay);
    parent.execute = true;
    parent.execute_type = 3;
    parent.execute_id = nested.id;
    engine.ResetStats();
    engine.Publish({parent, nested}, 0, false);
    result = engine.Apply(Context(), packet);
    Check(result.action == wpe::FilterAction::NoModifyDisplay && result.bytes[2] == 0xee,
          "filter trigger executes the linked filter before returning parent action");
    Check(result.logs.size() == 2 && result.logs[0].name == nested.name &&
          result.logs[1].name == parent.name,
          "nested and parent filter logs are returned for deferred delivery");
    stats = engine.Stats();
    Check(stats.filters[0].second == 1 && stats.filters[1].second == 1 &&
          stats.globals[0] == 2,
          "nested execution updates both shared runtime counters");

    parent.action = static_cast<std::int32_t>(wpe::FilterAction::None);
    parent.execute_type = 0;
    engine.ResetStats();
    engine.Publish({parent}, 0, false);
    result = engine.Apply(Context(), packet);
    Check(result.action == wpe::FilterAction::None && result.logs.size() == 1 &&
          result.triggers.size() == 1 &&
          result.triggers[0].type == wpe::FilterExecuteType::Send &&
          engine.Stats().filters[0].second == 1,
          "send trigger is reported without changing the packet action");

    auto cycle_a = parent;
    auto cycle_b = parent;
    cycle_a.id = wpe::Guid::Parse("c1112233-4455-6677-8899-aabbccddeeff");
    cycle_b.id = wpe::Guid::Parse("d1112233-4455-6677-8899-aabbccddeeff");
    cycle_a.execute_type = cycle_b.execute_type = 3;
    cycle_a.execute_id = cycle_b.id;
    cycle_b.execute_id = cycle_a.id;
    engine.Publish({cycle_a, cycle_b}, 0, false);
    result = engine.Apply(Context(), packet);
    Check(result.action == wpe::FilterAction::None && result.logs.empty(),
          "cyclic filter triggers stop without recursion or false execution");

    engine.ResetStats();
    auto published = Base("91112233-4455-6677-8899-aabbccddeeff");
    published.search = Text("0|10");
    published.modify = Text("1|11");
    engine.Publish({published}, 0, true);
    std::atomic<bool> concurrent_results_valid{true};
    std::vector<std::thread> readers;
    for (int i = 0; i < 4; ++i) {
        readers.emplace_back([&] {
            for (int packet_index = 0; packet_index < 2000; ++packet_index) {
                const auto concurrent = engine.Apply(Context(), packet);
                if (concurrent.action != wpe::FilterAction::Replace || concurrent.bytes.size() != packet.size() ||
                    (concurrent.bytes[1] != 0x11 && concurrent.bytes[1] != 0x22))
                    concurrent_results_valid.store(false, std::memory_order_relaxed);
            }
        });
    }
    for (int i = 0; i < 500; ++i) {
        published.modify = Text((i & 1) == 0 ? "1|11" : "1|22");
        engine.Publish({published}, 0, true);
    }
    for (auto& reader : readers) reader.join();
    Check(concurrent_results_valid.load(std::memory_order_relaxed),
          "atomic table publication remains valid under concurrent packet reads");
    stats = engine.Stats();
    Check(stats.filters.size() == 1 && stats.filters[0].second == 8000 &&
          stats.filters[0].second == stats.globals[0],
          "publication shares live item and global counters without divergent copies");
    engine.ResetStats();
    engine.Publish({published}, 0, true);
    stats = engine.Stats();
    Check(stats.filters[0].second == 0 && stats.globals[0] == 0,
          "publishing after reset cannot resurrect stale counter values");

    std::cout << "PASS: " << checks
              << " filter-engine checks; gates, wildcards, actions, progression, ordering and counters\n";
}
