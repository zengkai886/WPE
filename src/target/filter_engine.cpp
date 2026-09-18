#include "filter_engine.h"
#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <limits>
#include <string>
#include <unordered_set>

namespace wpe {
namespace {

struct Condition {
    int position{};
    std::uint8_t value{};
    std::uint8_t mask{};
    bool partial{};
};

struct Modification { int position{}; std::uint8_t value{}; };
struct Range { int from{}; int to{}; };

class ReaderGuard final {
public:
    explicit ReaderGuard(std::atomic<std::uint32_t>& readers) noexcept : readers_(readers) {
        readers_.fetch_add(1);
    }
    ~ReaderGuard() { readers_.fetch_sub(1); }
    ReaderGuard(const ReaderGuard&) = delete;
    ReaderGuard& operator=(const ReaderGuard&) = delete;

private:
    std::atomic<std::uint32_t>& readers_;
};

std::string Narrow(const Text& value) {
    if (!value) return {};
    std::string result;
    result.reserve(value->size());
    for (const auto character : *value) {
        if (character > 0x7f) return {};
        result.push_back(static_cast<char>(character));
    }
    return result;
}

std::string_view Trim(std::string_view value) noexcept {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t' ||
           value.front() == '\r' || value.front() == '\n')) value.remove_prefix(1);
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t' ||
           value.back() == '\r' || value.back() == '\n')) value.remove_suffix(1);
    return value;
}

template<class F>
void Split(std::string_view value, char delimiter, F&& visitor) {
    while (true) {
        const auto position = value.find(delimiter);
        visitor(value.substr(0, position));
        if (position == std::string_view::npos) break;
        value.remove_prefix(position + 1);
    }
}

bool ParseInt(std::string_view value, int& result) noexcept {
    value = Trim(value);
    if (value.empty()) return false;
    const auto parsed = std::from_chars(value.data(), value.data() + value.size(), result);
    return parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size();
}

int Nibble(char value) noexcept {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

bool ParseHex(std::string_view value, std::uint8_t& result) noexcept {
    value = Trim(value);
    if (value.size() == 1) {
        const int low = Nibble(value[0]);
        if (low < 0) return false;
        result = static_cast<std::uint8_t>(low);
        return true;
    }
    if (value.size() != 2) return false;
    const int high = Nibble(value[0]);
    const int low = Nibble(value[1]);
    if (high < 0 || low < 0) return false;
    result = static_cast<std::uint8_t>((high << 4) | low);
    return true;
}

bool ParseMaskedHex(std::string_view value, Condition& condition) noexcept {
    value = Trim(value);
    if (value.size() != 2) return false;
    condition.value = 0;
    condition.mask = 0;
    if (value[0] != '*') {
        const int high = Nibble(value[0]);
        if (high < 0) return false;
        condition.value = static_cast<std::uint8_t>(high << 4);
        condition.mask = 0xf0;
    }
    if (value[1] != '*') {
        const int low = Nibble(value[1]);
        if (low < 0) return false;
        condition.value = static_cast<std::uint8_t>(condition.value | low);
        condition.mask = static_cast<std::uint8_t>(condition.mask | 0x0f);
    }
    condition.partial = condition.mask != 0xff;
    return true;
}

std::vector<int> ParsePositions(std::string_view value) {
    std::vector<int> result;
    Split(value, ',', [&](std::string_view part) {
        int position = 0;
        if (ParseInt(part, position) && position >= 0) result.push_back(position);
    });
    return result;
}

std::vector<Modification> ParseModifications(std::string_view value) {
    std::vector<Modification> result;
    Split(value, ',', [&](std::string_view part) {
        const auto pipe = part.find('|');
        if (pipe == std::string_view::npos || part.find('|', pipe + 1) != std::string_view::npos) return;
        int position = 0;
        std::uint8_t byte = 0;
        if (ParseInt(part.substr(0, pipe), position) &&
            ParseHex(part.substr(pipe + 1), byte)) result.push_back({position, byte});
    });
    return result;
}

std::vector<Condition> ParseConditions(std::string_view value, bool strict, bool& valid) {
    std::vector<Condition> result;
    valid = true;
    Split(value, ',', [&](std::string_view part) {
        part = Trim(part);
        if (part.empty()) return;
        const auto pipe = part.find('|');
        if (pipe == std::string_view::npos || pipe == 0 || pipe + 1 >= part.size() ||
            part.find('|', pipe + 1) != std::string_view::npos) { if (strict) valid = false; return; }
        Condition condition;
        if (!ParseInt(part.substr(0, pipe), condition.position) || condition.position < 0 ||
            !ParseMaskedHex(part.substr(pipe + 1), condition)) { if (strict) valid = false; return; }
        result.push_back(condition);
    });
    if (!valid) return {};
    return result;
}

std::vector<Range> ParseRanges(std::string_view value) {
    std::vector<Range> result;
    Split(value, ';', [&](std::string_view part) {
        part = Trim(part);
        if (part.empty()) return;
        const auto dash = part.find('-');
        int from = 0;
        int to = 0;
        if (dash == std::string_view::npos) {
            if (ParseInt(part, from)) result.push_back({from, from});
        } else if (ParseInt(part.substr(0, dash), from) &&
                   ParseInt(part.substr(dash + 1), to)) result.push_back({from, to});
    });
    return result;
}

std::vector<std::uint8_t> ParseHeader(std::string_view value) {
    std::string compact;
    compact.reserve(value.size());
    for (const char character : value)
        if (character != ' ' && character != '\t' && character != '\r' && character != '\n')
            compact.push_back(character);
    if (compact.empty() || (compact.size() % 2) != 0) return {};
    std::vector<std::uint8_t> result;
    result.reserve(compact.size() / 2);
    for (std::size_t i = 0; i < compact.size(); i += 2) {
        std::uint8_t byte = 0;
        if (!ParseHex(std::string_view(compact).substr(i, 2), byte)) return {};
        result.push_back(byte);
    }
    return result;
}

bool IsZero(const Guid& value) noexcept {
    return std::all_of(value.canonical.begin(), value.canonical.end(),
                       [](std::uint8_t byte) { return byte == 0; });
}

std::uint8_t RandomOther(std::uint8_t excluded) noexcept {
    static std::atomic<std::uint64_t> state{
        static_cast<std::uint64_t>(std::chrono::high_resolution_clock::now().time_since_epoch().count())};
    auto old = state.load(std::memory_order_relaxed);
    std::uint64_t next = 0;
    do {
        next = old;
        next ^= next << 13;
        next ^= next >> 7;
        next ^= next << 17;
    } while (!state.compare_exchange_weak(old, next, std::memory_order_relaxed));
    auto result = static_cast<std::uint8_t>(next);
    if (result == excluded) result = static_cast<std::uint8_t>(result + 1U);
    return result;
}

std::uint8_t StepByte(std::uint8_t value, std::int64_t step, int& carry) noexcept {
    const auto sum = static_cast<std::int64_t>(value) + step;
    carry = static_cast<int>(sum / 256);
    const auto wrapped = ((sum % 256) + 256) % 256;
    return static_cast<std::uint8_t>(wrapped);
}

} // namespace

struct FilterEngine::Table {
    struct RuntimeState {
        explicit RuntimeState(std::int64_t execution_count = 0,
                              std::int64_t progression = 0) noexcept
            : executions(execution_count), progression_count(progression) {}
        std::atomic<std::int64_t> executions{};
        std::atomic<std::int64_t> progression_count{};
    };

    struct GlobalState {
        std::array<std::atomic<std::int64_t>, 6> values{};
    };

    struct Item {
        FilterSnapshot source;
        std::vector<int> sockets;
        std::vector<Range> lengths;
        std::vector<Range> ports;
        std::vector<std::uint8_t> header;
        std::vector<Condition> search;
        bool search_present{};
        bool search_valid{true};
        std::unordered_set<int> excluded;
        std::vector<Modification> modifications;
        std::vector<int> progression_positions;
        std::vector<int> random_positions;
        std::shared_ptr<RuntimeState> runtime;
    };

    std::vector<std::shared_ptr<Item>> filters;
    std::shared_ptr<GlobalState> globals{std::make_shared<GlobalState>()};
    std::int32_t execute_mode{};
    bool speed_mode{};
};

FilterEngine::FilterEngine() {
    owned_table_ = std::make_unique<const Table>();
    table_.store(owned_table_.get());
}

FilterEngine::~FilterEngine() = default;

void FilterEngine::Publish(const std::vector<FilterSnapshot>& filters,
                           std::int32_t execute_mode, bool speed_mode) {
    const std::scoped_lock lock(publish_mutex_);
    const auto* old = table_.load();
    auto fresh = std::make_unique<Table>();
    fresh->execute_mode = execute_mode;
    fresh->speed_mode = speed_mode;
    // Counts are runtime state, not snapshot state. Sharing them prevents a
    // publisher from resurrecting stale values or losing concurrent updates.
    fresh->globals = old->globals;

    for (const auto& source : filters) {
        auto item = std::make_shared<Table::Item>();
        item->source = source;
        Split(Narrow(source.socket), ';', [&](std::string_view part) {
            int value = 0;
            if (ParseInt(part, value)) item->sockets.push_back(value);
        });
        item->lengths = ParseRanges(Narrow(source.length));
        item->ports = ParseRanges(Narrow(source.port));
        item->header = ParseHeader(Narrow(source.header));
        const auto search = Narrow(source.search);
        item->search_present = source.search && !source.search->empty();
        item->search_valid = !(item->search_present && search.empty() &&
                               std::any_of(source.search->begin(), source.search->end(),
                                           [](char16_t value) { return value > 0x7f; }));
        if (item->search_valid)
            item->search = ParseConditions(search, source.mode == 0, item->search_valid);
        for (const auto value : ParsePositions(Narrow(source.exclude_position)))
            item->excluded.insert(value);
        item->modifications = ParseModifications(Narrow(source.modify));
        item->progression_positions = ParsePositions(Narrow(source.progression_position));
        item->random_positions = ParsePositions(Narrow(source.random_position));
        const auto prior = std::find_if(old->filters.begin(), old->filters.end(),
            [&](const auto& candidate) { return candidate->source.id == source.id; });
        item->runtime = prior != old->filters.end()
            ? (*prior)->runtime
            : std::make_shared<Table::RuntimeState>(source.execution_count,
                                                    source.progression_count);
        fresh->filters.push_back(std::move(item));
    }
    const auto* fresh_pointer = fresh.get();
    retired_tables_.push_back(std::move(owned_table_));
    owned_table_ = std::move(fresh);
    table_.store(fresh_pointer);
    // Sequentially-consistent reader publication makes this quiescent check
    // safe: an older reader is counted, while a later reader can only acquire
    // the newly published table.
    if (readers_.load() == 0) retired_tables_.clear();
}

namespace {

bool InRanges(int value, const std::vector<Range>& ranges) noexcept {
    return std::any_of(ranges.begin(), ranges.end(),
        [&](const Range& range) { return value >= range.from && value <= range.to; });
}

std::size_t FunctionIndex(std::uint8_t type) noexcept {
    constexpr std::array<std::uint8_t, 17> map{0,0,1,1,2,2,3,3,4,5,6,6,7,8,9,10,11};
    return type < map.size() ? map[type] : static_cast<std::size_t>(-1);
}

bool Effective(const FilterEngine::Table::Item& item, const FilterContext& context,
               std::span<const std::uint8_t> bytes) noexcept {
    if (!item.source.enabled) return false;
    const auto function = FunctionIndex(context.packet_type);
    if (function >= item.source.functions.size() || !item.source.functions[function]) return false;
    if (item.source.appoint_socket &&
        std::find(item.sockets.begin(), item.sockets.end(), static_cast<int>(context.socket)) == item.sockets.end()) return false;
    if (item.source.appoint_port) {
        bool found = false;
        for (std::size_t i = 0; i < context.port_count && !found; ++i)
            found = InRanges(context.ports[i], item.ports);
        if (!found) return false;
    }
    if (item.source.appoint_length && !InRanges(static_cast<int>(bytes.size()), item.lengths)) return false;
    if (item.source.appoint_header &&
        (item.header.empty() || item.header.size() > bytes.size() ||
         !std::equal(item.header.begin(), item.header.end(), bytes.begin()))) return false;
    return true;
}

bool NormalMatch(const FilterEngine::Table::Item& item,
                 std::span<const std::uint8_t> bytes) noexcept {
    if (!item.search_present || !item.search_valid || bytes.empty()) return false;
    if (item.search.empty()) return true;
    for (const auto& condition : item.search) {
        if (condition.position < 0 || static_cast<std::size_t>(condition.position) >= bytes.size()) return false;
        const bool equal = (bytes[condition.position] & condition.mask) ==
                           (condition.value & condition.mask);
        if (item.excluded.contains(condition.position) ? equal : !equal) return false;
    }
    return true;
}

std::vector<int> AdvancedMatches(const FilterEngine::Table::Item& item,
                                 std::span<const std::uint8_t> bytes) {
    auto conditions = item.search;
    std::sort(conditions.begin(), conditions.end(),
              [](const Condition& left, const Condition& right) { return left.position < right.position; });
    std::vector<int> result;
    if (conditions.empty()) return result;
    const auto& first = conditions.front();
    for (int i = 0; i < static_cast<int>(bytes.size()); ++i) {
        // Preserve the original first-condition behavior: it is an exact byte
        // anchor even when the source contains a partial wildcard.
        if (bytes[static_cast<std::size_t>(i)] != first.value) continue;
        bool matched = true;
        int last = i;
        for (std::size_t j = 1; j < conditions.size(); ++j) {
            const auto& condition = conditions[j];
            const int index = i + condition.position - first.position;
            if (index < 0 || static_cast<std::size_t>(index) >= bytes.size()) { matched = false; break; }
            const bool equal = (bytes[static_cast<std::size_t>(index)] & condition.mask) ==
                               (condition.value & condition.mask);
            if (item.excluded.contains(condition.position) ? equal : !equal) { matched = false; break; }
            last = (std::max)(last, index);
        }
        if (matched) {
            result.push_back(i);
            if (item.source.start_from == 0) break;
            i = last;
        }
    }
    return result;
}

bool ApplyProgression(const FilterEngine::Table::Item& item, ByteBuffer& bytes,
                      int base, std::int64_t count) noexcept {
    bool changed = false;
    for (const int configured : item.progression_positions) {
        const int position = configured + (item.source.start_from == 1 ? base : 0);
        if (position < 0 || static_cast<std::size_t>(position) >= bytes.size()) continue;
        int carry = 0;
        bytes[static_cast<std::size_t>(position)] = StepByte(bytes[static_cast<std::size_t>(position)],
            static_cast<std::int64_t>(item.source.progression_step) * (count + 1), carry);
        changed = true;
        if (item.source.progression_carry && carry > 0) {
            for (int i = 0; i < item.source.progression_carry_number && carry > 0; ++i) {
                const int previous = position - i - 1;
                if (previous < 0) break;
                bytes[static_cast<std::size_t>(previous)] =
                    StepByte(bytes[static_cast<std::size_t>(previous)], carry, carry);
            }
        }
    }
    return changed;
}

bool ApplyReplace(const FilterEngine::Table::Item& item, ByteBuffer& bytes,
                  const std::vector<int>& matches) noexcept {
    bool changed = false;
    const auto progression = item.runtime->progression_count.load(std::memory_order_relaxed);
    const auto apply_at = [&](int base) {
        bool local = false;
        for (const auto& modification : item.modifications) {
            const int position = modification.position + (item.source.start_from == 1 ? base : 0);
            if (position < 0 || static_cast<std::size_t>(position) >= bytes.size()) continue;
            bytes[static_cast<std::size_t>(position)] = modification.value;
            local = true;
        }
        local |= ApplyProgression(item, bytes, base, progression);
        for (const int configured : item.random_positions) {
            const int position = configured + (item.source.start_from == 1 ? base : 0);
            if (position < 0 || static_cast<std::size_t>(position) >= bytes.size()) continue;
            auto& byte = bytes[static_cast<std::size_t>(position)];
            byte = RandomOther(byte);
            local = true;
        }
        return local;
    };
    if (item.source.mode == 0) changed = apply_at(0);
    else for (const int match : matches) changed = apply_at(match); // original keeps the final result
    if (changed && !item.progression_positions.empty() && item.source.progression_continuous)
        item.runtime->progression_count.fetch_add(1, std::memory_order_relaxed);
    return changed;
}

bool ApplyChange(const FilterEngine::Table::Item& item, ByteBuffer& bytes) {
    if (item.modifications.empty()) return false;
    int maximum = -1;
    for (const auto& modification : item.modifications) maximum = (std::max)(maximum, modification.position);
    if (maximum < 0) return false;
    bytes.assign(static_cast<std::size_t>(maximum) + 1, 0);
    for (const auto& modification : item.modifications)
        if (modification.position >= 0 && static_cast<std::size_t>(modification.position) < bytes.size())
            bytes[static_cast<std::size_t>(modification.position)] = modification.value;
    const auto progression = item.runtime->progression_count.load(std::memory_order_relaxed);
    const bool progressed = ApplyProgression(item, bytes, 0, progression);
    if (progressed && item.source.progression_continuous)
        item.runtime->progression_count.fetch_add(1, std::memory_order_relaxed);
    return !bytes.empty();
}

} // namespace

FilterResult FilterEngine::Apply(const FilterContext& context,
                                 std::span<const std::uint8_t> input) noexcept {
    FilterResult result;
    try {
        result.bytes.assign(input.begin(), input.end());
        ReaderGuard reader(readers_);
        const auto* table = table_.load();
        struct Outcome {
            bool applied{};
            FilterAction action{FilterAction::None};
        };
        std::array<Guid, 16> execution_stack{};
        const auto apply_item = [&](auto&& self, const std::shared_ptr<Table::Item>& item,
                                    std::size_t depth) -> Outcome {
            if (depth >= execution_stack.size()) return {};
            for (std::size_t i = 0; i < depth; ++i)
                if (execution_stack[i] == item->source.id) return {};
            execution_stack[depth] = item->source.id;

            if (!Effective(*item, context, result.bytes)) return {};
            std::vector<int> matches;
            const bool matched = item->source.mode == 0
                ? NormalMatch(*item, result.bytes)
                : !(matches = AdvancedMatches(*item, result.bytes)).empty();
            if (!matched) return {};

            bool applied = false;
            const auto action = static_cast<FilterAction>(item->source.action);
            switch (action) {
            case FilterAction::Replace: applied = ApplyReplace(*item, result.bytes, matches); break;
            case FilterAction::Change: applied = ApplyChange(*item, result.bytes); break;
            case FilterAction::Intercept:
            case FilterAction::NoModifyDisplay:
            case FilterAction::NoModifyNoDisplay: applied = true; break;
            default: break;
            }

            // Filter is the only trigger type whose executor belongs to this
            // P0 slice. Unsupported Send/Robot/WareHouse triggers must not be
            // reported as successful merely because their GUID is populated.
            if (item->source.execute && item->source.execute_type == 3 &&
                !IsZero(item->source.execute_id)) {
                const auto target = std::find_if(table->filters.begin(), table->filters.end(),
                    [&](const auto& candidate) {
                        return candidate->source.id == item->source.execute_id;
                    });
                if (target != table->filters.end())
                    applied = self(self, *target, depth + 1).applied || applied;
            }
            if (!applied) return {};

            item->runtime->executions.fetch_add(1, std::memory_order_relaxed);
            table->globals->values[0].fetch_add(1, std::memory_order_relaxed);
            std::size_t counter = table->globals->values.size();
            switch (action) {
            case FilterAction::Replace: counter = 1; break;
            case FilterAction::Change: counter = 2; break;
            case FilterAction::Intercept: counter = 3; break;
            case FilterAction::NoModifyDisplay: counter = 4; break;
            case FilterAction::NoModifyNoDisplay: counter = 5; break;
            default: break;
            }
            if (counter < table->globals->values.size())
                table->globals->values[counter].fetch_add(1, std::memory_order_relaxed);
            if (!table->speed_mode) {
                result.logs.push_back(PendingFilterLog{
                    item->source.name, static_cast<std::int32_t>(action),
                    static_cast<std::int32_t>(matches.empty() ? 1 : matches.size()),
                    context.packet_type, static_cast<std::int32_t>(input.size())});
            }
            return {true, action};
        };

        for (const auto& item : table->filters) {
            const auto outcome = apply_item(apply_item, item, 0);
            if (!outcome.applied) continue;
            result.action = outcome.action;
            const auto action = outcome.action;
            if (action != FilterAction::None &&
                (action == FilterAction::Intercept || action == FilterAction::Change ||
                 action == FilterAction::NoModifyDisplay ||
                 action == FilterAction::NoModifyNoDisplay || table->execute_mode == 0)) break;
        }
    } catch (...) {
        result.action = FilterAction::None;
        result.logs.clear();
        try { result.bytes.assign(input.begin(), input.end()); } catch (...) { result.bytes.clear(); }
    }
    return result;
}

FilterStats FilterEngine::Stats() const noexcept {
    FilterStats result;
    try {
        ReaderGuard reader(readers_);
        const auto* table = table_.load();
        result.filters.reserve(table->filters.size());
        for (const auto& item : table->filters)
            result.filters.emplace_back(item->source.id,
                item->runtime->executions.load(std::memory_order_relaxed));
        for (std::size_t i = 0; i < result.globals.size(); ++i)
            result.globals[i] = table->globals->values[i].load(std::memory_order_relaxed);
    } catch (...) {}
    return result;
}

void FilterEngine::ResetStats() noexcept {
    ReaderGuard reader(readers_);
    const auto* table = table_.load();
    for (const auto& item : table->filters)
        item->runtime->executions.store(0, std::memory_order_relaxed);
    for (auto& counter : table->globals->values) counter.store(0, std::memory_order_relaxed);
}

} // namespace wpe
