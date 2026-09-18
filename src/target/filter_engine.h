#pragma once

#include "headless_core.h"
#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <utility>
#include <vector>

namespace wpe {

enum class FilterAction : std::int32_t {
    Replace = 0,
    Intercept = 1,
    NoModifyDisplay = 2,
    NoModifyNoDisplay = 3,
    None = 4,
    Change = 5,
};

struct FilterContext {
    std::int64_t socket{};
    std::uint8_t packet_type{};
    std::array<std::uint16_t, 2> ports{};
    std::size_t port_count{};
};

struct FilterResult {
    FilterAction action{FilterAction::None};
    ByteBuffer bytes;
};

struct FilterLogRecord {
    Text name;
    FilterAction action{FilterAction::None};
    std::int32_t matches{};
    std::uint8_t packet_type{};
    std::int32_t packet_length{};
};

struct FilterStats {
    std::vector<std::pair<Guid, std::int64_t>> filters;
    std::array<std::int64_t, 6> globals{};
};

// A published table is immutable. Per-filter counters and progression state are
// atomics carried across snapshots by GUID, so packet threads never take a lock.
class FilterEngine final {
public:
    struct Table;
    using LogSink = std::function<void(const FilterLogRecord&)>;

    explicit FilterEngine(LogSink log_sink = {});
    ~FilterEngine();
    FilterEngine(const FilterEngine&) = delete;
    FilterEngine& operator=(const FilterEngine&) = delete;

    void Publish(const std::vector<FilterSnapshot>& filters,
                 std::int32_t execute_mode, bool speed_mode);
    [[nodiscard]] FilterResult Apply(const FilterContext& context,
                                     std::span<const std::uint8_t> bytes) noexcept;
    [[nodiscard]] FilterStats Stats() const noexcept;
    void ResetStats() noexcept;

private:
    // Packet threads only touch the reader count and an atomic raw pointer.
    // Publishers retain replaced tables until a quiescent point, then reclaim
    // them off the packet path.
    mutable std::atomic<std::uint32_t> readers_{};
    std::atomic<const Table*> table_{nullptr};
    std::unique_ptr<const Table> owned_table_;
    std::vector<std::unique_ptr<const Table>> retired_tables_;
    std::mutex publish_mutex_;
    LogSink log_sink_;
};

} // namespace wpe
