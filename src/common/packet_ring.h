#pragma once
#include "ipc_codec.h"
#include <array>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <vector>

namespace wpe {
struct PendingFilterLog {
    Text name;
    std::int32_t action{};
    std::int32_t matches{};
    std::uint8_t packet_type{};
    std::int32_t packet_length{};
};

struct PendingPacket {
    std::int64_t id{};
    std::int64_t time_ticks{};
    std::int64_t socket{};
    std::uint8_t packet_type{};
    std::uint8_t filter_action{};
    // Address bytes are captured by the detour; formatting belongs to the writer.
    std::array<std::uint8_t,128> socket_address{};
    std::size_t socket_address_length{};
    std::shared_ptr<const ByteBuffer> raw;
    std::shared_ptr<const ByteBuffer> modified;
    // Filter logs travel with the packet work item so a detour performs only
    // one bounded ring enqueue. Encoding and IPC delivery stay on the writer.
    std::vector<PendingFilterLog> filter_logs;
    bool suppress_packet{};
    std::int64_t Size() const noexcept;
};
class PacketRing {
public:
    using Item=std::shared_ptr<const PendingPacket>;
    explicit PacketRing(std::int32_t max_count=65536,std::int64_t max_bytes=64*1024*1024);
    // Short queue lock, never waits for consumer capacity or pipe I/O. Not lock-free.
    // Published packets and buffers must remain immutable for their full lifetime.
    void Enqueue(Item item);
    std::vector<Item> DequeueBatch(std::int32_t max_count,std::int64_t max_bytes,std::chrono::milliseconds wait);
    std::size_t Count() const;
    std::uint64_t Dropped() const;
    void Clear();
    void Wake();
    // Owner must wake/join all consumers before destroying the ring.
private:
    const std::int32_t max_count_;
    const std::int64_t max_bytes_;
    mutable std::mutex mutex_;
    std::condition_variable signal_;
    std::deque<Item> queue_;
    std::int64_t bytes_{};
    std::uint64_t dropped_{};
    bool signaled_{};
};
} // namespace wpe
