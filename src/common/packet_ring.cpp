#include "packet_ring.h"

namespace wpe {
std::int64_t PendingPacket::Size() const noexcept {
    std::int64_t size=64;
    if(raw) size+=static_cast<std::int64_t>(raw->size());
    if(modified && modified!=raw) size+=static_cast<std::int64_t>(modified->size());
    size+=static_cast<std::int64_t>(filter_logs.size()*sizeof(PendingFilterLog));
    for(const auto& log:filter_logs)
        if(log.name) size+=static_cast<std::int64_t>(log.name->size()*sizeof(char16_t));
    return size;
}
PacketRing::PacketRing(std::int32_t max_count,std::int64_t max_bytes):max_count_(max_count),max_bytes_(max_bytes) {}
void PacketRing::Enqueue(Item item) {
    if(!item) return;
    {
        std::lock_guard lock(mutex_);
        const auto size=item->Size();
        queue_.push_back(std::move(item));
        bytes_+=size;
        while((static_cast<std::int64_t>(queue_.size())>max_count_ || bytes_>max_bytes_) && queue_.size()>1) {
            bytes_-=queue_.front()->Size(); queue_.pop_front(); ++dropped_;
        }
        signaled_=true;
    }
    signal_.notify_all();
}
std::vector<PacketRing::Item> PacketRing::DequeueBatch(std::int32_t max_count,std::int64_t max_bytes,std::chrono::milliseconds wait) {
    if(wait.count() < -1) throw std::invalid_argument("Wait must be nonnegative or -1 for infinite");
    std::unique_lock lock(mutex_);
    if(queue_.empty()) {
        signaled_=false;
        const auto ready=[&] { return signaled_ || !queue_.empty(); };
        if(wait.count()==-1) signal_.wait(lock,ready);
        else signal_.wait_for(lock,wait,ready);
    }
    std::vector<Item> batch;
    std::int64_t taken=0;
    while(!queue_.empty() && static_cast<std::int64_t>(batch.size())<max_count && taken<max_bytes) {
        // Append before modifying the queue, so allocation failure loses no packet.
        batch.push_back(queue_.front());
        const auto size=queue_.front()->Size(); queue_.pop_front(); bytes_-=size; taken+=size;
    }
    return batch;
}
std::size_t PacketRing::Count() const { std::lock_guard lock(mutex_); return queue_.size(); }
std::uint64_t PacketRing::Dropped() const { std::lock_guard lock(mutex_); return dropped_; }
void PacketRing::Clear() { std::lock_guard lock(mutex_); queue_.clear(); bytes_=0; }
void PacketRing::Wake() { {std::lock_guard lock(mutex_); signaled_=true;} signal_.notify_all(); }
} // namespace wpe
