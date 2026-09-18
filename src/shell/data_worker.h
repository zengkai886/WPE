#pragma once
#include "data_service.h"
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <mutex>
#include <thread>
namespace wpe::shell {
class DataWorker {
public:
    explicit DataWorker(std::filesystem::path database);
    ~DataWorker();
    DataWorker(const DataWorker&)=delete;
    DataWorker& operator=(const DataWorker&)=delete;
    void Submit(std::string method,Json args,WebBridge::Completion done);
    // Native target-event ingress. The event is committed by the worker and
    // never exposed as a browser-callable method.
    void SubmitStoreEvent(std::vector<std::uint8_t> frame,WebBridge::Completion done);
    void ForgetExportPlan(std::string token); // Internal cleanup cannot be rejected by the work-queue cap.
    void ForgetImportPlan(std::string token);
    void Drain(const DataService::Emit& emit); // Called by the host UI timer.
    [[nodiscard]] std::uint64_t DroppedStoreEventCount() const noexcept;
private:
    struct Job {std::string method;Json args;WebBridge::Completion done;std::optional<std::vector<std::uint8_t>> store_event;};
    struct Result {WebBridge::Completion done;Json value;std::string error;std::vector<std::pair<std::string,Json>> events;};
    void Run(const std::filesystem::path& path);
    void ForgetPlan(std::string method,std::string token);
    mutable std::mutex mutex_;
    std::condition_variable wake_;
    std::deque<Job> jobs_;
    std::deque<Result> results_;
    std::size_t store_event_bytes_{};
    std::uint64_t dropped_store_events_{};
    bool stopping_{};
    std::thread thread_;
};
}
