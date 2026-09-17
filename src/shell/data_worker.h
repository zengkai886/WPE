#pragma once
#include "data_service.h"
#include <condition_variable>
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
    void Drain(const DataService::Emit& emit); // Called by the host UI timer.
private:
    struct Job {std::string method;Json args;WebBridge::Completion done;};
    struct Result {WebBridge::Completion done;Json value;std::string error;std::vector<std::pair<std::string,Json>> events;};
    void Run(const std::filesystem::path& path);
    std::mutex mutex_;
    std::condition_variable wake_;
    std::deque<Job> jobs_;
    std::deque<Result> results_;
    bool stopping_{};
    std::thread thread_;
};
}
