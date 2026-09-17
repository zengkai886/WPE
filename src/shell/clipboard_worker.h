#pragma once
#include "clipboard.h"
#include <chrono>
#include <cstdint>
#include <functional>
#include <deque>
#include <mutex>
#include <thread>
namespace wpe::shell {
// UI-thread API. GetClipboardData may wait for another app's delayed renderer;
// keep that wait off the WebView thread. Shutdown waits for an active OS call.
class ClipboardWorker {
public:
    using Done=std::function<void(bool,std::wstring)>;
    explicit ClipboardWorker(bool isolatedMemory=false);
    ~ClipboardWorker();
    void Submit(bool write,std::wstring text,Done done);
    void Drain();
    void Cancel();
private:
    struct Job {bool write;std::wstring text;Done done;std::uint64_t epoch;};
    struct Result {Done done;bool ok;std::wstring text;std::uint64_t epoch;};
    void Run(bool isolatedMemory);
    void WaitForWork(DWORD milliseconds);
    std::mutex mutex_;
    HANDLE wake_event_{};
    std::deque<Job> jobs_;
    std::deque<Result> results_;
    std::uint64_t epoch_{};
    std::size_t outstanding_{};
    bool stopping_{};
    std::thread thread_;
};
}
