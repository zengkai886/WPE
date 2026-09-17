#include "clipboard_worker.h"
#include <stdexcept>
namespace wpe::shell {
ClipboardWorker::ClipboardWorker(bool isolatedMemory){
    wake_event_=CreateEventW(nullptr,FALSE,FALSE,nullptr);if(!wake_event_)throw std::runtime_error("Cannot create clipboard worker event");
    try{thread_=std::thread([this,isolatedMemory]{Run(isolatedMemory);});}catch(...){CloseHandle(wake_event_);throw;}
}
ClipboardWorker::~ClipboardWorker(){
    Cancel();{std::lock_guard lock(mutex_);stopping_=true;}SetEvent(wake_event_);
    if(thread_.joinable())thread_.join();Drain();CloseHandle(wake_event_);
}
void ClipboardWorker::Submit(bool write,std::wstring text,Done done){
    bool rejected=false;
    {std::lock_guard lock(mutex_);rejected=stopping_||outstanding_>=32;
        if(!rejected){jobs_.push_back({write,std::move(text),std::move(done),epoch_});++outstanding_;}}
    if(rejected){done(false,{});return;}SetEvent(wake_event_);
}
void ClipboardWorker::Cancel(){
    std::deque<Job> cancelled;
    {std::lock_guard lock(mutex_);++epoch_;cancelled.swap(jobs_);outstanding_-=cancelled.size();}
    SetEvent(wake_event_);for(auto& job:cancelled)try{job.done(false,{});}catch(...){}
}
void ClipboardWorker::Drain(){
    std::deque<Result> ready;std::uint64_t epoch=0;
    {std::lock_guard lock(mutex_);ready.swap(results_);outstanding_-=ready.size();epoch=epoch_;}
    for(auto& result:ready)try{const bool ok=result.epoch==epoch&&result.ok;result.done(ok,ok?std::move(result.text):std::wstring{});}catch(...){}
}
void ClipboardWorker::WaitForWork(DWORD milliseconds){
    // Clipboard owners receive sent messages even with immediate-render data.
    // Pump those while idle/retrying so another app's EmptyClipboard cannot hang.
    MsgWaitForMultipleObjectsEx(1,&wake_event_,milliseconds,QS_ALLINPUT,MWMO_INPUTAVAILABLE);
    MSG message{};while(PeekMessageW(&message,nullptr,0,0,PM_REMOVE)){TranslateMessage(&message);DispatchMessageW(&message);}
}
void ClipboardWorker::Run(bool isolatedMemory){
    // This worker owns the real clipboard window; the self-test memory seam
    // deliberately creates no window and never accesses the user's clipboard.
    const HWND owner=isolatedMemory?nullptr:CreateWindowExW(0,L"STATIC",L"WPE clipboard worker",0,0,0,0,0,HWND_MESSAGE,nullptr,nullptr,nullptr);
    std::wstring memory;
    for(;;){
        Job job;bool found=false;
        {std::lock_guard lock(mutex_);if(stopping_)break;if(!jobs_.empty()){job=std::move(jobs_.front());jobs_.pop_front();found=true;}}
        if(!found){WaitForWork(INFINITE);continue;}
        ClipboardStatus status=ClipboardStatus::error;std::wstring text;
        try{for(int attempt=0;attempt<10;++attempt){
            {std::lock_guard lock(mutex_);if(stopping_||job.epoch!=epoch_)break;}
            if(isolatedMemory){if(job.write)memory=job.text;else text=memory;status=ClipboardStatus::ok;}
            else if(owner)status=job.write?WriteClipboardText(owner,job.text):ReadClipboardText(owner,text);
            if(status!=ClipboardStatus::busy)break;
            const auto until=std::chrono::steady_clock::now()+std::chrono::milliseconds(100);
            while(std::chrono::steady_clock::now()<until){
                {std::lock_guard lock(mutex_);if(stopping_||job.epoch!=epoch_)break;}
                const auto left=std::chrono::duration_cast<std::chrono::milliseconds>(until-std::chrono::steady_clock::now()).count();
                if(left>0)WaitForWork(static_cast<DWORD>(left));
            }
        }}catch(...){status=ClipboardStatus::error;}
        {std::lock_guard lock(mutex_);results_.push_back({std::move(job.done),status==ClipboardStatus::ok,std::move(text),job.epoch});}
        WaitForWork(0); // Also service ownership messages during a busy queue.
    }
    if(owner)DestroyWindow(owner);
}
}
