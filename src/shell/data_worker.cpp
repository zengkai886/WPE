#include "data_worker.h"
#include "common/ipc_protocol.h"
#include <algorithm>
#include <limits>
namespace wpe::shell {
DataWorker::DataWorker(std::filesystem::path database):thread_([this,database=std::move(database)]{Run(database);}){}
DataWorker::~DataWorker(){
    std::deque<Job> cancelled;
    {std::lock_guard lock(mutex_);stopping_=true;cancelled.swap(jobs_);}
    wake_.notify_one();if(thread_.joinable())thread_.join();
    // The active transaction has settled. Never run the remaining queue during
    // UI-thread teardown; a busy DB would multiply its wait by the queue size.
    for(auto& job:cancelled){
        {std::lock_guard lock(mutex_);if(job.store_event)store_event_bytes_-=job.store_event->size();}
        try{job.done(nullptr,"退出：未开始的数据任务已取消");}catch(...){}}
    for(auto& result:results_)try{result.done(std::move(result.value),std::move(result.error));}catch(...){}
}
void DataWorker::Submit(std::string method,Json args,WebBridge::Completion done){
    bool rejected=false;
    {std::lock_guard lock(mutex_);rejected=stopping_||jobs_.size()+results_.size()>=512;
        if(!rejected)jobs_.push_back({std::move(method),std::move(args),std::move(done),std::nullopt});}
    if(rejected){done(nullptr,"数据任务队列已满或正在退出，请稍后重试");return;}
    wake_.notify_one();
}
void DataWorker::SubmitStoreEvent(std::vector<std::uint8_t> frame,WebBridge::Completion done){
    const auto size=frame.size();
    std::vector<WebBridge::Completion> dropped;
    bool rejected=false;
    {std::lock_guard lock(mutex_);
        rejected=stopping_||size==0||size>static_cast<std::size_t>(wpe::IpcProtocol::MaxControlFrame);
        // Target events are telemetry: when their bounded queue is full,
        // evict the oldest queued target event (never an ordinary RPC) and
        // complete it with an explicit drop error before accepting the new one.
        while(!rejected && (jobs_.size()+results_.size()>=512 ||
              store_event_bytes_>16U*1024U*1024U-size)){
            const auto old=std::find_if(jobs_.begin(),jobs_.end(),
                [](const Job& item){return item.store_event.has_value();});
            if(old==jobs_.end()){rejected=true;break;}
            auto evicted=std::move(*old);
            store_event_bytes_-=evicted.store_event->size();
            jobs_.erase(old);
            ++dropped_store_events_;
            dropped.push_back(std::move(evicted.done));
        }
        if(!rejected){store_event_bytes_+=size;jobs_.push_back({{}, {}, std::move(done), std::move(frame)});}}
    for(auto& completion:dropped){try{completion(nullptr,"入库事件队列已满，已丢弃较旧事件");}catch(...) {}}
    if(rejected){done(nullptr,"入库事件队列已满、事件过大或正在退出，请稍后重试");return;}
    wake_.notify_one();
}
void DataWorker::SubmitTargetConfiguration(WebBridge::Completion done){
    Submit("__targetConfiguration",Json::object(),std::move(done));
}
void DataWorker::ForgetExportPlan(std::string token){ForgetPlan("__discardEditorExport",std::move(token));}
void DataWorker::ForgetImportPlan(std::string token){ForgetPlan("__discardImport",std::move(token));}
void DataWorker::ForgetPlan(std::string method,std::string token){
    if(token.empty())return;
    {std::lock_guard lock(mutex_);if(stopping_)return;
        jobs_.push_front({std::move(method),{{"token",std::move(token)}},[](Json,std::string){},std::nullopt});}
    wake_.notify_one();
}
void DataWorker::Drain(const DataService::Emit& emit){
    std::deque<Result> ready;{std::lock_guard lock(mutex_);ready.swap(results_);}
    for(auto& result:ready){
        for(auto& [name,data]:result.events){
            try{emit(std::move(name),std::move(data));}
            catch(const std::exception& e){if(result.error.empty())result.error="数据已提交，但界面更新失败："+std::string(e.what());}
            catch(...){if(result.error.empty())result.error="数据已提交，但界面更新失败";}
        }
        try{result.done(std::move(result.value),std::move(result.error));}catch(...){/* One consumer cannot strand other calls. */}
    }
}
void DataWorker::Run(const std::filesystem::path& path){
    std::unique_ptr<DataService> service;std::string startup_error;Result* current=nullptr;
    try{service=std::make_unique<DataService>(path,[&current](std::string name,Json data){if(current)current->events.emplace_back(std::move(name),std::move(data));});}
    catch(const std::exception& e){startup_error=e.what();}
    for(;;){
        Job job;{std::unique_lock lock(mutex_);wake_.wait(lock,[&]{return stopping_||!jobs_.empty();});
            if(jobs_.empty()&&stopping_)break;job=std::move(jobs_.front());jobs_.pop_front();}
        Result result;result.done=std::move(job.done);current=&result;
        try{
            if(!service)throw std::runtime_error(startup_error);
            if(job.store_event){
                const auto stored=service->ApplyStoreEvent(*job.store_event);
                result.value={{"ok",true},{"stored",stored}};
            }else if(job.method=="__targetConfiguration") result.value=service->TargetConfiguration();
            else result.value=service->Call(job.method,job.args);
        }
        catch(const StoreEventCommittedError& e){
            // SQLite and the worker-owned mirror are already committed. Keep
            // that fact in the completion payload while surfacing the feed
            // delivery failure to the host/UI.
            result.value={{"ok",true},{"stored",true},{"committed",true}};
            result.error=e.what();
        }
        catch(const std::exception& e){result.error=e.what();}
        current=nullptr;{std::lock_guard lock(mutex_);
            if(job.store_event)store_event_bytes_-=job.store_event->size();
            results_.push_back(std::move(result));}
    }
}
std::uint64_t DataWorker::DroppedStoreEventCount() const noexcept {
    std::lock_guard lock(mutex_);
    return dropped_store_events_;
}
}
