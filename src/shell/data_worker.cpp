#include "data_worker.h"
namespace wpe::shell {
DataWorker::DataWorker(std::filesystem::path database):thread_([this,database=std::move(database)]{Run(database);}){}
DataWorker::~DataWorker(){
    std::deque<Job> cancelled;
    {std::lock_guard lock(mutex_);stopping_=true;cancelled.swap(jobs_);}
    wake_.notify_one();if(thread_.joinable())thread_.join();
    // The active transaction has settled. Never run the remaining queue during
    // UI-thread teardown; a busy DB would multiply its wait by the queue size.
    for(auto& job:cancelled)try{job.done(nullptr,"退出：未开始的数据任务已取消");}catch(...){}
    for(auto& result:results_)try{result.done(std::move(result.value),std::move(result.error));}catch(...){}
}
void DataWorker::Submit(std::string method,Json args,WebBridge::Completion done){
    bool rejected=false;
    {std::lock_guard lock(mutex_);rejected=stopping_||jobs_.size()+results_.size()>=512;
        if(!rejected)jobs_.push_back({std::move(method),std::move(args),std::move(done)});}
    if(rejected){done(nullptr,"数据任务队列已满或正在退出，请稍后重试");return;}
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
        try{if(!service)throw std::runtime_error(startup_error);result.value=service->Call(job.method,job.args);}
        catch(const std::exception& e){result.error=e.what();}
        current=nullptr;{std::lock_guard lock(mutex_);results_.push_back(std::move(result));}
    }
}
}
