#include "web_bridge.h"
#include <vector>

namespace wpe::shell {
WebBridge::WebBridge(Post post):post_(std::move(post)){}
WebBridge::~WebBridge(){closed_=true;FailAllPending();}
std::string WebBridge::Key(std::string value){for(char& c:value)if(c>='A'&&c<='Z')c=static_cast<char>(c-'A'+'a');return value;}
bool WebBridge::IsAllowedSource(std::string_view source){
    constexpr std::string_view origin="https://app.wpe64.local";
    if(source.size()<origin.size() || Key(std::string(source.substr(0,origin.size())))!=origin)return false;
    return source.size()==origin.size() || source[origin.size()]=='/';
}
void WebBridge::Register(std::string method,Handler handler){
    RegisterAsync(std::move(method),[handler=std::move(handler)](const Json& args,Completion done){done(handler(args),{});});
}
void WebBridge::RegisterAsync(std::string method,AsyncHandler handler){methods_[Key(std::move(method))]=std::move(handler);}
void WebBridge::Reply(const Json& id,bool ok,Json value,const std::string& error){
    Json message{{"type","result"},{"ok",ok}};
    if(!id.is_null())message["id"]=id;
    if(!value.is_null())message["result"]=std::move(value);
    if(!error.empty())message["error"]=error;
    post_(message.dump());
}
void WebBridge::Receive(std::string_view source,std::string_view raw){
    if(closed_ || !IsAllowedSource(source))return;
    Json id;
    try {
        const auto message=Json::parse(raw);
        if(!message.is_object())return;
        if(message.contains("id") && message["id"].is_string())id=message["id"];
        const auto type=message.value("type",std::string{});
        if(type=="answer"){
            if(id.is_string())Complete(id.get<std::string>(),message.value("ok",false)?message.value("result",Json{}):Json{},message.value("ok",false)?"":"界面未成功返回确认结果");
            return;
        }
        if(type!="call" || !id.is_string())return;
        const auto method=message.value("method",std::string{});
        const auto found=methods_.find(Key(method));
        if(found==methods_.end()){Reply(id,false,nullptr,"尚未实现的方法: "+method);return;}
        const auto args=message.value("args",Json::object());
        if(!args.is_null()&&!args.is_object())throw std::invalid_argument("args must be an object or null");
        auto once=std::make_shared<bool>(false);
        Completion done=[this,alive=std::weak_ptr(call_epoch_),once,id](Json result,std::string error){
            if(alive.expired()||*once)return;*once=true;
            try{Reply(id,error.empty(),std::move(result),error);}catch(...){/* Closing transport. */}
        };
        try{found->second(args.is_null()?Json::object():args,done);}
        catch(const std::exception& error){done(nullptr,error.what());}
    }catch(const std::exception& error){
        if(!id.is_null())try{Reply(id,false,nullptr,error.what());}catch(...){/* Transport is already closed. */}
    }
}
std::string WebBridge::Ask(std::string method,Json args,Answer answer,std::chrono::milliseconds timeout){
    return AskResult(std::move(method),std::move(args),[answer=std::move(answer)](Json value,std::string error){if(answer)answer(error.empty()?std::move(value):Json{});},timeout);
}
std::string WebBridge::AskResult(std::string method,Json args,Completion answer,std::chrono::milliseconds timeout){
    if(closed_||cancelling_){if(answer)try{answer(nullptr,"界面已关闭或正在取消");}catch(...){}return {};}
    const auto id="a"+std::to_string(++sequence_);
    pending_.emplace(id,Pending{Clock::now()+timeout,std::move(answer)});
    Json message{{"type","ask"},{"id",id},{"method",std::move(method)}};
    if(!args.is_null())message["args"]=std::move(args);
    try{post_(message.dump());}catch(...){Complete(id,nullptr,"无法发送界面请求");}
    return id;
}
void WebBridge::Complete(const std::string& id,Json value,std::string error){
    auto entry=pending_.extract(id);
    if(!entry.empty() && entry.mapped().complete)try{entry.mapped().complete(std::move(value),std::move(error));}catch(...){/* One failing UI consumer must not strand the rest. */}
}
void WebBridge::FailAllPending(){
    if(cancelling_)return;
    cancelling_=true;
    call_epoch_.reset();
    // Keep cancellation active while callbacks run: they may try to ask again.
    // Extracting the whole map needs no temporary ID allocations during shutdown.
    auto abandoned=std::move(pending_);
    pending_.clear();
    for(auto& [id,pending]:abandoned){
        (void)id;
        if(pending.complete)try{pending.complete(nullptr,"界面请求已取消");}catch(...){}
    }
    cancelling_=false;
    if(!closed_)call_epoch_=std::make_shared<int>(0);
}
void WebBridge::Tick(Clock::time_point now){
    std::vector<std::string> expired;
    for(const auto& [id,pending]:pending_)if(pending.deadline<=now)expired.push_back(id);
    for(const auto& id:expired)Complete(id,nullptr,"界面请求超时");
}
void WebBridge::PushEvent(std::string name,Json data){
    if(closed_)return;
    Json message{{"type","event"},{"name",std::move(name)}};
    if(!data.is_null())message["data"]=std::move(data);
    post_(message.dump());
}
WebBridge::Completion WebBridge::WithErrorToast(Completion done){
    return [this,epoch=std::weak_ptr(call_epoch_),done=std::move(done)](Json result,std::string error){
        if(!epoch.expired()&&!error.empty()){
            try{PushEvent("toast",{{"level",4},{"text",error}});}catch(...){/* The RPC completion below is independent. */}
        }
        done(std::move(result),std::move(error));
    };
}
} // namespace wpe::shell
