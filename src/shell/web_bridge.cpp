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
void WebBridge::Register(std::string method,Handler handler){methods_[Key(std::move(method))]=std::move(handler);}
void WebBridge::Reply(const Json& id,bool ok,Json value,const std::string& error){
    Json message{{"type","result"},{"ok",ok}};
    if(!id.is_null())message["id"]=id;
    if(!value.is_null())message["result"]=std::move(value);
    if(!error.empty())message["error"]=error;
    post_(message.dump());
}
void WebBridge::Receive(std::string_view source,std::string_view raw){
    if(closed_ || !IsAllowedSource(source) || raw.size()>1024*1024)return;
    Json id;
    try {
        const auto message=Json::parse(raw);
        if(!message.is_object())return;
        if(message.contains("id") && message["id"].is_string())id=message["id"];
        const auto type=message.value("type",std::string{});
        if(type=="answer"){
            if(id.is_string())Complete(id.get<std::string>(),message.value("ok",false)?message.value("result",Json{}):Json{});
            return;
        }
        if(type!="call" || !id.is_string())return;
        const auto method=message.value("method",std::string{});
        const auto found=methods_.find(Key(method));
        if(found==methods_.end()){Reply(id,false,nullptr,"尚未实现的方法: "+method);return;}
        const auto args=message.value("args",Json::object());
        if(!args.is_null()&&!args.is_object())throw std::invalid_argument("args must be an object or null");
        const auto result=found->second(args.is_null()?Json::object():args);
        Reply(id,true,result);
    }catch(const std::exception& error){
        if(!id.is_null())try{Reply(id,false,nullptr,error.what());}catch(...){/* Transport is already closed. */}
    }
}
std::string WebBridge::Ask(std::string method,Json args,Answer answer,std::chrono::milliseconds timeout){
    if(closed_ || pending_.size()>=1024){if(answer)answer(nullptr);return {};}
    const auto id="a"+std::to_string(++sequence_);
    pending_.emplace(id,Pending{Clock::now()+timeout,std::move(answer)});
    Json message{{"type","ask"},{"id",id},{"method",std::move(method)}};
    if(!args.is_null())message["args"]=std::move(args);
    try{post_(message.dump());}catch(...){Complete(id,nullptr);}
    return id;
}
void WebBridge::Complete(const std::string& id,Json value){
    auto entry=pending_.extract(id);
    if(!entry.empty() && entry.mapped().complete)try{entry.mapped().complete(std::move(value));}catch(...){/* One failing UI consumer must not strand the rest. */}
}
void WebBridge::FailAllPending(){
    std::vector<std::string> ids;
    for(const auto& [id,pending]:pending_){(void)pending;ids.push_back(id);}
    for(const auto& id:ids)Complete(id,nullptr);
}
void WebBridge::Tick(Clock::time_point now){
    std::vector<std::string> expired;
    for(const auto& [id,pending]:pending_)if(pending.deadline<=now)expired.push_back(id);
    for(const auto& id:expired)Complete(id,nullptr);
}
void WebBridge::PushEvent(std::string name,Json data){
    if(closed_)return;
    Json message{{"type","event"},{"name",std::move(name)}};
    if(!data.is_null())message["data"]=std::move(data);
    post_(message.dump());
}
} // namespace wpe::shell
