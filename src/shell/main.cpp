#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <windowsx.h>
#include <shellapi.h>
#include <shobjidl.h>
#include <shlobj.h>
#include <shlwapi.h>
#include <wininet.h>
#include <dwmapi.h>
#include <wrl.h>
#include <WebView2.h>
#include "web_bridge.h"
#include "data_worker.h"
#include "clipboard_worker.h"
#include "target_link.h"
#include "socks5_runtime.h"
#include "http_proxy_runtime.h"
#include "wpc_runtime.h"
#include "proxy_capture_filter.h"
#include "resource.h"
#include "common/ipc_codec.h"
#include "common/packet_frame.h"
#include <TlHelp32.h>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <iomanip>
#include <memory>
#include <sstream>
#include <deque>
#include <mutex>
#include <optional>
#include <unordered_set>
#include <atomic>
#include <array>
#include <cctype>
#include <map>
#include <string_view>

using Microsoft::WRL::Callback;
using Microsoft::WRL::ComPtr;
using wpe::shell::Json;
using wpe::shell::WebBridge;
namespace fs=std::filesystem;
namespace {
constexpr UINT app_ready=WM_APP+1, app_drag=WM_APP+2, app_test=WM_APP+3, app_failure=WM_APP+4, app_file=WM_APP+5, app_target=WM_APP+6;
constexpr wchar_t origin[]=L"https://app.wpe64.local/index.html";
void Check(HRESULT result,const char* operation){
    if(FAILED(result)){std::ostringstream text;text<<operation<<" HRESULT=0x"<<std::hex<<static_cast<unsigned long>(result);throw std::runtime_error(text.str());}
}
std::wstring Wide(std::string_view text){
    if(text.empty())return {};
    const auto count=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),nullptr,0);
    if(count==0)throw std::runtime_error("Invalid UTF-8");
    std::wstring result(static_cast<std::size_t>(count),L'\0');
    MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),result.data(),count);return result;
}
std::string Utf8(std::wstring_view text){
    if(text.empty())return {};
    const auto count=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),nullptr,0,nullptr,nullptr);
    if(count==0)throw std::runtime_error("Invalid UTF-16");
    std::string result(static_cast<std::size_t>(count),'\0');
    WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,text.data(),static_cast<int>(text.size()),result.data(),count,nullptr,nullptr);return result;
}
std::u16string U16(std::string_view text){
    const auto wide=Wide(text);return std::u16string(wide.begin(),wide.end());
}
std::string PacketTime(std::int64_t ticks){
    // The target sends .NET DateTime ticks in local time.  Convert the value
    // back to a fixed-width string matching the original PacketRow format:
    // HH:mm:ss:fffffff.  Invalid/zero timestamps are deliberately rendered
    // as an empty value instead of making one malformed packet break the feed.
    constexpr std::int64_t kFileTimeDateTimeTicks=504911232000000000LL;
    if(ticks<kFileTimeDateTimeTicks)return {};
    const auto file_ticks=static_cast<std::uint64_t>(ticks-kFileTimeDateTimeTicks);
    FILETIME local{};ULARGE_INTEGER value{};value.QuadPart=file_ticks;
    local.dwLowDateTime=value.LowPart;local.dwHighDateTime=value.HighPart;
    SYSTEMTIME time{};if(!FileTimeToSystemTime(&local,&time))return {};
    std::ostringstream out;out<<std::setfill('0')<<std::setw(2)<<time.wHour<<':'
        <<std::setw(2)<<time.wMinute<<':'<<std::setw(2)<<time.wSecond<<':'
        <<std::setw(7)<<(file_ticks%10000000ULL);return out.str();
}
std::string LogTime(){
    SYSTEMTIME now{};GetLocalTime(&now);
    std::ostringstream out;out<<std::setfill('0')<<std::setw(2)<<now.wHour<<':'
        <<std::setw(2)<<now.wMinute<<':'<<std::setw(2)<<now.wSecond<<':'
        <<std::setw(7)<<static_cast<unsigned>(now.wMilliseconds)*10000U;return out.str();
}
std::int64_t NowPacketTicks(){
    FILETIME file_time{};GetSystemTimeAsFileTime(&file_time);
    ULARGE_INTEGER value{};value.LowPart=file_time.dwLowDateTime;value.HighPart=file_time.dwHighDateTime;
    // .NET ticks are 100 ns units since 0001-01-01; FILETIME uses the same
    // unit since 1601-01-01.
    return 504911232000000000LL+static_cast<std::int64_t>(value.QuadPart/100ULL);
}
std::string PacketHex(const wpe::Bytes& bytes,std::size_t limit=60){
    if(!bytes)return {};
    const char digits[]="0123456789ABCDEF";std::string out;
    for(std::size_t i=0;i<std::min(bytes->size(),limit);++i){
        if(i)out+=' ';out+=digits[(*bytes)[i]>>4];out+=digits[(*bytes)[i]&15];
    }
    if(bytes->size()>limit)out+=" ...";return out;
}

/*
  Proxy capture filtering lives in the native host, not in the Vue table.
  ProxyPacket rows are produced on the Winsock worker and the browser only
  receives rows that passed this gate.  Keeping the gate here also means the
  selected row and its byte detail use the same set of packets.
*/
std::string CompactHex(std::string_view text){
    std::string out;
    for(const auto c:text){
        if(std::isspace(static_cast<unsigned char>(c))||c==','||c==';')continue;
        if(!std::isxdigit(static_cast<unsigned char>(c)))return {};
        out.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
    }
    if(out.empty()||(out.size()%2)!=0)return {};
    return out;
}
bool HexBytes(std::string_view text,std::vector<std::uint8_t>& out){
    const auto compact=CompactHex(text);
    if(compact.empty())return false;
    out.clear();out.reserve(compact.size()/2);
    for(std::size_t i=0;i<compact.size();i+=2){
        const auto digit=[](char c)->int{
            if(c>='0'&&c<='9')return c-'0';
            if(c>='A'&&c<='F')return c-'A'+10;
            return -1;
        };
        const int hi=digit(compact[i]),lo=digit(compact[i+1]);
        if(hi<0||lo<0)return false;
        out.push_back(static_cast<std::uint8_t>((hi<<4)|lo));
    }
    return true;
}
std::vector<std::string_view> FilterHexAlternatives(std::string_view text){
    // The original capture filter treats ';' as an OR separator for packet
    // data and headers. Keep it out of HexBytes: concatenating alternatives
    // such as "01 00;FF EE" would turn two rules into one impossible value.
    std::vector<std::string_view> result;
    std::size_t begin=0;
    while(begin<=text.size()){
        const auto end=text.find(';',begin);
        const auto part=text.substr(begin,end==std::string_view::npos?text.size()-begin:end-begin);
        const auto first=part.find_first_not_of(" \t\r\n");
        if(first!=std::string_view::npos){
            const auto last=part.find_last_not_of(" \t\r\n");
            result.push_back(part.substr(first,last-first+1));
        }
        if(end==std::string_view::npos)break;
        begin=end+1;
    }
    return result;
}
bool ContainsBytes(std::span<const std::uint8_t> hay,std::span<const std::uint8_t> needle){
    if(needle.empty()||needle.size()>hay.size())return false;
    return std::search(hay.begin(),hay.end(),needle.begin(),needle.end())!=hay.end();
}
std::vector<std::string> FilterParts(std::string_view text){
    std::vector<std::string> parts;std::string current;
    for(const auto c:text){
        if(c==','||c==';'||std::isspace(static_cast<unsigned char>(c))){
            if(!current.empty()){parts.push_back(std::move(current));current.clear();}
        }else current.push_back(c);
    }
    if(!current.empty())parts.push_back(std::move(current));
    return parts;
}
bool NumberInList(std::string_view text,std::int64_t value){
    for(const auto& part:FilterParts(text)){
        std::istringstream in(part);std::int64_t n{};char extra{};
        if((in>>n)&&!(in>>extra)&&n==value)return true;
    }
    return false;
}
bool LengthMatches(std::string_view text,std::int64_t value){
    const auto trimmed=std::string(text);
    const auto dash=trimmed.find('-');
    try{
        if(dash==std::string::npos)return std::stoll(trimmed)==value;
        const auto lo=std::stoll(trimmed.substr(0,dash)),hi=std::stoll(trimmed.substr(dash+1));
        return lo<=value&&value<=hi;
    }catch(...){return false;}
}
bool AddressHasIp(std::string_view address,std::string_view wanted){
    if(wanted.empty())return false;
    if(address==wanted)return true;
    if(address.size()>wanted.size()&&address.compare(0,wanted.size(),wanted)==0){
        const auto next=address[wanted.size()];
        if(next==':'||next==']')return true;
    }
    return false;
}
bool AddressHasPort(std::string_view address,std::string_view wanted){
    const auto parts=FilterParts(wanted);
    for(const auto& part:parts){
        std::string tail(address);
        if(!tail.empty()&&tail.back()==']')continue;
        const auto colon=tail.rfind(':');
        if(colon==std::string::npos)continue;
        std::istringstream in(part);std::int64_t port{};char extra{};
        if((in>>port)&&!(in>>extra)&&std::to_string(port)==tail.substr(colon+1))return true;
    }
    return false;
}
bool TypeMatches(const Json& filter,std::uint8_t type){
    const auto enabled=[&](const char* key){return filter.value(key,false);};
    // Keep the original FilterFunction mapping exact.  The four proxy types
    // are not a generic "request/response" bucket, and HTTP/HTTPS rows do
    // not implicitly match TCP_Req/TCP_Resp in the C# implementation.
    switch(type){
    case 0:case 1:return enabled("send");
    case 2:case 3:return enabled("sendTo");
    case 4:case 5:return enabled("recv");
    case 6:case 7:return enabled("recvFrom");
    case 8:return enabled("wsaSend");
    case 9:return enabled("wsaSendTo");
    case 10:case 11:return enabled("wsaRecv");
    case 12:return enabled("wsaRecvFrom");
    case 13:return enabled("tcpReq");
    case 14:return enabled("udpReq");
    case 15:return enabled("tcpResp");
    case 16:return enabled("udpResp");
    default:return false;
    }
}
std::string Base64(std::span<const std::uint8_t> bytes){
    static constexpr char alphabet[]="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;out.reserve((bytes.size()+2)/3*4);
    for(std::size_t i=0;i<bytes.size();i+=3){
        const auto a=bytes[i];const auto b=i+1<bytes.size()?bytes[i+1]:0;const auto c=i+2<bytes.size()?bytes[i+2]:0;
        out+=alphabet[a>>2];out+=alphabet[((a&3)<<4)|(b>>4)];
        out+=i+1<bytes.size()?alphabet[((b&15)<<2)|(c>>6)]:'=';
        out+=i+2<bytes.size()?alphabet[c&63]:'=';
    }
    return out;
}
std::vector<std::uint8_t> Unbase64(std::string_view text){
    std::string input;for(const auto c:text)if(c!=' '&&c!='\r'&&c!='\n'&&c!='\t')input+=c;
    if(input.empty())return {};
    auto value=[](char c){return c>='A'&&c<='Z'?c-'A':c>='a'&&c<='z'?c-'a'+26:c>='0'&&c<='9'?c-'0'+52:c=='+'?62:c=='/'?63:-1;};
    if(input.size()%4!=0)return {};
    std::vector<std::uint8_t> out;out.reserve(input.size()/4*3);
    for(std::size_t i=0;i<input.size();i+=4){const int a=value(input[i]),b=value(input[i+1]);const int c=input[i+2]=='='?-1:value(input[i+2]),d=input[i+3]=='='?-1:value(input[i+3]);if(a<0||b<0||c<-1||d<-1)return {};out.push_back(static_cast<std::uint8_t>((a<<2)|(b>>4)));if(c>=0){out.push_back(static_cast<std::uint8_t>((b<<4)|(c>>2)));if(d>=0)out.push_back(static_cast<std::uint8_t>((c<<6)|d));}}
    return out;
}
std::string PacketText(const wpe::Text& text){
    return text?Utf8(std::wstring(text->begin(),text->end())):std::string{};
}
bool ValidInstancePath(const fs::path& path){
    if(path.empty()||!path.is_absolute())return false;
    const auto text=path.wstring();
    for(std::size_t i=0;i<text.size();++i){
        const auto c=text[i];
        if(c==L'<'||c==L'>'||c==L'"'||c==L'|'||c==L'?'||c==L'*')return false;
        if(c==L':'&&!(i==1&&((text[0]>=L'A'&&text[0]<=L'Z')||(text[0]>=L'a'&&text[0]<=L'z'))))return false;
    }
    return true;
}
Json ProbeInstancePath(const fs::path& root,const fs::path& current){
    std::error_code ec;const auto normalized=root.lexically_normal();
    const auto version=normalized/L"2.3.0";const auto db=version/L"WPE.db";
    const bool valid=ValidInstancePath(normalized);
    const bool dir_exists=valid&&fs::is_directory(normalized,ec);ec.clear();
    const bool file_exists=valid&&fs::is_regular_file(db,ec);ec.clear();
    std::int64_t size=0,current_size=0;
    if(file_exists){const auto bytes=fs::file_size(db,ec);if(!ec)size=static_cast<std::int64_t>(bytes);ec.clear();}
    const auto current_db=current/L"2.3.0"/L"WPE.db";
    if(fs::is_regular_file(current_db,ec)){const auto bytes=fs::file_size(current_db,ec);if(!ec)current_size=static_cast<std::int64_t>(bytes);}
    return {{"valid",valid},{"full",Utf8(normalized.wstring())},{"dirExists",dir_exists},
            {"fileExists",file_exists},{"size",size},{"modified",file_exists?"已存在":""},
            {"current",Utf8(current.lexically_normal().wstring())},{"currentSize",current_size}};
}
struct CoString {LPWSTR value{};~CoString(){CoTaskMemFree(value);} };
bool IsAdmin(){
    SID_IDENTIFIER_AUTHORITY authority=SECURITY_NT_AUTHORITY;
    PSID sid=nullptr;BOOL member=FALSE;
    if(AllocateAndInitializeSid(&authority,2,SECURITY_BUILTIN_DOMAIN_RID,DOMAIN_ALIAS_RID_ADMINS,0,0,0,0,0,0,&sid)){
        CheckTokenMembership(nullptr,sid,&member);FreeSid(sid);
    }
    return member!=FALSE;
}
struct Options {fs::path assets,data,report;bool test{};};
Options Arguments(){
    std::wstring path(32768,L'\0');const auto count=GetModuleFileNameW(nullptr,path.data(),static_cast<DWORD>(path.size()));
    if(count==0||count==path.size())throw std::runtime_error("Cannot determine executable path");path.resize(count);
    const auto folder=fs::path(path).parent_path();
    Options result{folder/L"wwwroot",folder/L"runtime",{},false};
    bool assets_explicit=false;
    int argc=0;auto argv=CommandLineToArgvW(GetCommandLineW(),&argc);
    if(!argv)throw std::runtime_error("Cannot read command line");
    std::unique_ptr<wchar_t*,decltype(&LocalFree)> owner(argv,LocalFree);
    for(int i=1;i<argc;++i){
        const std::wstring arg=argv[i];
        if(i+1>=argc)throw std::runtime_error("Expected a value after command option");
        if(arg==L"--assets"){result.assets=argv[++i];assets_explicit=true;}
        else if(arg==L"--data-dir")result.data=argv[++i];
        else if(arg==L"--self-test"){result.test=true;result.report=argv[++i];}
        else throw std::runtime_error("Unknown option");
    }
    result.assets=fs::absolute(result.assets);result.data=fs::absolute(result.data);
    // A developer build keeps wwwroot at the repository root while the
    // executable lives in build/<config>.  Make a direct double-click work
    // without requiring a fragile command-line --assets override.  An
    // explicit --assets remains authoritative and still fails loudly when it
    // points at an invalid package.
    if(!assets_explicit&&!fs::is_regular_file(result.assets/L"index.html")){
        const auto candidates={folder.parent_path()/L"wwwroot",folder.parent_path().parent_path()/L"wwwroot"};
        for(const auto& candidate:candidates){
            if(fs::is_regular_file(candidate/L"index.html")){result.assets=fs::absolute(candidate);break;}
        }
    }
    if(!fs::is_regular_file(result.assets/L"index.html"))throw std::runtime_error("Missing original wwwroot/index.html; use --assets");
    if(result.test){result.report=fs::absolute(result.report);fs::create_directories(result.report);}
    fs::create_directories(result.data);
    return result;
}
std::string StartupEnvironmentError(const Options& options){
    std::vector<std::string> errors;
    std::error_code ec;
    if(!fs::is_regular_file(options.assets/L"index.html",ec))
        errors.emplace_back("前端资源缺失：未找到 wwwroot\\index.html。请完整解压发布包，不要只复制 EXE。");
    ec.clear();
    if(!fs::is_directory(options.assets/L"assets",ec))
        errors.emplace_back("前端资源不完整：未找到 wwwroot\\assets 目录。");

    LPWSTR version=nullptr;
    const HRESULT runtime_hr=GetAvailableCoreWebView2BrowserVersionString(nullptr,&version);
    const bool runtime_ok=SUCCEEDED(runtime_hr)&&version&&*version;
    if(!runtime_ok){
        std::ostringstream text;
        text<<"未检测到 Microsoft Edge WebView2 Runtime（x64）。请在服务器安装 WebView2 Runtime 后再启动。";
        if(FAILED(runtime_hr))text<<" HRESULT=0x"<<std::hex<<static_cast<unsigned long>(runtime_hr);
        errors.push_back(text.str());
    }
    if(version)CoTaskMemFree(version);

    ec.clear();
    fs::create_directories(options.data,ec);
    if(ec){
        errors.push_back("数据目录不可写："+Utf8(options.data.wstring())+
                         "。请把程序放到本地磁盘，或使用可写的用户目录启动。");
    }else{
        const auto probe=options.data/(L".startup-write-"+std::to_wstring(GetCurrentProcessId()));
        HANDLE file=CreateFileW(probe.c_str(),GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                                nullptr,CREATE_ALWAYS,FILE_ATTRIBUTE_TEMPORARY|FILE_FLAG_DELETE_ON_CLOSE,nullptr);
        if(file==INVALID_HANDLE_VALUE){
            errors.push_back("数据目录不可写："+Utf8(options.data.wstring())+
                             "。请换到当前用户可写目录后再启动。");
        }else CloseHandle(file);
    }
    if(errors.empty())return {};
    std::string result="WPE-陈北玄 启动环境检查失败：\n\n";
    for(std::size_t i=0;i<errors.size();++i){
        result+="• "+errors[i];
        if(i+1<errors.size())result+='\n';
    }
    result+="\n\n请修复以上项目后重新打开程序。";
    return result;
}
class Host {
public:
    explicit Host(Options options):options_(std::move(options)),exit_code_(options_.test?1:0){}
    ~Host(){
        closing_=true;lifetime_.reset();
        packet_send_running_=false;send_running_=false;
        for(const auto id:hotkey_ids_)if(id)UnregisterHotKey(window_,id);
        if(http_proxy_)http_proxy_->Stop();
        if(proxy_)proxy_->Stop();
        if(wpc_)wpc_->Stop();
        {
            std::lock_guard lock(proxy_clients_mutex_);
            proxy_clients_.clear();
        }
        {
            std::lock_guard lock(proxy_connections_mutex_);
            proxy_connections_.clear();
        }
        if(target_)target_->Stop();
        clipboard_.reset();data_.reset();
        // Complete callbacks while the report/window state they capture still exists.
        if(bridge_){bridge_->FailAllPending();bridge_.reset();}
        if(controller_)controller_->Close();
        if(IsWindow(window_))DestroyWindow(window_);
    }
    int Run();
private:
    struct ProxyCapture { wpe::Packet packet; std::string client_addr; std::string server_addr; std::string server_domain; std::uint8_t domain_type{}; };
    static LRESULT CALLBACK WindowProc(HWND window,UINT message,WPARAM wparam,LPARAM lparam);
    LRESULT Message(UINT message,WPARAM wparam,LPARAM lparam);
    template<class F> HRESULT Guard(F&& action){try{action();return S_OK;}catch(const std::exception& e){Fail(e.what());return E_FAIL;}}
    void Initialize();
    void Configure();
    void RegisterMethods();
    void Resize();
    void State();
    void Script(const std::wstring& script);
    void BeginTest();
    void CaptureAndFinish();
    void Fail(const std::string& message);
    void Finish(bool success);
    void PickImportFile();
    void CancelFileJobs();
    void DiscardExport(const Json& plan){if(data_&&plan.is_object()&&plan.contains("token"))data_->ForgetExportPlan(plan.at("token").get<std::string>());}
    void DrainClipboard();
    void DrainTarget();
    void DrainProxy();
    void QueueTargetFrame(wpe::ByteBuffer frame,bool packet_channel);
    void QueueProxyPacket(wpe::shell::ProxyPacket packet);
    void QueueTargetResult(WebBridge::Completion done,Json value,std::string error);
    void AbortTargetInjection(WebBridge::Completion done,std::string error);
    void HandleTargetFrame(wpe::ByteBuffer frame,bool packet_channel);
    Json PacketRow(const wpe::Packet& packet) const;
    Json ProxyPacketRow(const ProxyCapture& packet) const;
    Json PacketDetail(const wpe::Packet& packet) const;
    const wpe::Packet* FindPacket(std::int64_t id) const;
    const wpe::Packet* FindProxyPacket(std::int64_t id) const;
    wpe::Packet* FindPacketMutable(std::int64_t id);
    ProxyCapture* FindProxyCaptureMutable(std::int64_t id);
    void ClearCapturedPackets();
    void ClearProxyPackets();
    void RefreshProxyCaptureFilter();
    struct ProxyFilterEvidence {
        bool header_match{};
        bool type_match{};
    };
    bool ProxyCaptureAllowed(const wpe::shell::ProxyPacket& packet,
                             ProxyFilterEvidence* evidence=nullptr) const;
    void SyncTargetConfiguration(WebBridge::Completion done);
    bool ApplyProxyRuntimeConfiguration(const Json& config, bool allow_start, Json& result, std::string& error);
    void AppendSystemLog(std::string module,std::string content);
    void AppendProxyLog(std::string user,std::string ip,std::string content);
    void QueueProxyClientEvent(wpe::shell::ProxyClientEvent event);
    Json ProxyClientRows() const;
    void QueueProxyConnectionEvent(wpe::shell::ProxyConnectionEvent event);
    void RefreshAccountOnline();
    bool StartWpc(const Json& setting,const Json& snapshot,std::string& error);
    std::filesystem::path HookDll() const;
    std::filesystem::path X86HookDll() const;
    std::filesystem::path X86Helper() const;
    Json InjectStatus() const;
    Json InjectStats() const;
    Json EnumerateProcesses() const;
    void RememberInjection(DWORD pid,const fs::path& path,const std::string& method,const std::wstring& args);
    void RegisterTargetMethods();
    std::unique_ptr<wpe::shell::ClipboardWorker> clipboard_;
    struct FileJob {std::string method;Json args;WebBridge::Completion done;Json export_plan=nullptr;Json file_info=nullptr;};
    void BeginImport(FileJob job,const fs::path& path,std::uint64_t epoch);
    void ReleaseImport(const std::string& token){if(data_)data_->ForgetImportPlan(token);if(token==import_token_){import_token_.clear();import_path_.clear();}}
    std::string import_token_,import_path_;
    std::deque<FileJob> file_jobs_;
    ComPtr<IFileDialog> file_dialog_;
    std::uint64_t file_epoch_{};
    bool test_cancel_file_{},test_encrypted_import_{},file_prompt_pending_{};
    Options options_;
    HWND window_{};
    ComPtr<ICoreWebView2Environment> environment_;
    ComPtr<ICoreWebView2Controller> controller_;
    ComPtr<ICoreWebView2> view_;
    std::unique_ptr<WebBridge> bridge_;
    std::unique_ptr<wpe::shell::DataWorker> data_;
    std::unique_ptr<wpe::shell::Socks5Runtime> proxy_;
    std::unique_ptr<wpe::shell::HttpProxyRuntime> http_proxy_;
    std::unique_ptr<wpe::shell::WpcRuntime> wpc_;
    bool wpc_refresh_pending_{};
    std::string proxy_display_host_="127.0.0.1";
    std::unordered_set<std::string> last_online_accounts_;
    std::unique_ptr<wpe::shell::TargetLink> target_;
    struct TargetResult {WebBridge::Completion done;Json value;std::string error;};
    std::mutex target_mutex_;
    std::deque<std::pair<wpe::ByteBuffer,bool>> target_frames_;
    std::deque<TargetResult> target_results_;
    std::mutex proxy_mutex_;
    std::deque<wpe::shell::ProxyPacket> proxy_frames_;
    mutable std::mutex proxy_clients_mutex_;
    std::unordered_map<std::string, wpe::shell::ProxyClientEvent> proxy_clients_;
    mutable std::mutex proxy_connections_mutex_;
    std::unordered_map<std::string, wpe::shell::ProxyConnectionEvent> proxy_connections_;
    // Injected packets are runtime data, not database rows.  Keep the same
    // bounded mirror the UI list consumes so selecting a row can fetch its
    // before/after bytes without crossing the IPC channel a second time.
    std::deque<wpe::Packet> packet_capture_;
    std::deque<ProxyCapture> proxy_capture_;
    // JavaScript Numbers are exact only through 2^53-1.  The old 1<<60
    // seed made every nearby proxy id round to the same value in WebView2,
    // so one click appeared to select every row and details pointed at the
    // wrong packet.  Proxy and injected feeds already have separate id
    // namespaces; a small, safe integer is the correct boundary here.
    std::int64_t next_proxy_packet_id_{1};
    mutable std::mutex proxy_filter_mutex_;
    Json proxy_capture_filter_=Json::object();
    std::atomic<std::uint64_t> proxy_filter_dropped_{};
    struct ProxyFilterDiagnostics {
        std::atomic<std::uint64_t> seen{};
        std::atomic<std::uint64_t> header_matches{};
        std::atomic<std::uint64_t> type_matches{};
        std::atomic<std::uint64_t> allowed{};
        std::atomic<std::uint64_t> tcp_requests{};
        std::atomic<std::uint64_t> tcp_responses{};
        std::atomic<std::uint64_t> udp_requests{};
        std::atomic<std::uint64_t> udp_responses{};
        std::atomic<std::uint64_t> other{};
        void Reset() noexcept {
            seen.store(0,std::memory_order_relaxed);
            header_matches.store(0,std::memory_order_relaxed);
            type_matches.store(0,std::memory_order_relaxed);
            allowed.store(0,std::memory_order_relaxed);
            tcp_requests.store(0,std::memory_order_relaxed);
            tcp_responses.store(0,std::memory_order_relaxed);
            udp_requests.store(0,std::memory_order_relaxed);
            udp_responses.store(0,std::memory_order_relaxed);
            other.store(0,std::memory_order_relaxed);
        }
    } proxy_filter_diagnostics_;
    Json target_stats_=Json::object();
    Json last_inject_=nullptr;
    std::int64_t system_socket_{};
    bool send_running_{},hook_running_{};
    std::atomic_bool packet_send_running_{};
    mutable std::mutex send_progress_mutex_;
    Json send_progress_=Json{{"Running",false},{"Index",-1},{"Total",0},{"Success",0},{"Fail",0}};
    std::array<int,12> hotkey_ids_{};
    // Borderless windows do not get DefWindowProc's WS_THICKFRAME resize
    // loop.  Keep a small native resize session so removing that style does
    // not remove the user's edge/corner resize gestures.
    WPARAM resize_hit_{};
    POINT resize_origin_{};
    RECT resize_window_{};
    bool native_drag_{},ready_{},revealed_{},closing_{},done_{},failure_posted_{};
    int exit_code_;
    std::uint64_t messages_{};
    Json report_=Json::object();
    std::chrono::steady_clock::time_point started_=std::chrono::steady_clock::now();
    // All WebView2 callbacks run on this STA. Expiration guards queued completions
    // after the host is destroyed, without creating a host/controller reference cycle.
    std::shared_ptr<int> lifetime_=std::make_shared<int>(0);
};
LRESULT CALLBACK Host::WindowProc(HWND window,UINT message,WPARAM wparam,LPARAM lparam){
    Host* self=reinterpret_cast<Host*>(GetWindowLongPtrW(window,GWLP_USERDATA));
    if(message==WM_NCCREATE){self=static_cast<Host*>(reinterpret_cast<CREATESTRUCTW*>(lparam)->lpCreateParams);self->window_=window;SetWindowLongPtrW(window,GWLP_USERDATA,reinterpret_cast<LONG_PTR>(self));}
    if(!self)return DefWindowProcW(window,message,wparam,lparam);
    try{return self->Message(message,wparam,lparam);}catch(const std::exception& error){self->Fail(error.what());return 0;}
}
LRESULT Host::Message(UINT message,WPARAM wparam,LPARAM lparam){
    switch(message){
    // There is no native non-client area: returning zero for both forms of
    // WM_NCCALCSIZE prevents DefWindowProc from restoring a one-pixel frame
    // during an activation or DPI transition.
    case WM_NCCALCSIZE:return 0;
    // The client surface is the complete window; suppress the default
    // non-client repaint so the native resize frame cannot reintroduce a
    // white outline around the custom shell.
    case WM_NCPAINT:return 0;
    case WM_ERASEBKGND:return 1;
    case WM_GETMINMAXINFO:{auto info=reinterpret_cast<MINMAXINFO*>(lparam);info->ptMinTrackSize={900,600};
        MONITORINFO monitor{sizeof(MONITORINFO)};if(GetMonitorInfoW(MonitorFromWindow(window_,MONITOR_DEFAULTTONEAREST),&monitor)){
            info->ptMaxPosition={monitor.rcWork.left-monitor.rcMonitor.left,monitor.rcWork.top-monitor.rcMonitor.top};
            info->ptMaxSize={monitor.rcWork.right-monitor.rcWork.left,monitor.rcWork.bottom-monitor.rcWork.top};}return 0;}
    case WM_NCHITTEST:if(!IsZoomed(window_)){
        RECT r{};GetWindowRect(window_,&r);const int x=GET_X_LPARAM(lparam),y=GET_Y_LPARAM(lparam),edge=3;
        const bool left=x<r.left+edge,right=x>=r.right-edge,top=y<r.top+edge,bottom=y>=r.bottom-edge;
        if(top)return left?HTTOPLEFT:right?HTTOPRIGHT:HTTOP;
        if(bottom)return left?HTBOTTOMLEFT:right?HTBOTTOMRIGHT:HTBOTTOM;
        if(left)return HTLEFT;if(right)return HTRIGHT;
    }break;
    case WM_NCLBUTTONDOWN:
        if(!IsZoomed(window_)&&(wparam==HTLEFT||wparam==HTRIGHT||wparam==HTTOP||wparam==HTBOTTOM||
            wparam==HTTOPLEFT||wparam==HTTOPRIGHT||wparam==HTBOTTOMLEFT||wparam==HTBOTTOMRIGHT)){
            resize_hit_=wparam;GetCursorPos(&resize_origin_);GetWindowRect(window_,&resize_window_);SetCapture(window_);return 0;
        }
        break;
    case WM_MOUSEMOVE:
        if(resize_hit_){
            POINT cursor{};GetCursorPos(&cursor);RECT next=resize_window_;
            constexpr LONG min_width=900,min_height=600;
            const bool left=resize_hit_==HTLEFT||resize_hit_==HTTOPLEFT||resize_hit_==HTBOTTOMLEFT;
            const bool right=resize_hit_==HTRIGHT||resize_hit_==HTTOPRIGHT||resize_hit_==HTBOTTOMRIGHT;
            const bool top=resize_hit_==HTTOP||resize_hit_==HTTOPLEFT||resize_hit_==HTTOPRIGHT;
            const bool bottom=resize_hit_==HTBOTTOM||resize_hit_==HTBOTTOMLEFT||resize_hit_==HTBOTTOMRIGHT;
            if(left)next.left=std::min(cursor.x,resize_window_.right-min_width);
            if(right)next.right=std::max(cursor.x,resize_window_.left+min_width);
            if(top)next.top=std::min(cursor.y,resize_window_.bottom-min_height);
            if(bottom)next.bottom=std::max(cursor.y,resize_window_.top+min_height);
            SetWindowPos(window_,nullptr,next.left,next.top,next.right-next.left,next.bottom-next.top,SWP_NOZORDER|SWP_NOACTIVATE);
            return 0;
        }
        break;
    case WM_LBUTTONUP:
    case WM_NCLBUTTONUP:
        if(resize_hit_){resize_hit_=0;ReleaseCapture();return 0;}
        break;
    case WM_CAPTURECHANGED:resize_hit_=0;break;
    case WM_SETCURSOR:
        if(!IsZoomed(window_)){
            switch(LOWORD(lparam)){
            case HTTOPLEFT:case HTBOTTOMRIGHT:SetCursor(LoadCursorW(nullptr,IDC_SIZENWSE));return TRUE;
            case HTTOPRIGHT:case HTBOTTOMLEFT:SetCursor(LoadCursorW(nullptr,IDC_SIZENESW));return TRUE;
            case HTTOP:case HTBOTTOM:SetCursor(LoadCursorW(nullptr,IDC_SIZENS));return TRUE;
            case HTLEFT:case HTRIGHT:SetCursor(LoadCursorW(nullptr,IDC_SIZEWE));return TRUE;
            default:break;
            }
        }
        break;
    case WM_DPICHANGED:{auto r=reinterpret_cast<RECT*>(lparam);SetWindowPos(window_,nullptr,r->left,r->top,r->right-r->left,r->bottom-r->top,SWP_NOZORDER|SWP_NOACTIVATE);return 0;}
    case WM_SIZE:Resize();State();return 0;
    case WM_TIMER:
        if(bridge_)bridge_->Tick();
        if(!closing_)DrainClipboard();
        if(!closing_)DrainTarget();
        if(!closing_)DrainProxy();
        if(data_&&bridge_&&!closing_)data_->Drain([this](std::string name,Json value){
            const bool wpc_feed = name == "feed:replace" && value.is_object() &&
                                  (value.value("list",0) == 17 || value.value("list",0) == 18);
            bridge_->PushEvent(name, value);
            if(wpc_feed && wpc_ && wpc_->Running() && !wpc_refresh_pending_){
                wpc_refresh_pending_=true;
                data_->Submit("__wpcSnapshot",Json::object(),[this](Json snapshot,std::string error){
                    wpc_refresh_pending_=false;
                    if(error.empty()&&wpc_&&wpc_->Running())wpc_->Update(snapshot.value("servers",Json::array()),snapshot.value("notices",Json::array()));
                });
            }
        });
        if(data_&&!closing_)RefreshAccountOnline();
        if(options_.test && std::chrono::steady_clock::now()-started_>std::chrono::seconds(90))Fail("WebView2 self-test timed out");
        if(!options_.test && !revealed_ && std::chrono::steady_clock::now()-started_>std::chrono::seconds(4)){
            revealed_=true;ShowWindow(window_,SW_SHOW);if(controller_)controller_->put_IsVisible(TRUE);Resize();
            RedrawWindow(window_,nullptr,nullptr,RDW_INVALIDATE|RDW_ERASE|RDW_UPDATENOW|RDW_ALLCHILDREN);
        }
        if(!options_.test && !ready_ && std::chrono::steady_clock::now()-started_>std::chrono::seconds(30))Fail("原 Vue 页面未在 30 秒内完成初始化，请检查 WebView2 Runtime 和 wwwroot 资源。");
        return 0;
    case app_ready:
        if(!ready_){ready_=true;if(!options_.test){revealed_=true;ShowWindow(window_,SW_SHOW);if(controller_)controller_->put_IsVisible(TRUE);Resize();RedrawWindow(window_,nullptr,nullptr,RDW_INVALIDATE|RDW_ERASE|RDW_UPDATENOW|RDW_ALLCHILDREN);}else BeginTest();}
        return 0;
    case app_drag:ReleaseCapture();SendMessageW(window_,WM_NCLBUTTONDOWN,HTCAPTION,0);return 0;
    case app_test:CaptureAndFinish();return 0;
    case app_file:PickImportFile();return 0;
    case app_target:DrainTarget();DrainProxy();return 0;
    case app_failure:
        // Posted from WebView2 callbacks: no nested modal pump in those callbacks.
        if(!options_.test)MessageBoxW(window_,Wide(report_.value("error",std::string("Native host failed"))).c_str(),L"WPE C++ 宿主错误",MB_OK|MB_ICONERROR);
        Finish(false);return 0;
    case WM_CLOSE:
        CancelFileJobs();
        closing_=true;if(bridge_)bridge_->FailAllPending();
        if(controller_)controller_->Close();view_.Reset();controller_.Reset();
        DestroyWindow(window_);return 0;
    case WM_DESTROY:KillTimer(window_,1);PostQuitMessage(exit_code_);return 0;
    }
    return DefWindowProcW(window_,message,wparam,lparam);
}
int Host::Run(){
    if(const auto error=StartupEnvironmentError(options_);!error.empty())
        throw std::runtime_error(error);
    const auto instance=GetModuleHandleW(nullptr);
    WNDCLASSEXW type{sizeof(WNDCLASSEXW)};type.lpfnWndProc=WindowProc;type.hInstance=instance;type.hIcon=LoadIconW(instance,MAKEINTRESOURCEW(IDI_APP_ICON));type.hIconSm=LoadIconW(instance,MAKEINTRESOURCEW(IDI_APP_ICON));type.hCursor=LoadCursorW(nullptr,IDC_ARROW);type.lpszClassName=L"Wpe64NativeHost";
    if(!RegisterClassExW(&type))throw std::runtime_error("Window class registration failed");
    // The Vue shell already owns the title bar and window buttons.  Remove
    // both caption and thick-frame styles: the latter is the Windows/DWM
    // source of the bright one-pixel outline.  Resize gestures are handled
    // by the small borderless loop in Message() instead.
    constexpr DWORD style=WS_OVERLAPPEDWINDOW & ~(WS_CAPTION|WS_THICKFRAME);
    window_=CreateWindowExW(0,type.lpszClassName,L"WPE-陈北玄 v2.3.0",style,100,100,1200,820,nullptr,nullptr,instance,this);
    if(!window_)throw std::runtime_error("Window creation failed");
    // Some Windows themes/WebView2 versions reintroduce the caption while
    // attaching the controller.  Apply the non-client style explicitly and
    // ask DWM to recalculate the frame so the invariant is observable at
    // runtime, not just in the CreateWindowEx argument.
    auto frame_style=GetWindowLongPtrW(window_,GWL_STYLE);
    frame_style&=~static_cast<LONG_PTR>(WS_CAPTION|WS_THICKFRAME);
    SetWindowLongPtrW(window_,GWL_STYLE,frame_style);
    SetWindowPos(window_,nullptr,0,0,0,0,SWP_NOMOVE|SWP_NOSIZE|SWP_NOZORDER|SWP_NOACTIVATE|SWP_FRAMECHANGED);
    // Extend the DWM surface across the complete client rectangle.  A zero
    // margin still leaves a one-pixel active-window outline on some Windows
    // builds; the documented -1 sentinel makes the non-client surface fully
    // transparent while WebView2 paints the entire visible window.
    const MARGINS margins{-1,-1,-1,-1};DwmExtendFrameIntoClientArea(window_,&margins);
    // DWMWA_BORDER_COLOR is only available on newer DWM versions.  Use the
    // numeric value so older SDK headers still build, and ignore E_INVALIDARG
    // on older Windows where the attribute does not exist.  COLOR_NONE makes
    // the resize frame transparent; the custom Vue shell remains visible.
    constexpr DWORD kDwmBorderColor=34;
    constexpr COLORREF kDwmColorNone=0xFFFFFFFEu;
    DwmSetWindowAttribute(window_,kDwmBorderColor,&kDwmColorNone,sizeof(kDwmColorNone));
    SetTimer(window_,1,100,nullptr);
    Initialize();
    MSG message{};BOOL status;
    while((status=GetMessageW(&message,nullptr,0,0))>0){TranslateMessage(&message);DispatchMessageW(&message);}
    bridge_.reset();view_.Reset();controller_.Reset();environment_.Reset();
    if(status<0)throw std::runtime_error("Window message loop failed");
    return static_cast<int>(message.wParam);
}
void Host::Initialize(){
    Check(CreateCoreWebView2EnvironmentWithOptions(nullptr,options_.data.c_str(),nullptr,
        Callback<ICoreWebView2CreateCoreWebView2EnvironmentCompletedHandler>([this,alive=std::weak_ptr(lifetime_)](HRESULT result,ICoreWebView2Environment* environment)->HRESULT{
            if(alive.expired()||closing_)return S_OK;
            return Guard([&]{Check(result,"Create WebView2 environment");environment_=environment;
                CoString version;Check(environment_->get_BrowserVersionString(&version.value),"Runtime version");report_["webview2Runtime"]=Utf8(version.value);
                Check(environment_->CreateCoreWebView2Controller(window_,Callback<ICoreWebView2CreateCoreWebView2ControllerCompletedHandler>([this,alive=std::weak_ptr(lifetime_)](HRESULT hr,ICoreWebView2Controller* controller)->HRESULT{
                    if(alive.expired()||closing_)return S_OK;
                    return Guard([&]{Check(hr,"Create controller");controller_=controller;Check(controller_->get_CoreWebView2(&view_),"Get WebView2");Configure();});
                }).Get()),"Create controller async");
            });
        }).Get()),"Create environment async");
}
void Host::Configure(){
    ComPtr<ICoreWebView2_3> resources;Check(view_.As(&resources),"WebView2 resource mapping interface");
    // The mapped folder is the packaged frontend that the native host is
    // expected to serve.  Using DENY here makes navigation succeed but blocks
    // every resource under app.wpe64.local, leaving WebView2 as a blank white
    // page.  Keep the origin restricted to this local virtual host while
    // allowing the mapped folder to be read.
    Check(resources->SetVirtualHostNameToFolderMapping(L"app.wpe64.local",options_.assets.c_str(),COREWEBVIEW2_HOST_RESOURCE_ACCESS_KIND_ALLOW),"Map original wwwroot");
    ComPtr<ICoreWebView2Settings> settings;Check(view_->get_Settings(&settings),"Get settings");
    Check(settings->put_IsWebMessageEnabled(TRUE),"Enable web messages");
    Check(settings->put_AreHostObjectsAllowed(FALSE),"Disable host objects");
    Check(settings->put_AreDefaultScriptDialogsEnabled(FALSE),"Disable script dialogs");
    Check(settings->put_AreDevToolsEnabled(options_.test?TRUE:FALSE),"Configure devtools");
    ComPtr<ICoreWebView2Settings9> nonclient;
    native_drag_=SUCCEEDED(settings.As(&nonclient)) && SUCCEEDED(nonclient->put_IsNonClientRegionSupportEnabled(TRUE));
    ComPtr<ICoreWebView2Controller2> background;if(SUCCEEDED(controller_.As(&background)))background->put_DefaultBackgroundColor(COREWEBVIEW2_COLOR{255,10,10,15});
    bridge_=std::make_unique<WebBridge>([this](const std::string& text){if(closing_)throw std::runtime_error("Host is closing");Check(view_->PostWebMessageAsJson(Wide(text).c_str()),"Post web message");});
    RegisterMethods();
    EventRegistrationToken token{};
    Check(view_->add_WebMessageReceived(Callback<ICoreWebView2WebMessageReceivedEventHandler>([this](ICoreWebView2*,ICoreWebView2WebMessageReceivedEventArgs* args)->HRESULT{
        return Guard([&]{CoString source,raw;Check(args->get_Source(&source.value),"Message source");Check(args->get_WebMessageAsJson(&raw.value),"Message JSON");++messages_;bridge_->Receive(Utf8(source.value),Utf8(raw.value));});
    }).Get(),&token),"Register web messages");
    Check(view_->add_NavigationStarting(Callback<ICoreWebView2NavigationStartingEventHandler>([this](ICoreWebView2*,ICoreWebView2NavigationStartingEventArgs* args)->HRESULT{
        return Guard([&]{CoString uri;Check(args->get_Uri(&uri.value),"Navigation URI");if(!WebBridge::IsAllowedSource(Utf8(uri.value)))Check(args->put_Cancel(TRUE),"Block navigation");else {CancelFileJobs();bridge_->FailAllPending();}});
    }).Get(),&token),"Register navigation");
    Check(view_->add_NewWindowRequested(Callback<ICoreWebView2NewWindowRequestedEventHandler>([](ICoreWebView2*,ICoreWebView2NewWindowRequestedEventArgs* args)->HRESULT{return args->put_Handled(TRUE);}).Get(),&token),"Block new windows");
    Check(view_->add_PermissionRequested(Callback<ICoreWebView2PermissionRequestedEventHandler>([](ICoreWebView2*,ICoreWebView2PermissionRequestedEventArgs* args)->HRESULT{return args->put_State(COREWEBVIEW2_PERMISSION_STATE_DENY);}).Get(),&token),"Block web permissions");
    Check(view_->add_ProcessFailed(Callback<ICoreWebView2ProcessFailedEventHandler>([this](ICoreWebView2*,ICoreWebView2ProcessFailedEventArgs*)->HRESULT{bridge_->FailAllPending();Fail("WebView2 renderer failed");return S_OK;}).Get(),&token),"Register process failures");
    Check(view_->add_NavigationCompleted(Callback<ICoreWebView2NavigationCompletedEventHandler>([this](ICoreWebView2*,ICoreWebView2NavigationCompletedEventArgs* args)->HRESULT{
        return Guard([&]{BOOL ok=FALSE;Check(args->get_IsSuccess(&ok),"Navigation status");if(!ok)Fail("Original frontend navigation failed");});
    }).Get(),&token),"Register navigation completion");
    Resize();
    // The host starts hidden to avoid a white startup flash.  Explicitly
    // enable the controller and repaint when it is shown; some DWM/GPU
    // combinations otherwise leave a controller created on a hidden parent
    // as a blank white surface.
    Check(controller_->put_IsVisible(TRUE),"Show WebView2 controller");
    Check(view_->Navigate(origin),"Navigate original frontend");
}
void Host::Resize(){
    if(!controller_)return;
    // The native host is borderless: the WebView must occupy the entire
    // client rectangle.  The old three-pixel inset was only compensating for
    // the removed native frame and left the host's default (white) background
    // visible as a bright outline on all four sides.
    RECT bounds{};GetClientRect(window_,&bounds);controller_->put_Bounds(bounds);
}
void Host::State(){if(bridge_&&!closing_)bridge_->PushEvent("window:state",{{"maximized",IsZoomed(window_)!=FALSE}});}
bool Host::StartWpc(const Json& setting,const Json& snapshot,std::string& error){
    wpe::shell::WpcConfig config;
    config.bind_address=setting.value("IP",std::string("127.0.0.1"));
    const auto configured_port=setting.value("Port",88);
    if(configured_port<1||configured_port>65535){error="WPC 监听端口必须在 1 ~ 65535 之间";return false;}
    config.port=static_cast<std::uint16_t>(configured_port);
    config.user=setting.value("UserName",std::string{});
    config.password=setting.value("PassWord",std::string{});
    config.servers=snapshot.value("servers",Json::array());
    config.notices=snapshot.value("notices",Json::array());
    if(wpc_)wpc_->Stop();
    if(!wpc_||!wpc_->Start(std::move(config),error))return false;
    const auto stats=wpc_->Stats();
    if(bridge_)bridge_->PushEvent("wpc:state",{{"running",true},{"port",stats.port}});
    return true;
}
void Host::AppendSystemLog(std::string module,std::string content){
    if(!data_||content.empty())return;
    data_->Submit("__appendLog",{{"list",2},{"row",{{"Time",LogTime()},{"FuncName",std::move(module)},{"Content",std::move(content)}}}},[](Json,std::string){});
}
void Host::AppendProxyLog(std::string user,std::string ip,std::string content){
    if(!data_||content.empty())return;
    data_->Submit("__appendLog",{{"list",4},{"row",{{"Time",LogTime()},{"UserName",std::move(user)},{"LoginIP",std::move(ip)},{"Content",std::move(content)}}}},[](Json,std::string){});
}
Json Host::ProxyClientRows() const {
    struct Aggregate {
        std::string account, ip, device, client, auth_time;
        std::int64_t links{};
    };
    std::map<std::string, Aggregate> grouped;
    std::lock_guard lock(proxy_clients_mutex_);
    for (const auto& [session, event] : proxy_clients_) {
        (void)session;
        if (event.account_key.empty()) continue;
        const auto endpoint = event.device_id.empty() ? "ip:" + event.client_ip : "device:" + event.device_id;
        const auto key = event.account_key + "|" + endpoint;
        auto& row = grouped[key];
        if (row.links == 0) {
            row.account = event.account_key;
            row.ip = event.client_ip;
            row.device = event.device_id;
            row.client = event.client;
            row.auth_time = event.auth_time.empty() ? LogTime() : event.auth_time;
        }
        ++row.links;
    }
    Json rows = Json::array();
    for (const auto& [key, row] : grouped) {
        (void)key;
        rows.push_back({{"AccountId", row.account}, {"UserName", row.account},
                        {"AuthIP", row.ip}, {"IPLocation", ""},
                        {"LinksNumber", row.links}, {"DevicesNumber", 1},
                        {"TrafficStatistics", 0}, {"AuthResult", true},
                        {"AuthTime", row.auth_time}, {"DeviceId", row.device},
                        {"Client", row.client}});
    }
    return rows;
}
void Host::QueueProxyClientEvent(wpe::shell::ProxyClientEvent event) {
    if (event.session_id.empty()) return;
    if (event.connected && event.auth_time.empty()) event.auth_time = LogTime();
    {
        std::lock_guard lock(proxy_clients_mutex_);
        if (event.connected) proxy_clients_[event.session_id] = std::move(event);
        else proxy_clients_.erase(event.session_id);
    }
    if (!data_) return;
    data_->Submit("__setClientRows", {{"rows", ProxyClientRows()}}, [](Json, std::string) {});
}
void Host::QueueProxyConnectionEvent(wpe::shell::ProxyConnectionEvent event) {
    if (event.session_id.empty()) return;
    Json rows=Json::array();
    {
        std::lock_guard lock(proxy_connections_mutex_);
        if (event.connected) proxy_connections_[event.session_id]=std::move(event);
        else proxy_connections_.erase(event.session_id);
        for (const auto& [session, item] : proxy_connections_) {
            (void)session;
            rows.push_back({{"ClientIP",item.client_ip},{"ClientPort",item.client_port},
                            {"Target",item.target},{"DomainType",item.domain_type},
                            {"ServerAddress",item.server_address},{"Udp",item.udp},{"Wpc",item.wpc}});
        }
    }
    if (data_) data_->Submit("__setClientConnections", {{"items", std::move(rows)}}, [](Json, std::string) {});
}
void Host::RefreshAccountOnline(){
    std::unordered_set<std::string> current;
    if(proxy_){for(const auto& account:proxy_->OnlineAccounts())if(!account.empty())current.insert(account);}
    if(http_proxy_){for(const auto& account:http_proxy_->OnlineAccounts())if(!account.empty())current.insert(account);}
    if(current==last_online_accounts_)return;
    last_online_accounts_=current;
    Json accounts=Json::array();
    for(const auto& account:current)accounts.push_back(account);
    data_->Submit("__setAccountOnline",{{"accounts",std::move(accounts)}},[](Json,std::string){});
}
bool Host::ApplyProxyRuntimeConfiguration(const Json& config, bool allow_start, Json& result, std::string& error){
    if(!proxy_||!http_proxy_){error="代理运行时未初始化";return false;}
    {
        std::lock_guard lock(proxy_filter_mutex_);
        proxy_capture_filter_=config.value("captureFilter",Json::object());
    }
    const bool want_socks=config.value("enableSocks5",false),want_http=config.value("enableHttp",false);
    const bool running_socks=proxy_->Stats().running,running_http=http_proxy_->Stats().running;
    const bool running_any=running_socks||running_http;
    if(!want_socks&&!want_http){
        if(!allow_start&&!running_any){result={{"ok",true},{"running",false},{"socks5Addr",""},{"httpAddr",""}};return true;}
        error="请至少启用一种代理类型";return false;
    }
    const bool automatic=config.value("proxyIpAuto",true);
    const auto bind_address=automatic?std::string("0.0.0.0"):config.value("proxyIp",std::string{});
    if(bind_address.empty()){error="监听地址不能为空";return false;}
    const auto max_connections=static_cast<std::size_t>(std::max(1,config.value("maxConnection",5000)));
    const bool require_auth=config.value("enableAuth",true);
    std::vector<wpe::shell::Socks5Credential> credentials,wpc_accounts;
    for(const auto& account:config.value("accounts",Json::array()))if(account.is_object()){
        wpe::shell::Socks5Credential value;value.user=account.value("user",std::string{});value.password=account.value("password",std::string{});
        credentials.push_back(std::move(value));
    }
    for(const auto& account:config.value("wpcAccounts",Json::array()))if(account.is_object()){
        wpe::shell::Socks5Credential value;value.account_id=account.value("accountId",std::string{});value.user=account.value("user",std::string{});
        value.password=account.value("password",std::string{});value.enabled=account.value("enabled",false);value.limit_devices=account.value("limitDevices",false);
        value.max_devices=static_cast<std::size_t>(std::max(1,account.value("maxDevices",1)));value.expiry=account.value("expiry",false);value.expiry_time=account.value("expiryTime",std::string{});
        wpc_accounts.push_back(std::move(value));
    }
    const auto read_port=[&](const char* key,std::uint16_t fallback,const char* label,std::uint16_t& output){
        const auto value=config.value(key,static_cast<int>(fallback));
        if(value<1||value>65535){error=std::string(label)+" 端口必须在 1 ~ 65535 之间";return false;}
        output=static_cast<std::uint16_t>(value);return true;
    };
    std::uint16_t socks_port=0,http_port=0;
    if(want_socks&&!read_port("socks5Port",1080,"SOCKS5",socks_port))return false;
    if(want_http&&!read_port("httpPort",1081,"HTTP",http_port))return false;
    if(want_socks&&want_http&&socks_port==http_port){error="SOCKS5 和 HTTP 端口不能相同";return false;}
    std::optional<wpe::shell::Socks5Config> socks_config;
    std::optional<wpe::shell::HttpProxyConfig> http_config;
    if(want_socks){
        wpe::shell::Socks5Config runtime;runtime.bind_address=bind_address;runtime.port=socks_port;runtime.max_connections=max_connections;
        runtime.require_auth=require_auth;runtime.only_wpc=config.value("onlyWpc",false);runtime.credentials=credentials;runtime.wpc_accounts=wpc_accounts;
        runtime.on_packet=[this](wpe::shell::ProxyPacket packet){QueueProxyPacket(std::move(packet));};
        runtime.on_client=[this](wpe::shell::ProxyClientEvent event){QueueProxyClientEvent(std::move(event));};
        runtime.on_connection=[this](wpe::shell::ProxyConnectionEvent event){QueueProxyConnectionEvent(std::move(event));};
        socks_config=std::move(runtime);
    }
    if(want_http){
        wpe::shell::HttpProxyConfig runtime;runtime.bind_address=bind_address;runtime.port=http_port;runtime.max_connections=max_connections;runtime.require_auth=require_auth;runtime.credentials=credentials;
        runtime.enable_local_map=config.value("enableLocalMap",false);runtime.enable_remote_map=config.value("enableRemoteMap",false);
        const auto read_map_port=[&](const Json& row,const char* key,const char* label,std::uint16_t& output){
            const auto value=row.value(key,80);if(value<1||value>65535){error=std::string(label)+" 映射端口必须在 1 ~ 65535 之间";return false;}output=static_cast<std::uint16_t>(value);return true;
        };
        for(const auto& item:config.value("localMaps",Json::array()))if(item.is_object()){
            wpe::shell::HttpProxyConfig::LocalMapRule rule;rule.enabled=item.value("enabled",true);rule.protocol=item.value("protocol",std::string("Http"));
            rule.host=item.value("host",std::string{});rule.remote_path=item.value("remotePath",std::string{});rule.local_path=item.value("localPath",std::string{});
            if(rule.host.empty()||rule.local_path.empty()){error="本地映射缺少源地址或本地文件";return false;}if(!read_map_port(item,"port","本地",rule.port))return false;runtime.local_maps.push_back(std::move(rule));
        }
        for(const auto& item:config.value("remoteMaps",Json::array()))if(item.is_object()){
            wpe::shell::HttpProxyConfig::RemoteMapRule rule;rule.enabled=item.value("enabled",true);rule.protocol_from=item.value("protocolFrom",std::string("Http"));
            rule.host_from=item.value("hostFrom",std::string{});rule.path_from=item.value("pathFrom",std::string{});rule.protocol_to=item.value("protocolTo",std::string("Http"));
            rule.host_to=item.value("hostTo",std::string{});rule.path_to=item.value("pathTo",std::string{});
            if(rule.host_from.empty()||rule.host_to.empty()){error="远程映射缺少源地址或目标地址";return false;}
            if(!read_map_port(item,"portFrom","远程源",rule.port_from)||!read_map_port(item,"portTo","远程目标",rule.port_to))return false;runtime.remote_maps.push_back(std::move(rule));
        }
        runtime.on_packet=[this](wpe::shell::ProxyPacket packet){QueueProxyPacket(std::move(packet));};
        runtime.on_client=[this](wpe::shell::ProxyClientEvent event){QueueProxyClientEvent(std::move(event));};
        runtime.on_connection=[this](wpe::shell::ProxyConnectionEvent event){QueueProxyConnectionEvent(std::move(event));};
        http_config=std::move(runtime);
    }
    if(!allow_start&&!running_any){result={{"ok",true},{"running",false},{"socks5Addr",""},{"httpAddr",""}};return true;}
    // Apply atomically from the user's perspective: validate the complete
    // snapshot first, then replace the listeners. Existing sessions are closed
    // only for a live configuration change; subsequent connections use the
    // newly saved account/map/list data immediately.
    if(running_any){if(http_proxy_->Running())http_proxy_->Stop();if(proxy_->Running())proxy_->Stop();}
    std::string start_error;bool socks_started=false;
    if(socks_config&& !proxy_->Start(std::move(*socks_config),start_error)){error=std::move(start_error);return false;}
    socks_started=want_socks;
    if(http_config&&!http_proxy_->Start(std::move(*http_config),start_error)){
        if(socks_started)proxy_->Stop();error=std::move(start_error);return false;
    }
    const auto display_host=automatic?std::string("127.0.0.1"):config.value("proxyIp",std::string{});proxy_display_host_=display_host;
    const auto format_address=[&](std::uint16_t port){if(port==0)return std::string{};return (display_host.find(':')==display_host.npos?display_host:"["+display_host+"]")+":"+std::to_string(port);};
    const auto socks=proxy_->Stats(),http=http_proxy_->Stats();const auto socks_address=format_address(socks.port),http_address=format_address(http.port);
    result={{"ok",true},{"running",socks.running||http.running},{"socks5Addr",socks_address},{"httpAddr",http_address}};
    if(bridge_)bridge_->PushEvent("proxy:state",{{"running",socks.running||http.running},{"socks5Addr",socks_address},{"httpAddr",http_address}});
    return true;
}
void Host::RegisterMethods(){
    const auto db=options_.data/L"2.3.0"/L"WPE.db";
    data_=std::make_unique<wpe::shell::DataWorker>(db);
    proxy_=std::make_unique<wpe::shell::Socks5Runtime>();
    http_proxy_=std::make_unique<wpe::shell::HttpProxyRuntime>();
    wpc_=std::make_unique<wpe::shell::WpcRuntime>();
    target_=std::make_unique<wpe::shell::TargetLink>(
        [this](wpe::ByteBuffer frame,bool packet){QueueTargetFrame(std::move(frame),packet);},
        [this](wpe::IpcLinkState state){
            Json value{{"state",state==wpe::IpcLinkState::Attached?"attached":
                                   state==wpe::IpcLinkState::Attaching?"attaching":
                                   state==wpe::IpcLinkState::Disconnected?"disconnected":"idle"},
                       {"pid",target_?target_->TargetPid():0},
                       {"is64",target_?target_->TargetIs64():false},
                       {"hooked",false}};
             QueueTargetResult({},Json{{"__event","inject:state"},{"value",std::move(value)}},{});
        }, X86HookDll(), X86Helper());
    const auto target_config_method=[](const std::string& method){
        static const std::unordered_set<std::string> methods{
            "saveSystemSetting","saveHookSetting","saveLeachSetting","saveListSetting","saveListAutoClear",
            "addFilter","setFilterEnable","setAllFilterEnable","filterListAction","clearFilters","saveFilterEdit","importFilters",
            "addSend","setSendEnable","setAllSendEnable","sendListAction","clearSends","saveSendEdit","sendCollectionAction","clearSendCollection","importSends",
            "savePacketEdit","importBackup"
        };
        return methods.contains(method);
    };
    const auto proxy_live_method=[](const std::string& method){
        static const std::unordered_set<std::string> methods{
            "saveProxySetting","saveMapSetting","saveMapLocal","saveMapRemote","setMapEnable","mapAction","mapCommand",
            "saveAccount","deleteAccount","clearAllAccounts","setAccountEnable","saveBatchAccounts","deleteSelectedAccounts",
            "importAccounts","adjustAccountExpiry","adjustAccountLimit","importBackup"
        };
        return methods.contains(method);
    };
    for(const auto& method:wpe::shell::DataService::Methods()){
        bridge_->RegisterAsync(method,[this,method,target_config_method,proxy_live_method](const Json& args,WebBridge::Completion done){
            if(method=="getRemoteSetting"){
                data_->Submit(method,args,[this,done=std::move(done)](Json value,std::string error) mutable {
                    if(!error.empty()){done(nullptr,std::move(error));return;}
                    const auto stats=wpc_?wpc_->Stats():wpe::shell::WpcStats{};
                    if(value.is_object()){
                        value["Running"]=stats.running;
                        if(stats.running){value["IP"]=value.value("IP",std::string("127.0.0.1"));value["Port"]=stats.port;}
                    }
                    done(std::move(value),{});
                });
                return;
            }
            if(method=="saveRemoteSetting"){
                data_->Submit(method,args,[this,args,done=std::move(done)](Json value,std::string error) mutable {
                    (void)value;
                    if(!error.empty()){done(nullptr,std::move(error));return;}
                    const bool enabled=args.value("isRemote",false);
                    if(!enabled){if(wpc_)wpc_->Stop();if(bridge_)bridge_->PushEvent("wpc:state",{{"running",false},{"port",0}});done({{"ok",true},{"running",false}},{});return;}
                    data_->Submit("__wpcSnapshot",Json::object(),[this,args,done=std::move(done)](Json snapshot,std::string snapshot_error) mutable {
                        if(!snapshot_error.empty()){done(nullptr,std::move(snapshot_error));return;}
                        std::string start_error;
                        Json setting{{"IP",args.value("ip",std::string("127.0.0.1"))},{"Port",args.value("port",88)},
                                     {"UserName",args.value("userName",std::string{})},{"PassWord",args.value("passWord",std::string{})}};
                        if(!StartWpc(setting,snapshot,start_error)){done(nullptr,start_error.empty()?"WPC 服务初始化失败":std::move(start_error));return;}
                        done({{"ok",true},{"running",true},{"port",wpc_->Stats().port}},{});
                    });
                });
                return;
            }
            if(wpe::shell::DataService::NeedsOpenFile(method,args)||wpe::shell::DataService::NeedsSaveFile(method,args)){
                if(file_jobs_.size()>=8){done(nullptr,"文件选择请求过多");return;}
                auto safe=args;safe.erase("_filePath");safe.erase("_password"); // Only the native chooser may grant a file path.
                if(wpe::shell::DataService::NeedsSaveFile(method,args)){
                    // Snapshot selection on the data worker BEFORE opening the
                    // picker, just as the original constructs its List<T> first.
                    auto complete=bridge_->WithErrorToast(std::move(done));
                    data_->Submit("__prepareEditorExport",{{"method",method},{"args",safe}},[this,method,safe,complete,epoch=file_epoch_](Json plan,std::string error){
                        if(closing_||epoch!=file_epoch_){DiscardExport(plan);complete(nullptr,"文件选择已取消");return;}
                        if(!error.empty()){complete(nullptr,std::move(error));return;}
                        if(plan.at("rowCount")==0){complete(plan.at("result"),{});return;}
                        if(file_jobs_.size()>=8){DiscardExport(plan);complete(nullptr,"文件选择请求过多");return;}
                        file_jobs_.push_back({method,safe,complete,std::move(plan)});PostMessageW(window_,app_file,0,0);
                    });return;
                }
                auto complete=bridge_->WithErrorToast(std::move(done));
                data_->Submit("__fileInfo",{{"kind",wpe::shell::DataService::FileKind(method,safe)},{"save",false}},[this,method,safe,complete,epoch=file_epoch_](Json info,std::string error){
                    if(closing_||epoch!=file_epoch_){complete(nullptr,"文件选择已取消");return;}
                    if(!error.empty()){complete(nullptr,std::move(error));return;}
                    if(file_jobs_.size()>=8){complete(nullptr,"文件选择请求过多");return;}
                    file_jobs_.push_back({method,safe,complete,nullptr,std::move(info)});PostMessageW(window_,app_file,0,0);
                });return;
            }
            auto submit=[this,method,args,done,target_config_method,proxy_live_method]() mutable {
                data_->Submit(method,args,[this,method,done=std::move(done),target_config_method,proxy_live_method](Json value,std::string error) mutable {
                    if(!error.empty()){done(std::move(value),std::move(error));return;}
                    // Capture filtering is also used by the proxy feed.  It
                    // must take effect without restarting listeners when the
                    // user saves the filter dialog while a proxy is running.
                    if(method=="saveLeachSetting"&&proxy_&&http_proxy_&&
                       (proxy_->Stats().running||http_proxy_->Stats().running))
                        RefreshProxyCaptureFilter();
                    const bool target_live=target_config_method(method)&&target_&&target_->State()==wpe::IpcLinkState::Attached;
                    const bool proxy_live=proxy_live_method(method)&&proxy_&&http_proxy_&&
                        (proxy_->Stats().running||http_proxy_->Stats().running);
                    if(target_live){
                        SyncTargetConfiguration([done=std::move(done),value=std::move(value)](Json,std::string sync_error) mutable {
                            if(!sync_error.empty()){done(std::move(value),"数据已保存，但目标配置实时同步失败："+sync_error);return;}
                            done(std::move(value),{});
                        });
                        return;
                    }
                    if(proxy_live){
                        data_->Submit("__proxyRuntimeConfiguration",Json::object(),[this,done=std::move(done),value=std::move(value)](Json config,std::string config_error) mutable {
                            if(!config_error.empty()){done(std::move(value),"数据已保存，但代理配置读取失败："+config_error);return;}
                            Json refreshed;std::string refresh_error;
                            if(!ApplyProxyRuntimeConfiguration(config,false,refreshed,refresh_error)){
                                done(std::move(value),"数据已保存，但代理实时同步失败："+refresh_error);return;
                            }
                            done(std::move(value),{});
                        });
                        return;
                    }
                    done(std::move(value),{});
                });
            };
            if(wpe::shell::DataService::NeedsConfirmation(method,args)){
                bridge_->Ask("confirm",{{"title","确认操作"},{"content","确定删除选中的数据吗？此操作不可撤销。"},{"icon",2}},
                    [submit=std::move(submit),done](Json answer) mutable {if(answer==true)submit();else done({{"ok",true},{"delta",0}},{});});
            }else submit();
        });
    }
    bridge_->RegisterAsync("verifyEncryptPassword",[this](const Json& args,WebBridge::Completion done){
        if(import_token_.empty()||import_path_.empty()||!args.contains("path")||args["path"]!=import_path_){done({{"ok",false}},{});return;}
        data_->Submit("__verifyImportPassword",{{"token",import_token_},{"password",args.value("password",std::string{})}},[this,done,token=import_token_,epoch=file_epoch_](Json value,std::string error){
            if(!error.empty()||epoch!=file_epoch_||token!=import_token_){done({{"ok",false}},{});return;}done(std::move(value),{});
        });
    });
    bridge_->RegisterAsync("getSystemCheck",[this](const Json&,WebBridge::Completion done){
        data_->Submit("getPrefs",Json::object(),[this,done](Json prefs,std::string error){
            if(!error.empty()){done(nullptr,std::move(error));return;}
            const auto db=options_.data/L"2.3.0"/L"WPE.db";
            done(Json{
                {"isAdmin",IsAdmin()},{"version","2.3.0"},{"isBeta",false},{"language",prefs["language"]},
                {"themeMode",prefs["themeMode"]},{"isDark",prefs["isDark"]},{"scanLine",prefs["scanLine"]},{"nativeDrag",native_drag_},
                {"dbDir",Utf8(options_.data.wstring())},{"dbFile","WPE.db"},{"dbFull",Utf8(db.wstring())},{"dbInstance","default"},{"lastInjection",""},{"lastInject",nullptr},
                {"socks5Port",0},{"socks5Addr",""},{"httpAddr",""},{"geoVersion","未实现"},{"geoCount",0}},{});
        });
    });
    // InstanceView is a native-backed screen, not a static mock.  The path
    // is used as the root of <path>\\2.3.0\\WPE.db, matching the worker that
    // was created above.  The UI deliberately treats it as per-run state.
    bridge_->Register("probeDbPath",[this](const Json& args){
        try{return ProbeInstancePath(fs::path(Wide(args.value("path",std::string{}))),options_.data);}
        catch(const std::exception& e){return Json{{"valid",false},{"full",""},{"error",e.what()}};}
    });
    bridge_->RegisterAsync("pickFolder",[this](const Json& args,WebBridge::Completion done){
        if(closing_||file_dialog_||file_prompt_pending_){done(nullptr,"文件选择器正在使用");return;}
        if(file_jobs_.size()>=8){done(nullptr,"文件选择请求过多");return;}
        file_jobs_.push_back({"__pickFolder",args,std::move(done),nullptr,nullptr});PostMessageW(window_,app_file,0,0);
    });
    bridge_->RegisterAsync("saveInstance",[this](const Json& args,WebBridge::Completion done){
        try{
            const auto root=fs::path(Wide(args.value("path",std::string{})));
            const auto probe=ProbeInstancePath(root,options_.data);
            if(!probe.value("valid",false)){done(nullptr,"数据库路径无效；请使用绝对路径且不要包含非法字符");return;}
            const auto running=(proxy_&& (proxy_->Stats().running||http_proxy_&&http_proxy_->Stats().running))||
                (wpc_&&wpc_->Running())||(target_&&target_->State()!=wpe::IpcLinkState::Idle);
            if(running){done(nullptr,"请先停止当前代理、WPC 或目标连接，再切换数据库");return;}
            std::error_code ec;fs::create_directories(root/L"2.3.0",ec);if(ec){done(nullptr,"无法创建数据库目录: "+ec.message());return;}
            if(data_)data_.reset();
            options_.data=root.lexically_normal();
            data_=std::make_unique<wpe::shell::DataWorker>(options_.data/L"2.3.0"/L"WPE.db");
            data_->Submit("getPrefs",Json::object(),[this,done](Json prefs,std::string error){
                if(!error.empty()){done(nullptr,std::move(error));return;}
                done({{"ok",true},{"language",prefs.value("language",std::string("zh-CN"))},{"socks5Addr",""},{"httpAddr",""}},{});
            });
        }catch(const std::exception& e){done(nullptr,e.what());}
    });
    bridge_->Register("uiReady",[this](const Json&){PostMessageW(window_,app_ready,0,0);return Json{{"ok",true}};});
    bridge_->Register("minimizeWindow",[this](const Json&){ShowWindow(window_,SW_MINIMIZE);return Json{{"ok",true}};});
    bridge_->Register("toggleMaximize",[this](const Json&){ShowWindow(window_,IsZoomed(window_)?SW_RESTORE:SW_MAXIMIZE);return Json{{"maximized",IsZoomed(window_)!=FALSE}};});
    bridge_->Register("closeWindow",[this](const Json&){PostMessageW(window_,WM_CLOSE,0,0);return Json{{"ok",true}};});
    bridge_->Register("setTopMost",[this](const Json& args){
        const bool on=args.value("on",false);if(!SetWindowPos(window_,on?HWND_TOPMOST:HWND_NOTOPMOST,0,0,0,0,SWP_NOMOVE|SWP_NOSIZE|SWP_NOACTIVATE))throw std::runtime_error("Cannot change window z-order");
        if(options_.test)report_["topmostCalls"].push_back({{"on",on},{"style",GetWindowLongPtrW(window_,GWL_EXSTYLE)},{"visible",IsWindowVisible(window_)!=FALSE}});
        return Json{{"topMost",(GetWindowLongPtrW(window_,GWL_EXSTYLE)&WS_EX_TOPMOST)!=0}};});
    bridge_->Register("startDragWindow",[this](const Json&){PostMessageW(window_,app_drag,0,0);return Json{{"ok",true}};});
    clipboard_=std::make_unique<wpe::shell::ClipboardWorker>(options_.test);
    bridge_->RegisterAsync("clipboardRead",[this](const Json&,WebBridge::Completion done){
        clipboard_->Submit(false,{},[done](bool ok,std::wstring value){std::string text;try{if(ok)text=Utf8(value);}catch(...){}done({{"text",text}},{});});
    });
    bridge_->RegisterAsync("clipboardWrite",[this](const Json& args,WebBridge::Completion done){
        std::wstring text;try{if(args.contains("text")&&!args["text"].is_null())text=Wide(args.at("text").get<std::string>());}catch(...){done({{"ok",false}},{});return;}
        clipboard_->Submit(true,std::move(text),[done](bool ok,std::wstring){done({{"ok",ok}},{});});
    });
    // Windows-only shell actions that used to be hidden behind the old
    // WinForms host.  Keep them in the native bridge instead of pretending
    // that a browser tab can mutate the user's registry, proxy settings or
    // executable chooser.
    bridge_->Register("openExternal",[](const Json& args){
        const auto url=Wide(args.value("url",std::string{}));if(url.empty())return Json{{"ok",false},{"error","URL 为空"}};
        const auto result= reinterpret_cast<INT_PTR>(ShellExecuteW(nullptr,L"open",url.c_str(),nullptr,nullptr,SW_SHOWNORMAL));
        if(result<=32)return Json{{"ok",false},{"error","系统浏览器无法打开该地址"}};return Json{{"ok",true}};
    });
    const auto assoc_status=[](){
        constexpr std::array<const wchar_t*,10> extensions{{L".fp",L".sp",L".rp",L".whp",L".pas",L".pml",L".pmr",L".sc",L".sb",L".pa"}};
        int claimed=0;std::vector<std::string> foreign;for(const auto* ext:extensions){HKEY key{};if(RegOpenKeyExW(HKEY_CURRENT_USER,(std::wstring(L"Software\\Classes\\")+ext).c_str(),0,KEY_READ,&key)!=ERROR_SUCCESS)continue;wchar_t value[256]{};DWORD bytes=sizeof(value),type=0;if(RegQueryValueExW(key,nullptr,nullptr,&type,reinterpret_cast<BYTE*>(value),&bytes)==ERROR_SUCCESS&&type==REG_SZ){const auto name=Utf8(value);if(name=="WPE64.Data")++claimed;else if(!name.empty())foreign.push_back(name);}RegCloseKey(key);}return Json{{"ok",true},{"enabled",claimed>0},{"claimed",claimed},{"foreign",foreign},{"owners",Json::array()},{"iconMissing",false},{"total",static_cast<int>(extensions.size())},{"icon",nullptr}};
    };
    bridge_->Register("getFileAssoc",[assoc_status](const Json&){return assoc_status();});
    bridge_->Register("setFileAssoc",[assoc_status](const Json& args){
        constexpr std::array<const wchar_t*,10> extensions{{L".fp",L".sp",L".rp",L".whp",L".pas",L".pml",L".pmr",L".sc",L".sb",L".pa"}};
        const bool on=args.value("on",false);const auto exe_path=[]{wchar_t path[32768]{};const auto n=GetModuleFileNameW(nullptr,path,static_cast<DWORD>(std::size(path)));return std::wstring(path,n);}();
        for(const auto* ext:extensions){HKEY key{};const auto sub=std::wstring(L"Software\\Classes\\")+ext;if(!on){RegDeleteTreeW(HKEY_CURRENT_USER,sub.c_str());continue;}DWORD disposition=0;if(RegCreateKeyExW(HKEY_CURRENT_USER,sub.c_str(),0,nullptr,0,KEY_WRITE,nullptr,&key,&disposition)==ERROR_SUCCESS){const wchar_t progid[]=L"WPE64.Data";RegSetValueExW(key,nullptr,0,REG_SZ,reinterpret_cast<const BYTE*>(progid),sizeof(progid));RegCloseKey(key);}}
        if(on){HKEY key{};if(RegCreateKeyExW(HKEY_CURRENT_USER,L"Software\\Classes\\WPE64.Data\\shell\\open\\command",0,nullptr,0,KEY_WRITE,nullptr,&key,nullptr)==ERROR_SUCCESS){const auto command=L"\""+exe_path+L"\" \"%1\"";RegSetValueExW(key,nullptr,0,REG_SZ,reinterpret_cast<const BYTE*>(command.c_str()),static_cast<DWORD>((command.size()+1)*sizeof(wchar_t)));RegCloseKey(key);}}
        SHChangeNotify(SHCNE_ASSOCCHANGED,SHCNF_IDLIST,nullptr,nullptr);return assoc_status();
    });
    bridge_->Register("pickTargetExe",[this](const Json&){
        ComPtr<IFileOpenDialog> dialog;Check(CoCreateInstance(CLSID_FileOpenDialog,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&dialog)),"Create executable dialog");DWORD flags=0;Check(dialog->GetOptions(&flags),"Get executable dialog options");Check(dialog->SetOptions(flags|FOS_FORCEFILESYSTEM|FOS_FILEMUSTEXIST|FOS_NOCHANGEDIR),"Configure executable dialog");const COMDLG_FILTERSPEC filters[]={{L"Windows executable (*.exe)",L"*.exe"},{L"所有文件",L"*.*"}};Check(dialog->SetFileTypes(2,filters),"Set executable filters");const auto hr=dialog->Show(window_);if(hr==HRESULT_FROM_WIN32(ERROR_CANCELLED))return Json{{"path",""}};Check(hr,"Show executable dialog");ComPtr<IShellItem> item;Check(dialog->GetResult(&item),"Get executable dialog result");CoString path;Check(item->GetDisplayName(SIGDN_FILESYSPATH,&path.value),"Get executable path");return Json{{"path",Utf8(path.value)}};
    });
    bridge_->Register("setSystemProxy",[this](const Json& args){
        HKEY key{};if(RegOpenKeyExW(HKEY_CURRENT_USER,L"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",0,KEY_SET_VALUE,&key)!=ERROR_SUCCESS)throw std::runtime_error("无法打开系统代理设置");const DWORD enabled=args.value("enable",false)?1:0;if(RegSetValueExW(key,L"ProxyEnable",0,REG_DWORD,reinterpret_cast<const BYTE*>(&enabled),sizeof(enabled))!=ERROR_SUCCESS){RegCloseKey(key);throw std::runtime_error("无法写入系统代理状态");}if(enabled){const auto socks=proxy_?proxy_->Stats():wpe::shell::Socks5Stats{};const auto host=proxy_display_host_.empty()?std::string("127.0.0.1"):proxy_display_host_;const auto server=Wide(host+":"+std::to_string(socks.port?socks.port:1080));if(RegSetValueExW(key,L"ProxyServer",0,REG_SZ,reinterpret_cast<const BYTE*>(server.c_str()),static_cast<DWORD>((server.size()+1)*sizeof(wchar_t)))!=ERROR_SUCCESS){RegCloseKey(key);throw std::runtime_error("无法写入系统代理地址");}}RegCloseKey(key);InternetSetOptionW(nullptr,INTERNET_OPTION_SETTINGS_CHANGED,nullptr,0);InternetSetOptionW(nullptr,INTERNET_OPTION_REFRESH,nullptr,0);return Json{{"ok",true},{"enabled",enabled!=0}};
    });
    bridge_->RegisterAsync("extractBytes",[this](const Json& args,WebBridge::Completion done){data_->Submit("extractBytes",args,std::move(done));});
    bridge_->RegisterAsync("extractPick",[this](const Json& args,WebBridge::Completion done){
        try{ComPtr<IFileOpenDialog> dialog;Check(CoCreateInstance(CLSID_FileOpenDialog,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&dialog)),"Create extraction dialog");DWORD flags=0;Check(dialog->GetOptions(&flags),"Get extraction dialog options");Check(dialog->SetOptions(flags|FOS_FORCEFILESYSTEM|FOS_FILEMUSTEXIST|FOS_NOCHANGEDIR),"Configure extraction dialog");const COMDLG_FILTERSPEC filters[]={{L"支持的文件",L"*.chlsx;*.filt;*.pa"},{L"所有文件",L"*.*"}};dialog->SetFileTypes(2,filters);const auto hr=dialog->Show(window_);if(hr==HRESULT_FROM_WIN32(ERROR_CANCELLED)){done({{"Path",""},{"Text",""},{"Count",0}},{});return;}Check(hr,"Show extraction dialog");ComPtr<IShellItem> item;Check(dialog->GetResult(&item),"Get extraction dialog result");CoString path;Check(item->GetDisplayName(SIGDN_FILESYSPATH,&path.value),"Get extraction path");std::ifstream input(path.value,std::ios::binary);std::string bytes((std::istreambuf_iterator<char>(input)),{});if(!input)throw std::runtime_error("无法读取所选文件");data_->Submit("extractBytes",{{"kind",args.value("kind",0)},{"name",Utf8(path.value)},{"content",Base64(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(bytes.data()),bytes.size()))}},std::move(done));}catch(const std::exception& e){done(nullptr,e.what());}
    });
    bridge_->RegisterAsync("saveExtraction",[this](const Json& args,WebBridge::Completion done){
        try{ComPtr<IFileSaveDialog> dialog;Check(CoCreateInstance(CLSID_FileSaveDialog,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&dialog)),"Create extraction save dialog");DWORD flags=0;Check(dialog->GetOptions(&flags),"Get extraction dialog options");Check(dialog->SetOptions(flags|FOS_FORCEFILESYSTEM|FOS_OVERWRITEPROMPT|FOS_NOCHANGEDIR),"Configure extraction dialog");const COMDLG_FILTERSPEC filters[]={{L"文本文件",L"*.txt"},{L"所有文件",L"*.*"}};Check(dialog->SetFileTypes(2,filters),"Set extraction filters");Check(dialog->SetDefaultExtension(L"txt"),"Set extraction extension");if(dialog->Show(window_)==HRESULT_FROM_WIN32(ERROR_CANCELLED)){done({{"ok",false}},{});return;}ComPtr<IShellItem> item;Check(dialog->GetResult(&item),"Get extraction save result");CoString path;Check(item->GetDisplayName(SIGDN_FILESYSPATH,&path.value),"Get extraction save path");const auto text=args.value("text",std::string{});std::ofstream output(path.value,std::ios::binary);output.write(text.data(),static_cast<std::streamsize>(text.size()));if(!output)throw std::runtime_error("无法写入提取文件");done({{"ok",true},{"path",Utf8(path.value)}},{});}catch(const std::exception& e){done(nullptr,e.what());}
    });
    bridge_->Register("pickLocalFile",[this](const Json&){
        ComPtr<IFileOpenDialog> dialog;Check(CoCreateInstance(CLSID_FileOpenDialog,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&dialog)),"Create local file dialog");DWORD flags=0;Check(dialog->GetOptions(&flags),"Get local file dialog options");Check(dialog->SetOptions(flags|FOS_FORCEFILESYSTEM|FOS_FILEMUSTEXIST|FOS_NOCHANGEDIR),"Configure local file dialog");const COMDLG_FILTERSPEC filters[]={{L"所有文件",L"*.*"}};Check(dialog->SetFileTypes(1,filters),"Set local file filters");const auto hr=dialog->Show(window_);if(hr==HRESULT_FROM_WIN32(ERROR_CANCELLED))return Json{{"path",""}};Check(hr,"Show local file dialog");ComPtr<IShellItem> item;Check(dialog->GetResult(&item),"Get local file result");CoString path;Check(item->GetDisplayName(SIGDN_FILESYSPATH,&path.value),"Get local file path");return Json{{"path",Utf8(path.value)}};
    });
    bridge_->RegisterAsync("exportLogs",[this](const Json& args,WebBridge::Completion done){
        try{ComPtr<IFileSaveDialog> dialog;Check(CoCreateInstance(CLSID_FileSaveDialog,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&dialog)),"Create log export dialog");DWORD flags=0;Check(dialog->GetOptions(&flags),"Get log dialog options");Check(dialog->SetOptions(flags|FOS_FORCEFILESYSTEM|FOS_OVERWRITEPROMPT|FOS_NOCHANGEDIR),"Configure log dialog");const COMDLG_FILTERSPEC filters[]={{L"CSV 文件",L"*.csv"},{L"所有文件",L"*.*"}};Check(dialog->SetFileTypes(2,filters),"Set log filters");Check(dialog->SetDefaultExtension(L"csv"),"Set log extension");if(dialog->Show(window_)==HRESULT_FROM_WIN32(ERROR_CANCELLED)){done({{"ok",false}},{});return;}ComPtr<IShellItem> item;Check(dialog->GetResult(&item),"Get log result");CoString path;Check(item->GetDisplayName(SIGDN_FILESYSPATH,&path.value),"Get log path");const auto stats=bridge_?Json{{"kind",args.value("kind",0)}, {"stats",target_stats_}}:Json::object();std::ofstream output(path.value,std::ios::binary);output<<"kind,stats\n"<<args.value("kind",0)<<",\""<<stats.dump()<<"\"\n";if(!output)throw std::runtime_error("无法写入日志导出文件");done({{"ok",true},{"path",Utf8(path.value)}},{});}catch(const std::exception& e){done(nullptr,e.what());}
    });
    bridge_->Register("uninstallDriver",[](const Json&){return Json{{"ok",false},{"error","当前构建没有加载可卸载的内核驱动"}};});
    bridge_->RegisterAsync("registerHotkey",[this](const Json& args,WebBridge::Completion done){
        const int index=args.value("index",0);const auto text=args.value("text",std::string{});if(index<1||index>12||text.empty()){done({{"ok",false}},"快捷键参数无效");return;}
        UINT modifiers=0;UINT key=0;auto upper=text;std::transform(upper.begin(),upper.end(),upper.begin(),[](unsigned char c){return static_cast<char>(std::toupper(c));});
        if(upper.find("CTRL")!=std::string::npos)modifiers|=MOD_CONTROL;if(upper.find("ALT")!=std::string::npos)modifiers|=MOD_ALT;if(upper.find("SHIFT")!=std::string::npos)modifiers|=MOD_SHIFT;if(upper.find("WIN")!=std::string::npos)modifiers|=MOD_WIN;
        const auto pos=upper.find('F');if(pos!=std::string::npos){int number=0;try{number=std::stoi(upper.substr(pos+1));}catch(...){number=0;}if(number>=1&&number<=24)key=VK_F1+number-1;}
        if(!key){done({{"ok",false}},"快捷键必须包含 F1 到 F24");return;}const auto id=0x574500+index;UnregisterHotKey(window_,id);if(!RegisterHotKey(window_,id,modifiers,key)){done({{"ok",false}},"快捷键已被其他程序占用");return;}hotkey_ids_[static_cast<std::size_t>(index-1)]=id;data_->Submit("registerHotkey",args,[done](Json value,std::string error) mutable {done(std::move(value),std::move(error));});
    });
    RegisterTargetMethods();
    // Remote management is a persisted setting in the original application.
    // Restore it after the data worker is ready so a restart does not silently
    // leave an enabled service stopped.
    data_->Submit("getRemoteSetting",Json::object(),[this](Json setting,std::string error){
        if(closing_||!error.empty()||!setting.value("IsRemote",false))return;
        data_->Submit("__wpcSnapshot",Json::object(),[this,setting=std::move(setting)](Json snapshot,std::string snapshot_error){
            if(closing_||!snapshot_error.empty()){if(!snapshot_error.empty()&&bridge_)bridge_->PushEvent("wpc:state",{{"running",false},{"error",snapshot_error}});return;}
            std::string start_error;
            if(!StartWpc(setting,snapshot,start_error)&&bridge_)bridge_->PushEvent("wpc:state",{{"running",false},{"error",start_error.empty()?"WPC 服务初始化失败":start_error}});
        });
    });
    if(options_.test){
        bridge_->Register("__testStage",[this](const Json& args){report_["lastStage"]=args;return Json{{"ok",true}};});
        bridge_->Register("__testCancelNextFile",[this](const Json&){test_cancel_file_=true;return Json{{"ok",true}};});
        bridge_->Register("__testUseLastEncryptedExport",[this](const Json&){
            const auto target=options_.report/L"encrypted-export.sc";fs::copy_file(options_.report/L"export.sc",target,fs::copy_options::overwrite_existing);test_encrypted_import_=true;return Json{{"path",Utf8(target.wstring())}};
        });
        bridge_->Register("__testConfirm",[this](const Json&){
            bridge_->Ask("confirm",{{"title","C++ ↔ 原 Vue 双向桥测试"},{"content","此对话框由原 Vue 渲染，自动测试将点击确定。"},{"icon",2}},[this](Json answer){report_["originalVueConfirmed"]=answer;bridge_->PushEvent("toast",{{"level",1},{"text","NATIVE_BRIDGE_EVENT_OK"}});});return Json{{"ok",true}};});
        bridge_->Register("__testDone",[this](const Json& args){report_["frontend"]=args;PostMessageW(window_,app_test,0,0);return Json{{"ok",true}};});
    }
}
std::filesystem::path Host::HookDll() const {
    // A running target may still have the previous package DLL mapped (Windows
    // locks a loaded module).  Prefer the versioned side-by-side name when it
    // is present so an updated shell never pairs a new IPC schema with an old
    // injected runtime; the unversioned name remains the normal fallback.
    const auto packaged_next=options_.assets.parent_path()/L"wpe64-hook.next.dll";
    if(fs::is_regular_file(packaged_next))return packaged_next;
    const auto packaged=options_.assets.parent_path()/L"wpe64-hook.dll";
    if(fs::is_regular_file(packaged))return packaged;
    std::wstring module(32768,L'\0');
    const auto count=GetModuleFileNameW(nullptr,module.data(),static_cast<DWORD>(module.size()));
    if(count!=0&&count<module.size()){
        module.resize(count);
        const auto beside=fs::path(module).parent_path()/L"wpe64-hook.dll";
        if(fs::is_regular_file(beside))return beside;
    }
    throw std::runtime_error("未找到 wpe64-hook.dll，请先构建目标注入模块");
}
std::filesystem::path Host::X86HookDll() const {
    const auto packaged_next=options_.assets.parent_path()/L"wpe64-hook-x86.next.dll";
    if(fs::is_regular_file(packaged_next))return packaged_next;
    const auto packaged=options_.assets.parent_path()/L"wpe64-hook-x86.dll";
    if(fs::is_regular_file(packaged))return packaged;
    return {};
}
std::filesystem::path Host::X86Helper() const {
    const auto packaged=options_.assets.parent_path()/L"wpe64-x86-helper.exe";
    if(fs::is_regular_file(packaged))return packaged;
    return {};
}
void Host::RememberInjection(DWORD pid,const fs::path& path,const std::string& method,const std::wstring& args){
    last_inject_={{"pid",static_cast<std::int64_t>(pid)},{"path",Utf8(path.wstring())},
                  {"method",method},{"args",Utf8(args)}};
}
Json Host::InjectStatus() const {
    const auto state=target_?target_->State():wpe::IpcLinkState::Idle;
    return {{"state",state==wpe::IpcLinkState::Attached?"attached":state==wpe::IpcLinkState::Attaching?"attaching":
                     state==wpe::IpcLinkState::Disconnected?"disconnected":"idle"},
            {"pid",target_?target_->TargetPid():0},{"name",""},
            {"is64",target_?target_->TargetIs64():false},{"hooked",hook_running_},
            {"dropped",target_stats_.value("dropped",0)},
            {"ws1",target_stats_.value("ws1",false)},{"ws2",target_stats_.value("ws2",false)},
            {"msws",target_stats_.value("msws",false)}};
}
Json Host::InjectStats() const {
    Json result=target_stats_.is_object()?target_stats_:Json::object();
    result["pid"]=target_?target_->TargetPid():0;
    result["hooked"]=hook_running_;
    result["dropped"]=result.value("dropped",0);
    const auto packets=result.value("packets",Json::array());
    auto packet=[&](std::size_t i){return packets.is_array()&&i<packets.size()?packets[i].get<std::int64_t>():0;};
    result["total"]=packet(0);result["send"]=packet(1);result["sendTo"]=packet(2);
    result["recv"]=packet(3);result["recvFrom"]=packet(4);result["wsaSend"]=packet(5);
    result["wsaSendTo"]=packet(6);result["wsaRecv"]=packet(7);result["wsaRecvFrom"]=packet(8);
    result["totalSend"]=packet(9);result["totalRecv"]=packet(10);
    const auto globals=result.value("filterGlobals",Json::array());
    const auto filter_execute=globals.is_array()&&globals.size()?globals[0].get<std::int64_t>():0;
    result["queue"]=0;result["rate"]=0;result["filterExecute"]=filter_execute;result["filterPacket"]=filter_execute;
    return result;
}
Json Host::EnumerateProcesses() const {
    Json rows=Json::array();
    const auto snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(snapshot==INVALID_HANDLE_VALUE)return rows;
    PROCESSENTRY32W entry{};entry.dwSize=sizeof(entry);
    if(Process32FirstW(snapshot,&entry))do{
        std::string path;
        HANDLE process=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,entry.th32ProcessID);
        if(process){wchar_t buffer[32768]{};DWORD length=static_cast<DWORD>(std::size(buffer));
            if(QueryFullProcessImageNameW(process,0,buffer,&length))path=Utf8(std::wstring_view(buffer,length));CloseHandle(process);}
        rows.push_back({{"ProcessID",entry.th32ProcessID},{"ProcessName",Utf8(entry.szExeFile)},
                        {"ProcessPath",path}});
    }while(Process32NextW(snapshot,&entry));
    CloseHandle(snapshot);return rows;
}
void Host::QueueTargetFrame(wpe::ByteBuffer frame,bool packet_channel){
    {std::lock_guard lock(target_mutex_);if(target_frames_.size()<8192)target_frames_.emplace_back(std::move(frame),packet_channel);}
    if(window_)PostMessageW(window_,app_target,0,0);
}
void Host::QueueProxyPacket(wpe::shell::ProxyPacket packet){
    if(packet.bytes.empty())return;
    {std::lock_guard lock(proxy_mutex_);if(proxy_frames_.size()<8192)proxy_frames_.push_back(std::move(packet));}
    if(window_)PostMessageW(window_,app_target,0,0);
}
void Host::QueueTargetResult(WebBridge::Completion done,Json value,std::string error){
    {std::lock_guard lock(target_mutex_);target_results_.push_back({std::move(done),std::move(value),std::move(error)});}
    if(window_)PostMessageW(window_,app_target,0,0);
}
Json Host::PacketRow(const wpe::Packet& packet) const {
    const auto& bytes=packet.modified?packet.modified:packet.raw;
    const auto length=bytes?static_cast<std::int64_t>(bytes->size()):0;
    return {
        {"Id",packet.id},{"Time",PacketTime(packet.time_ticks)},{"Socket",packet.socket},
        {"Type",packet.packet_type},{"From",PacketText(packet.from)},{"FromLocation",""},
        {"To",PacketText(packet.to)},{"ToLocation",""},{"Len",length},
        {"Preview",PacketHex(bytes)},{"Action",packet.filter_action}
    };
}
Json Host::ProxyPacketRow(const ProxyCapture& capture) const {
    const auto& packet=capture.packet;
    const auto& bytes=packet.modified?packet.modified:packet.raw;
    const auto length=bytes?static_cast<std::int64_t>(bytes->size()):0;
    return {
        {"Id",packet.id},{"Time",PacketTime(packet.time_ticks)},{"Socket",packet.socket},{"TheologyID",0},
        {"Type",packet.packet_type},{"WebSocketType",0},{"ClientAddr",capture.client_addr},
        {"ClientLocation",""},{"ServerAddr",capture.server_addr},{"ServerLocation",""},
        {"ServerDomain",capture.server_domain},{"DomainType",capture.domain_type},{"Len",length},
        {"Preview",PacketHex(bytes)},{"Action",packet.filter_action}
    };
}
Json Host::PacketDetail(const wpe::Packet& packet) const {
    const auto raw=packet.raw?Base64(*packet.raw):std::string{};
    const auto modified=packet.modified?Base64(*packet.modified):std::string{};
    return {{"id",packet.id},{"packet",modified.empty()?Json(nullptr):Json(modified)},
            {"raw",raw.empty()?Json(nullptr):Json(raw)},
            {"modified",packet.raw!=packet.modified}};
}
const wpe::Packet* Host::FindPacket(std::int64_t id) const {
    for(auto it=packet_capture_.rbegin();it!=packet_capture_.rend();++it)
        if(it->id==id)return &*it;
    return nullptr;
}
const wpe::Packet* Host::FindProxyPacket(std::int64_t id) const {
    for(auto it=proxy_capture_.rbegin();it!=proxy_capture_.rend();++it)
        if(it->packet.id==id)return &it->packet;
    return nullptr;
}
wpe::Packet* Host::FindPacketMutable(std::int64_t id) {
    for(auto it=packet_capture_.rbegin();it!=packet_capture_.rend();++it)
        if(it->id==id)return &*it;
    return nullptr;
}
Host::ProxyCapture* Host::FindProxyCaptureMutable(std::int64_t id) {
    for(auto it=proxy_capture_.rbegin();it!=proxy_capture_.rend();++it)
        if(it->packet.id==id)return &*it;
    return nullptr;
}
void Host::ClearCapturedPackets(){
    packet_capture_.clear();
    if(bridge_)bridge_->PushEvent("feed:clear",{{"list",0}});
}
void Host::ClearProxyPackets(){
    proxy_capture_.clear();
    proxy_filter_dropped_.store(0,std::memory_order_relaxed);
    proxy_filter_diagnostics_.Reset();
    if(bridge_)bridge_->PushEvent("feed:clear",{{"list",1}});
}
void Host::RefreshProxyCaptureFilter(){
    if(!data_)return;
    data_->Submit("__proxyRuntimeConfiguration",Json::object(),[this](Json config,std::string error){
        if(!error.empty()||!config.is_object())return;
        std::lock_guard lock(proxy_filter_mutex_);
        proxy_capture_filter_=config.value("captureFilter",Json::object());
    });
}
bool Host::ProxyCaptureAllowed(const wpe::shell::ProxyPacket& frame,
                               ProxyFilterEvidence* evidence) const {
    if(evidence)*evidence={};
    Json filter;
    {
        std::lock_guard lock(proxy_filter_mutex_);
        filter=proxy_capture_filter_;
    }
    if(!filter.is_object())return true;

    const bool check_socket=filter.value("checkSocket",false);
    const bool check_ip=filter.value("checkIP",false);
    const bool check_port=filter.value("checkPort",false);
    const bool check_head=filter.value("checkHead",false);
    const bool check_data=filter.value("checkData",false);
    const bool check_length=filter.value("checkLen",false);
    const bool check_type=filter.value("checkType",false);
    if(!check_socket&&!check_ip&&!check_port&&!check_head&&!check_data&&!check_length&&!check_type)return true;

    const auto bytes=std::span<const std::uint8_t>(frame.bytes.data(),frame.bytes.size());
    const auto hex_match=[&](std::string_view pattern,bool prefix){
        for(const auto alternative:FilterHexAlternatives(pattern)){
            std::vector<std::uint8_t> needle;
            if(!HexBytes(alternative,needle)||needle.size()>bytes.size())continue;
            if(prefix&&std::equal(needle.begin(),needle.end(),bytes.begin()))return true;
            if(!prefix&&ContainsBytes(bytes,std::span<const std::uint8_t>(needle.data(),needle.size())))return true;
        }
        return false;
    };
    const auto data_match=[&](std::string_view pattern){
        if(hex_match(pattern,false))return true;
        for(const auto alternative:FilterHexAlternatives(pattern)){
            const std::string text(alternative);
            if(!text.empty()&&std::search(frame.bytes.begin(),frame.bytes.end(),text.begin(),text.end())!=frame.bytes.end())return true;
        }
        return false;
    };
    const auto ip_match=[&](){
        for(const auto& part:FilterParts(filter.value("ipValue",std::string{})))
            if(AddressHasIp(frame.client_addr,part)||AddressHasIp(frame.server_addr,part))return true;
        return false;
    };
    const auto port_match=[&](){return AddressHasPort(frame.client_addr,filter.value("portValue",std::string{}))||
                                      AddressHasPort(frame.server_addr,filter.value("portValue",std::string{}));};
    const auto socket_match=NumberInList(filter.value("socketValue",std::string{}),static_cast<std::int64_t>(frame.socket));
    const auto head_match=hex_match(filter.value("headValue",std::string{}),true);
    const auto content_match=data_match(filter.value("dataValue",std::string{}));
    const auto length_match=LengthMatches(filter.value("lenValue",std::string{}),static_cast<std::int64_t>(frame.bytes.size()));
    const auto type_match=TypeMatches(filter,frame.packet_type);
    if(evidence){
        evidence->header_match=check_head&&head_match;
        evidence->type_match=check_type&&type_match;
    }
    const bool not_show=filter.value("notShow",true);
    return wpe::shell::CaptureFilterAllowed({
        not_show, check_socket, socket_match, check_ip, ip_match(),
        check_port, port_match(), check_head, head_match, check_data,
        content_match, check_length, length_match, check_type, type_match
    });
}
void Host::HandleTargetFrame(wpe::ByteBuffer frame,bool packet_channel){
    if(packet_channel){
        try{
            const auto packet=wpe::PacketFrame::Decode(frame);
            packet_capture_.push_back(packet);
            constexpr std::size_t kCaptureLimit=500000;
            if(packet_capture_.size()>kCaptureLimit){
                const auto drop=packet_capture_.size()-kCaptureLimit;
                packet_capture_.erase(packet_capture_.begin(),packet_capture_.begin()+static_cast<std::ptrdiff_t>(drop));
                if(bridge_)bridge_->PushEvent("feed:trim",{{"list",0},{"keep",static_cast<std::int64_t>(packet_capture_.size())}});
            }
            if(bridge_)bridge_->PushEvent("feed:append",{{"list",0},{"rows",Json::array({PacketRow(packet)})}});
        }catch(...){ }
        return;
    }
    try{
        wpe::IpcReader reader(frame);const auto event=static_cast<wpe::IpcEvent>(reader.U8());
        switch(event){
        case wpe::IpcEvent::Stats:{
            const auto read_count=[&](const char* what){
                const auto count=reader.I32();
                if(count<0||count>100000)throw std::runtime_error(std::string(what)+" count is invalid");
                return count;
            };
            const bool sends=reader.Bool(),robots=reader.Bool();Json filters=Json::array(),send_rows=Json::array();
            const auto filter_count=read_count("Stats filter");for(std::int32_t i=0;i<filter_count;++i){const auto id=reader.Guid_().ToString();filters.push_back({{"id",id},{"count",reader.I64()}});}
            const auto send_count=read_count("Stats send");for(std::int32_t i=0;i<send_count;++i)send_rows.push_back({{"id",reader.Guid_().ToString()},{"count",reader.I64()},{"success",reader.I64()},{"fail",reader.I64()}});
            Json globals=Json::array();for(int i=0;i<6;++i)globals.push_back(reader.I64());
            Json packets=Json::array();const auto robot_count=read_count("Stats robot");for(std::int32_t i=0;i<robot_count;++i){reader.Guid_();reader.I64();}
            for(int i=0;i<11;++i)packets.push_back(reader.I64());
            if(reader.Remaining()!=0)throw std::runtime_error("Stats event has trailing bytes");
            const auto filter_execute=globals.empty()?0LL:globals[0].get<std::int64_t>();
            send_running_=sends;target_stats_={{"sendRunning",sends},{"robotRunning",robots},{"filters",filters},{"sends",send_rows},{"filterGlobals",globals},{"filterExecute",filter_execute},{"filterPacket",filter_execute},{"packets",packets},{"dropped",target_stats_.value("dropped",0)}};
            bridge_->PushEvent("send:running",{{"running",sends}});bridge_->PushEvent("target:stats",target_stats_);break;
        }
        case wpe::IpcEvent::HookState:{
            hook_running_=reader.Bool();target_stats_["ws1"]=reader.Bool();target_stats_["ws2"]=reader.Bool();target_stats_["msws"]=reader.Bool();
            if(reader.Remaining()!=0)throw std::runtime_error("HookState event has trailing bytes");
            bridge_->PushEvent("inject:state",InjectStatus());break;
        }
        case wpe::IpcEvent::StoreAdded:
            if(data_)data_->SubmitStoreEvent(std::move(frame),[](Json,std::string){});break;
        case wpe::IpcEvent::FilterLog:{
            const auto name=reader.Str();const auto action=reader.I32(),matches=reader.I32(),type=reader.I32(),length=reader.I32();
            if(reader.Remaining()!=0)throw std::runtime_error("FilterLog event has trailing bytes");
            bridge_->PushEvent("filter:log",{{"name",name?Utf8(std::wstring(name->begin(),name->end())):""},{"action",action},{"matches",matches},{"type",type},{"length",length}});break;
        }
        case wpe::IpcEvent::Dropped:{const auto count=reader.I64();if(reader.Remaining()!=0)throw std::runtime_error("Dropped event has trailing bytes");target_stats_["dropped"]=count;bridge_->PushEvent("inject:dropped",{{"count",count}});break;}
        case wpe::IpcEvent::Log:{const auto source=reader.Str(),message=reader.Str();if(reader.Remaining()!=0)throw std::runtime_error("Log event has trailing bytes");bridge_->PushEvent("filter:log",{{"source",source?Utf8(std::wstring(source->begin(),source->end())):""},{"message",message?Utf8(std::wstring(message->begin(),message->end())):""}});break;}
        case wpe::IpcEvent::Fatal:{const auto text=reader.Str();if(reader.Remaining()!=0)throw std::runtime_error("Fatal event has trailing bytes");bridge_->PushEvent("toast",{{"level",4},{"text",text?Utf8(std::wstring(text->begin(),text->end())):"目标进程连接失败"}});break;}
        default:throw std::runtime_error("Unknown target event");
        }
    }catch(const std::exception& error){if(bridge_)bridge_->PushEvent("toast",{{"level",4},{"text",error.what()}});}
}
void Host::DrainTarget(){
    std::deque<TargetResult> results;std::deque<std::pair<wpe::ByteBuffer,bool>> frames;
    {std::lock_guard lock(target_mutex_);results.swap(target_results_);frames.swap(target_frames_);}
    for(auto& result:results){
        if(!result.done && result.value.is_object() && result.value.value("__event","")=="inject:state"){
            if(bridge_)bridge_->PushEvent("inject:state",std::move(result.value.at("value")));continue;
        }
        if(result.done)try{result.done(std::move(result.value),std::move(result.error));}catch(...){ }
    }
    for(auto& frame:frames)if(bridge_&&!closing_)HandleTargetFrame(std::move(frame.first),frame.second);
}
void Host::DrainProxy(){
    std::deque<wpe::shell::ProxyPacket> frames;
    {std::lock_guard lock(proxy_mutex_);frames.swap(proxy_frames_);}
    if(!bridge_||closing_||frames.empty())return;
    Json rows=Json::array();
    for(auto& frame:frames){
        proxy_filter_diagnostics_.seen.fetch_add(1,std::memory_order_relaxed);
        switch(frame.packet_type){
        case 13: proxy_filter_diagnostics_.tcp_requests.fetch_add(1,std::memory_order_relaxed);break;
        case 15: proxy_filter_diagnostics_.tcp_responses.fetch_add(1,std::memory_order_relaxed);break;
        case 14: proxy_filter_diagnostics_.udp_requests.fetch_add(1,std::memory_order_relaxed);break;
        case 16: proxy_filter_diagnostics_.udp_responses.fetch_add(1,std::memory_order_relaxed);break;
        default: proxy_filter_diagnostics_.other.fetch_add(1,std::memory_order_relaxed);break;
        }
        ProxyFilterEvidence evidence;
        const bool allowed=ProxyCaptureAllowed(frame,&evidence);
        if(evidence.header_match)proxy_filter_diagnostics_.header_matches.fetch_add(1,std::memory_order_relaxed);
        if(evidence.type_match)proxy_filter_diagnostics_.type_matches.fetch_add(1,std::memory_order_relaxed);
        if(!allowed){
            proxy_filter_dropped_.fetch_add(1,std::memory_order_relaxed);
            continue;
        }
        proxy_filter_diagnostics_.allowed.fetch_add(1,std::memory_order_relaxed);
        ProxyCapture capture;
        capture.packet.id=next_proxy_packet_id_++;
        capture.packet.time_ticks=NowPacketTicks();
        capture.packet.socket=static_cast<std::int64_t>(frame.socket);
        capture.packet.packet_type=frame.packet_type;
        capture.packet.filter_action=4;
        capture.packet.from=U16(frame.client_addr);
        capture.packet.to=U16(frame.server_addr);
        capture.packet.raw=std::move(frame.bytes);
        // Runtime proxy packets do not pass through PacketFrame::Decode, so
        // there is no same-buffer marker to populate `modified`. Keep the
        // current bytes available to the detail/editor path while preserving
        // value equality (PacketDetail will still report this as unmodified).
        capture.packet.modified=capture.packet.raw;
        capture.client_addr=std::move(frame.client_addr);
        capture.server_addr=std::move(frame.server_addr);
        capture.server_domain=std::move(frame.server_domain);
        capture.domain_type=frame.domain_type;
        proxy_capture_.push_back(std::move(capture));
        rows.push_back(ProxyPacketRow(proxy_capture_.back()));
    }
    constexpr std::size_t kCaptureLimit=500000;
    if(proxy_capture_.size()>kCaptureLimit){
        const auto drop=proxy_capture_.size()-kCaptureLimit;
        proxy_capture_.erase(proxy_capture_.begin(),proxy_capture_.begin()+static_cast<std::ptrdiff_t>(drop));
        bridge_->PushEvent("feed:trim",{{"list",1},{"keep",static_cast<std::int64_t>(proxy_capture_.size())}});
    }
    bridge_->PushEvent("feed:append",{{"list",1},{"rows",std::move(rows)}});
}
void Host::AbortTargetInjection(WebBridge::Completion done,std::string error){
    if(!target_){QueueTargetResult(std::move(done),Json{},std::move(error));return;}
    target_->Detach([this,done=std::move(done),error=std::move(error)](bool ok,std::string detach_error) mutable {
        if(!ok&&!detach_error.empty()){
            if(!error.empty())error+="；";
            error+="清理目标连接失败: "+detach_error;
        }
        QueueTargetResult(std::move(done),Json{},std::move(error));
    });
}
void Host::SyncTargetConfiguration(WebBridge::Completion done){
    if(!data_||!target_||target_->State()!=wpe::IpcLinkState::Attached){done(nullptr,"尚未连接目标进程");return;}
    data_->SubmitTargetConfiguration([this,done=std::move(done)](Json config,std::string error) mutable {
        if(!error.empty()){QueueTargetResult(std::move(done),nullptr,std::move(error));return;}
        try{
            std::vector<wpe::ByteBuffer> requests;
            wpe::IpcWriter flags;for(const auto& v:config.at("hookFlags"))flags.Bool(v.get<bool>());
            wpe::IpcWriter request;request.U8(static_cast<std::uint8_t>(wpe::IpcCommand::SetConfig));request.U8(static_cast<std::uint8_t>(wpe::ConfigKind::HookFlags));request.Bytes(flags.ToArray());requests.push_back(request.ToArray());
            wpe::IpcWriter filters;filters.I32(static_cast<std::int32_t>(config.at("filters").size()));
            for(const auto& item:config.at("filters")){
                filters.Bool(item.value("enabled",false));filters.Guid_(wpe::Guid::Parse(item.value("id",std::string{})));filters.Str(U16(item.value("name",std::string{})));
                for(const auto& pair:std::array<std::pair<const char*,const char*>,4>{{{"appointHeader","header"},{"appointSocket","socket"},{"appointLength","length"},{"appointPort","port"}}}){filters.Bool(item.value(pair.first,false));filters.Str(U16(item.value(pair.second,std::string{})));}
                filters.I32(item.value("mode",0));filters.I32(item.value("action",0));filters.Bool(item.value("execute",false));filters.I32(item.value("executeType",2));filters.Guid_(wpe::Guid::Parse(item.value("executeId",std::string("00000000-0000-0000-0000-000000000000"))));
                const auto mask=item.value("functionMask",0);for(int i=0;i<12;++i)filters.Bool((mask&(1<<i))!=0);filters.I32(item.value("startFrom",0));filters.Bool(item.value("progressionDone",false));filters.Bool(item.value("progressionContinuous",false));filters.I32(item.value("progressionStep",1));filters.Bool(item.value("progressionCarry",false));filters.I32(item.value("progressionCarryNumber",1));filters.Str(U16(item.value("progressionPosition",std::string{})));filters.I32(item.value("progressionCount",0));filters.Str(U16(item.value("excludePosition",std::string{})));filters.Str(U16(item.value("randomPosition",std::string{})));filters.Str(U16(item.value("search",std::string{})));filters.Str(U16(item.value("modify",std::string{})));
            }
            request=wpe::IpcWriter();request.U8(static_cast<std::uint8_t>(wpe::IpcCommand::SetConfig));request.U8(static_cast<std::uint8_t>(wpe::ConfigKind::Filters));request.Bytes(filters.ToArray());requests.push_back(request.ToArray());
            wpe::IpcWriter runtime;const auto& r=config.at("runtime");runtime.Bool(r.value("speedMode",false));runtime.I32(r.value("systemSocket",0));runtime.I32(r.value("listExecute",1));runtime.I32(r.value("filterExecute",1));runtime.Bool(false);
            const auto& capture=config.value("captureFilter",Json::object());
            runtime.Bool(capture.value("notShow",true));
            for(const auto& pair:std::array<std::pair<const char*,const char*>,6>{{{"checkSocket","socketValue"},{"checkIP","ipValue"},{"checkPort","portValue"},{"checkHead","headValue"},{"checkData","dataValue"},{"checkLen","lenValue"}}}){runtime.Bool(capture.value(pair.first,false));runtime.Str(U16(capture.value(pair.second,std::string{})));}
            runtime.Bool(capture.value("checkType",false));
            for(const auto* key:std::array<const char*,12>{{"send","sendTo","recv","recvFrom","wsaSend","wsaSendTo","wsaRecv","wsaRecvFrom","tcpReq","udpReq","tcpResp","udpResp"}})runtime.Bool(capture.value(key,false));
            request=wpe::IpcWriter();request.U8(static_cast<std::uint8_t>(wpe::IpcCommand::SetConfig));request.U8(static_cast<std::uint8_t>(wpe::ConfigKind::Runtime));request.Bytes(runtime.ToArray());requests.push_back(request.ToArray());
            wpe::IpcWriter sends;sends.I32(static_cast<std::int32_t>(config.at("sends").size()));
            for(const auto& item:config.at("sends")){sends.Bool(item.value("enabled",false));sends.Guid_(wpe::Guid::Parse(item.value("id",std::string{})));sends.Str(U16(item.value("name",std::string{})));sends.Bool(item.value("systemSocket",false));sends.I32(item.value("loopCount",1));sends.I32(item.value("loopInterval",1000));sends.Str(U16(item.value("notes",std::string{})));sends.I32(static_cast<std::int32_t>(item.at("packets").size()));for(const auto& packet:item.at("packets")){sends.I32(packet.value("socket",0));sends.I32(packet.value("type",0));sends.Str(U16(packet.value("from",std::string{})));sends.Str(U16(packet.value("to",std::string{})));const auto& bytes=packet.at("bytes");sends.Bytes(bytes.is_binary()?wpe::ByteBuffer(bytes.get_binary().begin(),bytes.get_binary().end()):wpe::ByteBuffer{});}}
            request=wpe::IpcWriter();request.U8(static_cast<std::uint8_t>(wpe::IpcCommand::SetConfig));request.U8(static_cast<std::uint8_t>(wpe::ConfigKind::Sends));request.Bytes(sends.ToArray());requests.push_back(request.ToArray());
            auto shared=std::make_shared<std::pair<std::size_t,std::string>>(0,std::string{});auto pump=std::make_shared<std::function<void()>>();*pump=[this,requests=std::move(requests),shared,pump,done=std::move(done)]() mutable {if(shared->first==requests.size()){QueueTargetResult(std::move(done),{{"ok",true}},{});return;}target_->CallVoid(requests[shared->first],[this,shared,pump,done](bool ok,std::string error) mutable {if(!ok){QueueTargetResult(std::move(done),nullptr,std::move(error));return;}++shared->first;(*pump)();});};(*pump)();
        }catch(const std::exception& e){QueueTargetResult(std::move(done),nullptr,e.what());}
    });
}
void Host::RegisterTargetMethods(){
    bridge_->Register("getInjectProcessList",[this](const Json&){return EnumerateProcesses();});
    bridge_->Register("getProcessRows",[this](const Json&){Json rows=Json::array();for(auto row:EnumerateProcesses()){row["IsCheck"]=false;row["ModuleName"]=row.value("ProcessName",std::string{});rows.push_back(std::move(row));}return Json{{"rows",std::move(rows)}};});
    bridge_->Register("getProcessIcons",[](const Json&){return Json{{"icons",Json::object()}};});
    bridge_->Register("cancelPickWindow",[](const Json&){return Json{{"ok",true}};});
    bridge_->Register("pickWindow",[](const Json&){
        POINT point{};if(!GetCursorPos(&point))return Json{{"ok",false},{"error","无法读取鼠标位置"}};
        const auto window=WindowFromPoint(point);DWORD pid=0;GetWindowThreadProcessId(window,&pid);
        if(!pid||pid==GetCurrentProcessId())return Json{{"ok",false},{"error","请把鼠标移到目标窗口后重试"}};
        return Json{{"ok",true},{"pid",pid}};
    });
    bridge_->Register("enterInjectMode",[this](const Json&){return Json{{"ok",true},{"lastInject",last_inject_}};});
    bridge_->Register("getInjectStatus",[this](const Json&){return InjectStatus();});
    bridge_->Register("getInjectStats",[this](const Json&){return InjectStats();});
    bridge_->Register("getPacketDetail",[this](const Json& args){
        const auto id=args.value("id",static_cast<std::int64_t>(0));
        const auto* packet=args.value("list",0)==0?FindPacket(id):FindProxyPacket(id);
        return packet?PacketDetail(*packet):Json(nullptr);
    });
    // The data worker owns the persistent send-list editor.  Runtime packet
    // and proxy rows live in the host deques instead, so route those two lists
    // here rather than returning the old "proxy/inject source is not wired"
    // placeholder from data_edit.cpp.
    const auto edit_id=[](const Json& args)->std::int64_t{
        try{
            if(args.contains("id")&&args.at("id").is_string())return std::stoll(args.at("id").get<std::string>());
            return args.value("id",static_cast<std::int64_t>(0));
        }catch(...){return 0;}
    };
    bridge_->RegisterAsync("openPacketEdit",[this,edit_id](const Json& args,WebBridge::Completion done){
        const auto list=args.value("list",std::string("proxy"));
        if(list=="send"){
            data_->Submit("openPacketEdit",args,[done](Json value,std::string error) mutable {done(std::move(value),std::move(error));});
            return;
        }
        const auto id=edit_id(args);
        const auto* packet=list=="packet"?FindPacket(id):FindProxyPacket(id);
        if(!packet){done(Json{{"Id",""},{"List",list}},{});return;}
        const auto bytes=packet->modified?packet->modified:packet->raw;
        done(Json{{"Id",std::to_string(packet->id)},
                  {"List",list},
                  {"Socket",packet->socket},
                  {"Type",packet->packet_type},
                  {"From",PacketText(packet->from)},
                  {"To",PacketText(packet->to)},
                  {"Buffer",Base64(bytes?std::span<const std::uint8_t>(*bytes):std::span<const std::uint8_t>())},
                  {"CanSendBySession",false},
                  {"SystemSocket",system_socket_}},{});
    });
    bridge_->RegisterAsync("savePacketEdit",[this,edit_id](const Json& args,WebBridge::Completion done){
        const auto list=args.value("list",std::string("proxy"));
        if(list=="send"){
            data_->Submit("savePacketEdit",args,[done](Json value,std::string error) mutable {done(std::move(value),std::move(error));});
            return;
        }
        const auto bytes=Unbase64(args.value("buffer",std::string{}));
        if(bytes.empty()){done(Json{{"error","封包数据为空"}},{});return;}
        const auto id=edit_id(args);
        wpe::Packet* packet=nullptr;
        ProxyCapture* proxy_capture=nullptr;
        if(list=="packet")packet=FindPacketMutable(id);
        else if(list=="proxy"){
            proxy_capture=FindProxyCaptureMutable(id);
            packet=proxy_capture?&proxy_capture->packet:nullptr;
        }
        if(!packet){done(Json{{"error","这条封包已经不在列表里了"}},{});return;}
        packet->socket=args.value("socket",static_cast<std::int64_t>(0));
        packet->modified=bytes;
        if(packet->raw&&packet->modified&&*packet->raw==*packet->modified)packet->modified=packet->raw;
        const auto row=list=="packet"?PacketRow(*packet):ProxyPacketRow(*proxy_capture);
        if(bridge_)bridge_->PushEvent("feed:update",{{"list",list=="packet"?0:1},{"row",row}});
        done(Json{{"error",""}},{});
    });
    bridge_->Register("setSelectedPacket",[](const Json&){return Json{{"ok",true}};});
    bridge_->Register("clearPackets",[this](const Json& args){
        if(args.value("list",0)==0)ClearCapturedPackets();
        else ClearProxyPackets();
        return Json{{"ok",true}};
    });
    const auto packet_for=[this](std::int64_t id)->const wpe::Packet*{
        if(const auto* packet=FindPacket(id))return packet;
        return FindProxyPacket(id);
    };
    const auto packet_for_list=[this,packet_for](const Json& args)->const wpe::Packet*{
        std::int64_t id=0;
        try{
            if(args.contains("id")&&args.at("id").is_string())id=std::stoll(args.at("id").get<std::string>());
            else id=args.value("id",static_cast<std::int64_t>(0));
        }catch(...){return nullptr;}
        const auto list=args.value("list",std::string("proxy"));
        if(list=="packet")return FindPacket(id);
        if(list=="proxy")return FindProxyPacket(id);
        return packet_for(id);
    };
    const auto packet_text=[packet_for](const Json& args){std::string text;for(const auto& id:args.value("ids",Json::array()))if(id.is_number_integer()){if(const auto* p=packet_for(id.get<std::int64_t>())){const auto bytes=p->modified?p->modified:p->raw;text+=PacketHex(bytes,bytes?bytes->size():0);text+="\r\n";}}return text;};
    bridge_->Register("copyPacketHex",[packet_text](const Json& args){return Json{{"text",packet_text(args)}};});
    bridge_->Register("copyProxyHex",[packet_text](const Json& args){return Json{{"text",packet_text(args)}};});
    const auto export_capture=[this,packet_for](const Json& args,WebBridge::Completion done,const char* title){
        try{ComPtr<IFileSaveDialog> dialog;Check(CoCreateInstance(CLSID_FileSaveDialog,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&dialog)),title);DWORD flags=0;Check(dialog->GetOptions(&flags),"Get capture export options");Check(dialog->SetOptions(flags|FOS_FORCEFILESYSTEM|FOS_OVERWRITEPROMPT|FOS_NOCHANGEDIR),"Configure capture export");const COMDLG_FILTERSPEC filters[]={{L"CSV 文件",L"*.csv"},{L"所有文件",L"*.*"}};Check(dialog->SetFileTypes(2,filters),"Set capture export filters");Check(dialog->SetDefaultExtension(L"csv"),"Set capture export extension");if(dialog->Show(window_)==HRESULT_FROM_WIN32(ERROR_CANCELLED)){done({{"ok",false}},{});return;}ComPtr<IShellItem> item;Check(dialog->GetResult(&item),"Get capture export result");CoString path;Check(item->GetDisplayName(SIGDN_FILESYSPATH,&path.value),"Get capture export path");std::ofstream output(path.value,std::ios::binary);output<<"Id,Socket,Type,From,To,Length,Hex\n";for(const auto& id:args.value("ids",Json::array())){if(!id.is_number_integer())continue;const auto* packet=packet_for(id.get<std::int64_t>());if(!packet)continue;const auto bytes=packet->modified?packet->modified:packet->raw;output<<packet->id<<","<<packet->socket<<","<<packet->packet_type<<",\""<<PacketText(packet->from)<<"\",\""<<PacketText(packet->to)<<"\","<<(bytes?bytes->size():0)<<",\""<<PacketHex(bytes,bytes?bytes->size():0)<<"\"\n";}if(!output)throw std::runtime_error("无法写入封包导出文件");done({{"ok",true},{"path",Utf8(path.value)}},{});}catch(const std::exception& e){done(nullptr,e.what());}
    };
    bridge_->RegisterAsync("exportPacketExcel",[export_capture](const Json& args,WebBridge::Completion done) mutable {export_capture(args,std::move(done),"Create packet export dialog");});
    bridge_->RegisterAsync("exportProxyExcel",[export_capture](const Json& args,WebBridge::Completion done) mutable {export_capture(args,std::move(done),"Create proxy export dialog");});
    bridge_->Register("setSystemSocketByPacket",[this,packet_for](const Json& args){const auto* p=packet_for(args.value("id",static_cast<std::int64_t>(0)));if(!p)return Json{{"socket",0}};system_socket_=p->socket;return Json{{"socket",p->socket}};});
    bridge_->Register("setSystemSocketByProxy",[this,packet_for](const Json& args){const auto* p=packet_for(args.value("id",static_cast<std::int64_t>(0)));if(!p)return Json{{"socket",0}};system_socket_=p->socket;return Json{{"socket",p->socket}};});
    bridge_->RegisterAsync("addPacketToSend",[this,packet_for](const Json& args,WebBridge::Completion done){const auto sid=args.value("sid",std::string{});int count=0;for(const auto& id:args.value("ids",Json::array())){const auto* p=packet_for(id.get<std::int64_t>());if(!p)continue;const auto bytes=p->modified?p->modified:p->raw;data_->Submit("__appendPacketToSend",{{"sid",sid},{"socket",p->socket},{"type",p->packet_type},{"from",PacketText(p->from)},{"to",PacketText(p->to)},{"buffer",Base64(bytes?std::span<const std::uint8_t>(*bytes):std::span<const std::uint8_t>())}},[done,count](Json value,std::string error) mutable {if(!error.empty()){done(nullptr,std::move(error));return;}done({{"count",value.value("count",0)}},{});});return;}done({{"count",count}},{});});
    bridge_->RegisterAsync("addProxyToSend",[](const Json&,WebBridge::Completion done){done({{"count",0}},"代理列表没有可追加的运行时封包源");});
    bridge_->RegisterAsync("addPacketToWareHouse",[this,packet_for](const Json& args,WebBridge::Completion done){const auto wid=args.value("wid",std::string{});auto ids=args.value("ids",Json::array());if(ids.empty()){done({{"count",0}},{});return;}const auto* p=packet_for(ids.front().get<std::int64_t>());if(!p){done({{"count",0}},{});return;}const auto bytes=p->modified?p->modified:p->raw;data_->Submit("__appendPacketToWareHouse",{{"wid",wid},{"socket",p->socket},{"type",p->packet_type},{"from",PacketText(p->from)},{"to",PacketText(p->to)},{"buffer",Base64(bytes?std::span<const std::uint8_t>(*bytes):std::span<const std::uint8_t>())}},[done](Json value,std::string error) mutable {done(error.empty()?Json{{"count",value.value("count",0)}}:Json{},std::move(error));});});
    bridge_->RegisterAsync("addProxyToWareHouse",[](const Json&,WebBridge::Completion done){done({{"count",0}},"代理列表没有可追加的运行时封包源");});
    bridge_->RegisterAsync("addPacketToFilter",[this,packet_for](const Json& args,WebBridge::Completion done){const auto* p=packet_for(args.value("id",static_cast<std::int64_t>(0)));if(!p){done({{"ok",false}},{});return;}const auto bytes=p->modified?p->modified:p->raw;data_->Submit("__appendPacketToFilter",{{"hex",PacketHex(bytes,bytes?bytes->size():0)}},[done](Json value,std::string error) mutable {done(error.empty()?Json{{"ok",value.value("ok",false)}}:Json{},std::move(error));});});
    bridge_->RegisterAsync("addProxyToFilter",[](const Json&,WebBridge::Completion done){done({{"ok",false}},"代理列表没有可追加的运行时封包源");});
    const auto search_packets=[this](const Json& args,bool proxy){
        const auto pattern=args.value("pattern",std::string{});
        const bool hex=args.value("isHex",false);
        const int from=std::max(0,args.value("from",0));
        const int from_pos=std::max(0,args.value("fromPos",0));
        std::vector<std::uint8_t> needle;
        if(hex){
            int high=-1;
            for(const auto c:pattern){
                if(c==' '||c=='\t'||c=='\r'||c=='\n')continue;
                const int v=(c>='0'&&c<='9')?c-'0':(c>='a'&&c<='f')?c-'a'+10:(c>='A'&&c<='F')?c-'A'+10:-1;
                if(v<0)return Json{{"Found",false},{"Error","十六进制搜索格式不正确"}};
                if(high<0)high=v;
                else{needle.push_back(static_cast<std::uint8_t>((high<<4)|v));high=-1;}
            }
            if(high>=0)return Json{{"Found",false},{"Error","十六进制搜索必须为偶数位"}};
            if(needle.empty())return Json{{"Found",false},{"Error","十六进制搜索内容为空"},{"NextPos",0}};
        }
        const auto size=proxy?proxy_capture_.size():packet_capture_.size();
        const auto begin=std::min<std::size_t>(static_cast<std::size_t>(from),size);
        for(std::size_t i=begin;i<size;++i){
            const auto* p=proxy?&proxy_capture_[i].packet:&packet_capture_[i];
            const auto bytes=p->modified?p->modified:p->raw;
            if(!bytes)continue;
            const auto start_pos=i==begin?static_cast<std::size_t>(std::max(0,from_pos)):0;
            if(hex){
                if(start_pos>bytes->size()||needle.size()>bytes->size())continue;
                for(std::size_t pos=start_pos;pos+needle.size()<=bytes->size();++pos)
                    if(std::equal(needle.begin(),needle.end(),bytes->begin()+static_cast<std::ptrdiff_t>(pos)))
                        return Json{{"Found",true},{"Id",p->id},{"Index",static_cast<int>(i)},{"Offset",static_cast<int>(pos)},{"Length",static_cast<int>(needle.size())},{"NextPos",static_cast<int>(pos+std::max<std::size_t>(1,needle.size()))},{"Error",nullptr}};
            }else{
                const auto text=PacketHex(bytes,bytes->size());
                const auto pos=text.find(pattern,start_pos);
                if(pos!=std::string::npos)
                    return Json{{"Found",true},{"Id",p->id},{"Index",static_cast<int>(i)},{"Offset",static_cast<int>(pos)},{"Length",static_cast<int>(pattern.size())},{"NextPos",static_cast<int>(pos+std::max<std::size_t>(1,pattern.size()))},{"Error",nullptr}};
            }
        }
        return Json{{"Found",false},{"Error",nullptr},{"NextPos",0}};
    };
    bridge_->Register("searchPacketList",[search_packets](const Json& args){return search_packets(args,false);});
    bridge_->Register("searchProxyList",[search_packets](const Json& args){return search_packets(args,true);});
     bridge_->RegisterAsync("injectAttach",[this](const Json& args,WebBridge::Completion done){
         try{const auto pid=args.value("pid",0);const auto method=args.value("method",0);const auto dll=HookDll();auto finish=[this,done=std::move(done)](bool ok,std::string error) mutable {if(!ok){QueueTargetResult(std::move(done),nullptr,std::move(error));return;}SyncTargetConfiguration([this,done=std::move(done)](Json,std::string error) mutable {if(!error.empty()){AbortTargetInjection(std::move(done),std::move(error));return;}auto value=InjectStatus();value["ok"]=true;QueueTargetResult(std::move(done),std::move(value),{});});};if(pid<1){const auto path=fs::path(Wide(args.value("path",std::string{})));const auto command=Wide(args.value("args",std::string{}));RememberInjection(0,path,std::to_string(method),command);target_->AttachLaunched(path,command,dll,std::move(finish));}else{RememberInjection(static_cast<DWORD>(pid),{},std::to_string(method),{});target_->AttachPid(static_cast<DWORD>(pid),dll,std::move(finish));}}
        catch(const std::exception& e){done(nullptr,e.what());}
    });
     bridge_->RegisterAsync("injectQuick",[this](const Json&,WebBridge::Completion done){
         if(!last_inject_.is_object()){done(nullptr,"没有可用的上次注入目标");return;}Json args=last_inject_;args["pid"]=last_inject_.value("pid",0);args["method"]=last_inject_.value("method",0);
         try{const auto dll=HookDll();const auto pid=args.value("pid",0);auto finish=[this,done=std::move(done)](bool ok,std::string error) mutable {if(!ok){QueueTargetResult(std::move(done),nullptr,std::move(error));return;}SyncTargetConfiguration([this,done=std::move(done)](Json,std::string error) mutable {if(!error.empty()){AbortTargetInjection(std::move(done),std::move(error));return;}auto value=InjectStatus();value["ok"]=true;QueueTargetResult(std::move(done),std::move(value),{});});};if(pid>0)target_->AttachPid(static_cast<DWORD>(pid),dll,std::move(finish));else target_->AttachLaunched(fs::path(Wide(args.value("path",std::string{}))),Wide(args.value("args",std::string{})),dll,std::move(finish));}
        catch(const std::exception& e){done(nullptr,e.what());}
    });
     bridge_->RegisterAsync("injectStartHook",[this](const Json&,WebBridge::Completion done){SyncTargetConfiguration([this,done=std::move(done)](Json,std::string error) mutable {if(!error.empty()){AbortTargetInjection(std::move(done),std::move(error));return;}wpe::IpcWriter r;r.U8(static_cast<std::uint8_t>(wpe::IpcCommand::StartHook));target_->CallVoid(r.ToArray(),[this,done=std::move(done)](bool ok,std::string error) mutable {if(!ok){AbortTargetInjection(std::move(done),std::move(error));return;}target_->ResumeLaunched([this,done=std::move(done)](bool resumed,std::string resume_error) mutable {if(!resumed){AbortTargetInjection(std::move(done),std::move(resume_error));return;}QueueTargetResult(std::move(done),Json{{"ok",true}},{});});});});});
    bridge_->RegisterAsync("injectStopHook",[this](const Json&,WebBridge::Completion done){wpe::IpcWriter r;r.U8(static_cast<std::uint8_t>(wpe::IpcCommand::StopHook));target_->CallVoid(r.ToArray(),[this,done=std::move(done)](bool ok,std::string error){QueueTargetResult(std::move(done),ok?Json{{"ok",true}}:Json{},std::move(error));});});
    const auto start_send=[this](WebBridge::Completion done){
        SyncTargetConfiguration([this,done=std::move(done)](Json,std::string error) mutable {
            if(!error.empty()){done(nullptr,std::move(error));return;}
            wpe::IpcWriter r;r.U8(static_cast<std::uint8_t>(wpe::IpcCommand::StartSendList));
            target_->CallVoid(r.ToArray(),[this,done=std::move(done)](bool ok,std::string error) mutable {
                if(ok){send_running_=true;std::lock_guard lock(send_progress_mutex_);send_progress_["Running"]=true;send_progress_["Total"]=0;send_progress_["Index"]=-1;}
                QueueTargetResult(std::move(done),ok?Json{{"ok",true},{"running",send_running_}}:Json{},std::move(error));
            });
        });
    };
    bridge_->RegisterAsync("startSendList",[start_send](const Json&,WebBridge::Completion done) mutable {start_send(std::move(done));});
    bridge_->RegisterAsync("startSendEdit",[this,start_send](const Json&,WebBridge::Completion done) mutable {start_send(std::move(done));});
    bridge_->RegisterAsync("stopSendList",[this](const Json&,WebBridge::Completion done){wpe::IpcWriter r;r.U8(static_cast<std::uint8_t>(wpe::IpcCommand::StopSendList));target_->CallVoid(r.ToArray(),[this,done=std::move(done)](bool ok,std::string error) mutable {send_running_=false;{std::lock_guard lock(send_progress_mutex_);send_progress_["Running"]=false;}QueueTargetResult(std::move(done),ok?Json{{"ok",true},{"running",false}}:Json{},std::move(error));});});
    bridge_->RegisterAsync("stopSendEdit",[this](const Json&,WebBridge::Completion done){wpe::IpcWriter r;r.U8(static_cast<std::uint8_t>(wpe::IpcCommand::StopSendList));target_->CallVoid(r.ToArray(),[this,done=std::move(done)](bool ok,std::string error) mutable {send_running_=false;{std::lock_guard lock(send_progress_mutex_);send_progress_["Running"]=false;}QueueTargetResult(std::move(done),ok?Json{{"ok",true},{"running",false}}:Json{},std::move(error));});});
    bridge_->RegisterAsync("getSendMeta",[this](const Json&,WebBridge::Completion done){data_->Submit("getSendMeta",Json::object(),[this,done=std::move(done)](Json value,std::string error) mutable {if(value.is_object())value["running"]=send_running_;done(std::move(value),std::move(error));});});
    bridge_->RegisterAsync("getSendEditProgress",[this](const Json&,WebBridge::Completion done){std::lock_guard lock(send_progress_mutex_);auto value=send_progress_;value["Running"]=send_running_;done(std::move(value),{});});

    bridge_->RegisterAsync("startPacketSend",[this](const Json& args,WebBridge::Completion done){
        if(!target_||target_->State()!=wpe::IpcLinkState::Attached){done(nullptr,"尚未连接目标进程");return;}
        if(packet_send_running_.exchange(true)){done(nullptr,"已有封包正在发送");return;}
        const auto bytes=Unbase64(args.value("buffer",std::string{}));
        if(bytes.empty()){packet_send_running_=false;done(nullptr,"发送内容为空或不是有效 Base64");return;}
        const int socket=args.value("socket",0),type=args.value("type",0);const auto times=std::max(1,args.value("times",1));
        {
            std::lock_guard lock(send_progress_mutex_);send_progress_={{"Running",true},{"Index",0},{"Total",times},{"Success",0},{"Fail",0}};
        }
        auto state=std::make_shared<std::tuple<int,int,WebBridge::Completion>>(0,times,std::move(done));
        auto pump=std::make_shared<std::function<void()>>();
        *pump=[this,state,pump,socket,type,bytes]() mutable {
            auto& index=std::get<0>(*state);auto& total=std::get<1>(*state);
            if(!packet_send_running_||index>=total){packet_send_running_=false;QueueTargetResult(std::move(std::get<2>(*state)),{{"ok",true}},{});return;}
            wpe::IpcWriter writer;writer.U8(static_cast<std::uint8_t>(wpe::IpcCommand::SendPacket));writer.I32(socket);writer.I32(type);writer.Str(std::u16string{});writer.Str(std::u16string{});writer.Bytes(wpe::Bytes{bytes});
            target_->Call(writer.ToArray(),[this,state,pump](bool ok,std::string error,wpe::ByteBuffer response) mutable {
                auto& index=std::get<0>(*state);auto& total=std::get<1>(*state);bool sent=false;
                try{if(ok){wpe::IpcReader reader(response);if(static_cast<wpe::IpcStatus>(reader.U8())!=wpe::IpcStatus::Ok)throw std::runtime_error("目标拒绝封包发送");sent=reader.Bool();if(reader.Remaining()!=0)throw std::runtime_error("SendPacket response has trailing bytes");if(!sent)error="目标拒绝封包发送";}else if(error.empty())error="目标发送失败";}catch(const std::exception& e){ok=false;error=e.what();}
                {std::lock_guard lock(send_progress_mutex_);if(sent)send_progress_["Success"]=send_progress_.value("Success",0)+1;else send_progress_["Fail"]=send_progress_.value("Fail",0)+1;send_progress_["Index"]=index+1;}
                ++index;if(!ok||!packet_send_running_||index>=total){packet_send_running_=false;{std::lock_guard lock(send_progress_mutex_);send_progress_["Running"]=false;}QueueTargetResult(std::move(std::get<2>(*state)),sent?Json{{"ok",true}}:Json{{"ok",false}},sent?std::string{}:error);return;}(*pump)();
            });
        };(*pump)();
    });
    bridge_->RegisterAsync("stopPacketSend",[this](const Json&,WebBridge::Completion done){packet_send_running_=false;{std::lock_guard lock(send_progress_mutex_);send_progress_["Running"]=false;}done({{"ok",true}},{});});
    bridge_->RegisterAsync("getPacketSendProgress",[this](const Json&,WebBridge::Completion done){std::lock_guard lock(send_progress_mutex_);done(send_progress_,{});});
    bridge_->RegisterAsync("packetEditToSend",[this,packet_for_list](const Json& args,WebBridge::Completion done){
        const auto bytes=Unbase64(args.value("buffer",std::string{}));if(bytes.empty()){done({{"ok",false}},"封包内容为空");return;}
        Json request={{"sid",args.value("sid",std::string{})},{"socket",args.value("socket",0)},{"type",args.value("type",0)},{"from",args.value("from",std::string{})},{"to",args.value("to",std::string{})},{"buffer",args.value("buffer",std::string{})}};
        if(const auto* packet=packet_for_list(args)){request["socket"]=packet->socket;request["type"]=packet->packet_type;request["from"]=PacketText(packet->from);request["to"]=PacketText(packet->to);}
        data_->Submit("__appendPacketToSend",request,[done](Json v,std::string e) mutable {done(e.empty()?Json{{"ok",v.value("count",0)>0}}:Json{},std::move(e));});
    });
    bridge_->RegisterAsync("packetEditToFilter",[this](const Json& args,WebBridge::Completion done){const auto bytes=Unbase64(args.value("buffer",std::string{}));if(bytes.empty()){done({{"ok",false}},"封包内容为空");return;}data_->Submit("__appendPacketToFilter",{{"hex",PacketHex(wpe::Bytes{bytes},bytes.size())}},[done](Json v,std::string e) mutable {done(e.empty()?Json{{"ok",v.value("ok",false)}}:Json{},std::move(e));});});
    bridge_->RegisterAsync("startProxy",[this](const Json&,WebBridge::Completion done){
        auto finish=[this,done=std::move(done)](Json value,std::string error) mutable {
            if(!error.empty()){
                AppendSystemLog("Proxy", "代理启动失败: "+error);
                AppendProxyLog("系统", proxy_display_host_, "代理启动失败: "+error);
            }else if(value.is_object()&&value.value("running",false)){
                const auto socks=value.value("socks5Addr",std::string{}),http=value.value("httpAddr",std::string{});
                std::string content="代理已启动";
                if(!socks.empty())content+="；SOCKS5 "+socks;
                if(!http.empty())content+="；HTTP "+http;
                AppendSystemLog("Proxy",content);
                AppendProxyLog("系统",proxy_display_host_,content);
            }
            done(std::move(value),std::move(error));
        };
        if(!proxy_||!http_proxy_){finish(nullptr,"代理运行时未初始化");return;}
        const auto socks_stats=proxy_->Stats();
        const auto http_stats=http_proxy_->Stats();
        if(socks_stats.running||http_stats.running){
            const auto address=[&](std::uint16_t port){
                if(port==0)return std::string{};
                return (proxy_display_host_.find(':')==proxy_display_host_.npos?proxy_display_host_:"["+proxy_display_host_+"]")+":"+std::to_string(port);
            };
            finish({{"ok",true},{"running",true},
                  {"socks5Addr",address(socks_stats.port)},
                  {"httpAddr",address(http_stats.port)}},{});
            return;
        }
        data_->Submit("__proxyRuntimeConfiguration",Json::object(),[this,finish=std::move(finish)](Json config,std::string error) mutable {
            if(!error.empty()){finish(nullptr,std::move(error));return;}
            Json result;std::string apply_error;
            try{
                if(!ApplyProxyRuntimeConfiguration(config,true,result,apply_error)){finish(nullptr,std::move(apply_error));return;}
                finish(std::move(result),{});
            }catch(const std::exception& exception){
                if(proxy_&&proxy_->Running())proxy_->Stop();if(http_proxy_&&http_proxy_->Running())http_proxy_->Stop();finish(nullptr,exception.what());
            }
        });
    });
    bridge_->RegisterAsync("stopProxy",[this](const Json&,WebBridge::Completion done){
        const bool was_running=(http_proxy_&&http_proxy_->Running())||(proxy_&&proxy_->Running());
        if(http_proxy_)http_proxy_->Stop();
        if(proxy_)proxy_->Stop();
        proxy_display_host_="127.0.0.1";
        if(bridge_)bridge_->PushEvent("proxy:state",{{"running",false},{"socks5Addr",""},{"httpAddr",""}});
        if(was_running){
            AppendSystemLog("Proxy","代理已停止");
            AppendProxyLog("系统",proxy_display_host_,"代理已停止");
        }
        done({{"ok",true},{"running",false}},{});
    });
    bridge_->Register("getStats",[this](const Json&){
        Json value={{"queue",0},{"list",send_running_?1:0},{"total",0},{"proxyRunning",false},
            {"tcpReq",0},{"tcpResp",0},{"udpReq",0},{"udpResp",0},{"httpReq",0},{"httpResp",0},
            {"filterExecute",0},{"filterProxy",0},{"tcpConn",0},{"udpConn",0},{"onlineInfo",""},
            {"totalRequest",0},{"totalResponse",0},{"speedUp",0},{"speedDown",0},
            {"mappingHits",0},{"mappingMisses",0},{"mappingErrors",0},
            {"wpcProxyControl",0},{"wpcProxyDevices",0},{"wpcProxyRegisters",0},
            {"wpcProxyPings",0},{"wpcProxyErrors",0},
            {"filterEvidence",Json{{"seen",0},{"headerMatches",0},{"typeMatches",0},
                {"allowed",0},{"dropped",0},{"tcpReq",0},{"tcpResp",0},
                {"udpReq",0},{"udpResp",0},{"other",0}}}};
        if(target_stats_.is_object())value.update(target_stats_);
        const auto socks=proxy_?proxy_->Stats():wpe::shell::Socks5Stats{};
        const auto http=http_proxy_?http_proxy_->Stats():wpe::shell::Socks5Stats{};
        value["proxyRunning"]=socks.running||http.running;
        value["tcpConn"]=static_cast<std::int64_t>(socks.active-socks.udp_active-socks.wpc_controls+http.active);
        value["tcpReq"]=static_cast<std::int64_t>(socks.requests);
        value["tcpResp"]=static_cast<std::int64_t>(socks.responses);
        value["udpReq"]=static_cast<std::int64_t>(socks.udp_requests);
        value["udpResp"]=static_cast<std::int64_t>(socks.udp_responses);
        value["udpConn"]=static_cast<std::int64_t>(socks.udp_active);
        value["httpReq"]=static_cast<std::int64_t>(http.requests);
        value["httpResp"]=static_cast<std::int64_t>(http.responses);
        value["totalRequest"]=static_cast<std::int64_t>(socks.requests+http.requests);
        value["totalResponse"]=static_cast<std::int64_t>(socks.responses+http.responses);
        value["speedUp"]=static_cast<std::int64_t>(socks.bytes_up+http.bytes_up);
        value["speedDown"]=static_cast<std::int64_t>(socks.bytes_down+http.bytes_down);
        value["proxyErrors"]=static_cast<std::int64_t>(socks.errors+http.errors);
        value["mappingHits"]=static_cast<std::int64_t>(http.map_hits);
        value["mappingMisses"]=static_cast<std::int64_t>(http.map_misses);
        value["mappingErrors"]=static_cast<std::int64_t>(http.map_errors);
        value["wpcProxyControl"]=static_cast<std::int64_t>(socks.wpc_controls);
        value["wpcProxyDevices"]=static_cast<std::int64_t>(socks.wpc_devices);
        value["wpcProxyRegisters"]=static_cast<std::int64_t>(socks.wpc_registers);
        value["wpcProxyPings"]=static_cast<std::int64_t>(socks.wpc_pings);
        value["wpcProxyErrors"]=static_cast<std::int64_t>(socks.wpc_errors);
        value["filterProxy"]=static_cast<std::int64_t>(proxy_filter_dropped_.load(std::memory_order_relaxed));
        value["filterEvidence"]={
            {"seen",static_cast<std::int64_t>(proxy_filter_diagnostics_.seen.load(std::memory_order_relaxed))},
            {"headerMatches",static_cast<std::int64_t>(proxy_filter_diagnostics_.header_matches.load(std::memory_order_relaxed))},
            {"typeMatches",static_cast<std::int64_t>(proxy_filter_diagnostics_.type_matches.load(std::memory_order_relaxed))},
            {"allowed",static_cast<std::int64_t>(proxy_filter_diagnostics_.allowed.load(std::memory_order_relaxed))},
            {"dropped",static_cast<std::int64_t>(proxy_filter_dropped_.load(std::memory_order_relaxed))},
            {"tcpReq",static_cast<std::int64_t>(proxy_filter_diagnostics_.tcp_requests.load(std::memory_order_relaxed))},
            {"tcpResp",static_cast<std::int64_t>(proxy_filter_diagnostics_.tcp_responses.load(std::memory_order_relaxed))},
            {"udpReq",static_cast<std::int64_t>(proxy_filter_diagnostics_.udp_requests.load(std::memory_order_relaxed))},
            {"udpResp",static_cast<std::int64_t>(proxy_filter_diagnostics_.udp_responses.load(std::memory_order_relaxed))},
            {"other",static_cast<std::int64_t>(proxy_filter_diagnostics_.other.load(std::memory_order_relaxed))}
        };
        const auto wpc=wpc_?wpc_->Stats():wpe::shell::WpcStats{};
        value["wpcRunning"]=wpc.running;
        value["wpcConn"]=static_cast<std::int64_t>(wpc.active);
        value["wpcReq"]=static_cast<std::int64_t>(wpc.requests);
        value["wpcResp"]=static_cast<std::int64_t>(wpc.responses);
        value["wpcErrors"]=static_cast<std::int64_t>(wpc.errors);
        return value;
    });
    bridge_->Register("getFilterStats",[this](const Json&){
        const auto globals=target_stats_.value("filterGlobals",Json::array());
        auto at=[&](std::size_t i){return globals.is_array()&&i<globals.size()?globals[i].get<std::int64_t>():0;};
        std::int64_t execute=0;for(const auto& item:target_stats_.value("filters",Json::array()))execute+=item.value("count",0LL);
        return Json{{"ProxyTotal",at(0)},{"Hit",at(0)},{"Execute",execute},
                    {"Replace",at(1)},{"Change",at(2)},{"Intercept",at(3)},
                    {"Display",at(4)},{"NoDisplay",at(5)}};
    });
    bridge_->RegisterAsync("resetFilterStats",[this](const Json&,WebBridge::Completion done){wpe::IpcWriter r;r.U8(static_cast<std::uint8_t>(wpe::IpcCommand::ResetStats));r.U8(static_cast<std::uint8_t>(wpe::ResetWhat::FilterStats));target_->CallVoid(r.ToArray(),[this,done=std::move(done)](bool ok,std::string error){QueueTargetResult(std::move(done),ok?Json{{"ok",true}}:Json{},std::move(error));});});
}
void Host::CancelFileJobs(){
    // Navigation/close must cancel deferred clipboard writes too.
    if(clipboard_)clipboard_->Cancel();
    ++file_epoch_;file_prompt_pending_=false;if(file_dialog_)file_dialog_->Close(HRESULT_FROM_WIN32(ERROR_CANCELLED));
    const auto token=import_token_;ReleaseImport(token);
    auto cancelled=std::move(file_jobs_);file_jobs_.clear();for(auto& job:cancelled){DiscardExport(job.export_plan);job.done(nullptr,"文件选择已取消");}
}
void Host::PickImportFile(){
    if(closing_||file_dialog_||file_prompt_pending_||file_jobs_.empty())return;
    auto job=std::move(file_jobs_.front());file_jobs_.pop_front();const auto epoch=file_epoch_;
    try{
        if(job.method=="__pickFolder"){
            Check(CoCreateInstance(CLSID_FileOpenDialog,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&file_dialog_)),"Create folder dialog");
            DWORD flags=0;Check(file_dialog_->GetOptions(&flags),"Get folder dialog options");
            Check(file_dialog_->SetOptions(flags|FOS_PICKFOLDERS|FOS_FORCEFILESYSTEM|FOS_PATHMUSTEXIST|FOS_NOCHANGEDIR),"Configure folder dialog");
            const auto initial=job.args.value("path",std::string{});
            if(!initial.empty()){
                const auto folder=fs::path(Wide(initial));std::error_code ec;
                if(fs::is_directory(folder,ec)){
                    ComPtr<IShellItem> item;
                    if(SUCCEEDED(SHCreateItemFromParsingName(folder.wstring().c_str(),nullptr,IID_PPV_ARGS(&item))))file_dialog_->SetFolder(item.Get());
                }
            }
            const auto result=file_dialog_->Show(window_);
            if(result==HRESULT_FROM_WIN32(ERROR_CANCELLED)){job.done(nullptr,{});}
            else {Check(result,"Open folder dialog");ComPtr<IShellItem> item;Check(file_dialog_->GetResult(&item),"Get selected folder");CoString name;Check(item->GetDisplayName(SIGDN_FILESYSPATH,&name.value),"Get selected folder path");job.done({{"path",Utf8(name.value)}},{});}
            file_dialog_.Reset();
            if(!closing_&&!file_jobs_.empty())PostMessageW(window_,app_file,0,0);
            return;
        }
        fs::path path;const bool save=!job.export_plan.is_null();const auto& info=save?job.export_plan:job.file_info;const auto kind=info.at("kind").get<std::string>();
        if(options_.test){
            // Test-only chooser seam; fixed files under the isolated report dir.
            // The production Windows dialog is never replaced outside --self-test.
            if(!test_cancel_file_)path=options_.report/Wide(std::string(!save&&test_encrypted_import_?"encrypted-export.":save?"export.":"import.")+kind);test_cancel_file_=false;if(!save)test_encrypted_import_=false;
        }else{
            Check(CoCreateInstance(save?CLSID_FileSaveDialog:CLSID_FileOpenDialog,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&file_dialog_)),"Create file dialog");
            DWORD flags=0;Check(file_dialog_->GetOptions(&flags),"Get dialog flags");
            Check(file_dialog_->SetOptions(flags|FOS_FORCEFILESYSTEM|FOS_PATHMUSTEXIST|FOS_NOCHANGEDIR|(save?FOS_OVERWRITEPROMPT:FOS_FILEMUSTEXIST)),"Set dialog flags");
            const auto pattern=Wide("*."+kind),label=Wide(kind=="xls"?"Excel (*.xls)":"WPE (*."+kind+")"),extension=Wide(kind);
            const COMDLG_FILTERSPEC filters[]={{label.c_str(),pattern.c_str()},{L"XML 文件",L"*.xml"},{L"所有文件",L"*.*"}};
            Check(file_dialog_->SetFileTypes(kind=="xls"?1:3,filters),"Set dialog filters");Check(file_dialog_->SetDefaultExtension(extension.c_str()),"Set default extension");
            if(save&&info.contains("defaultName"))Check(file_dialog_->SetFileName(Wide(info.at("defaultName").get<std::string>()).c_str()),"Set default file name");
            Check(file_dialog_->SetTitle(Wide(info.at("title").get<std::string>()).c_str()),"Set dialog title");
            const auto hr=file_dialog_->Show(window_);if(hr!=HRESULT_FROM_WIN32(ERROR_CANCELLED)){Check(hr,"Open file dialog");ComPtr<IShellItem> item;Check(file_dialog_->GetResult(&item),"Get selected file");CoString name;Check(item->GetDisplayName(SIGDN_FILESYSPATH,&name.value),"Get file path");path=name.value;}
            file_dialog_.Reset();
        }
        if(closing_||epoch!=file_epoch_){DiscardExport(job.export_plan);job.done(nullptr,"文件选择已取消");}
        else if(path.empty()){DiscardExport(job.export_plan);if(save)job.done(job.export_plan.at("result"),{});else data_->Submit(job.method,job.args,job.done);}
        else if(save&&job.export_plan.value("plain",false)){
            file_prompt_pending_=true;
            data_->Submit("__writeEditorExport",{{"plan",job.export_plan},{"_filePath",Utf8(path.wstring())},{"_password",""}},[this,job,epoch](Json value,std::string failure){
                DiscardExport(job.export_plan);if(epoch==file_epoch_){file_prompt_pending_=false;job.done(std::move(value),std::move(failure));if(!closing_&&!file_jobs_.empty())PostMessageW(window_,app_file,0,0);}else job.done(nullptr,"导出已取消");
            });
        }
        else if(save){
            file_prompt_pending_=true;
            bridge_->AskResult("prompt",{{"formId","encrypt-export"},{"arg",{{"Title",job.export_plan.at("title")},{"FilePath",nullptr}}}},
                [this,job,epoch,path](Json answer,std::string error){
                    if(closing_||epoch!=file_epoch_){DiscardExport(job.export_plan);job.done(nullptr,"导出已取消");return;}
                    file_prompt_pending_=false;
                    if(!error.empty()){DiscardExport(job.export_plan);job.done(nullptr,"导出已取消："+error);}
                    else if(answer.is_null()||(answer.is_object()&&answer.contains("Password")&&answer["Password"].is_string()&&!answer["Password"].get<std::string>().empty()))
                        data_->Submit("__writeEditorExport",{{"plan",job.export_plan},{"_filePath",Utf8(path.wstring())},{"_password",answer.is_null()?"":answer["Password"].get<std::string>()}},[this,job](Json value,std::string failure){DiscardExport(job.export_plan);job.done(std::move(value),std::move(failure));});
                    else{DiscardExport(job.export_plan);job.done(nullptr,"密码结果无效；未写入文件");}
                    if(!file_jobs_.empty())PostMessageW(window_,app_file,0,0);
                });
        }
        else BeginImport(job,path,epoch);
    }catch(const std::exception& e){file_dialog_.Reset();file_prompt_pending_=false;DiscardExport(job.export_plan);job.done(nullptr,e.what());}
    if(!closing_&&!file_jobs_.empty())PostMessageW(window_,app_file,0,0);
}
void Host::DrainClipboard(){if(clipboard_)clipboard_->Drain();}
void Host::BeginImport(FileJob job,const fs::path& path,std::uint64_t epoch){
    file_prompt_pending_=true;job.args["_filePath"]=Utf8(path.wstring());
    data_->Submit("__prepareImport",{{"method",job.method},{"args",job.args}},[this,job,epoch](Json plan,std::string error){
        const auto token=plan.is_object()?plan.value("token",std::string{}):std::string{};
        auto complete=[this,job,epoch,token](Json value,std::string failure) mutable {
            ReleaseImport(token);
            if(epoch==file_epoch_){file_prompt_pending_=false;if(!closing_&&!file_jobs_.empty())PostMessageW(window_,app_file,0,0);}
            job.done(std::move(value),std::move(failure));
        };
        const bool target_import=job.method=="importFilters"||job.method=="importSends"||job.method=="importBackup";
        const bool proxy_import=job.method=="importAccounts"||job.method=="importBackup";
        auto finish=[this,job,epoch,token,complete,target_import,proxy_import](Json value,std::string failure) mutable {
            if(!failure.empty()){complete(std::move(value),std::move(failure));return;}
            if(target_import&&target_&&target_->State()==wpe::IpcLinkState::Attached){
                SyncTargetConfiguration([complete,value=std::move(value)](Json,std::string sync_error) mutable {
                    if(!sync_error.empty()){complete(std::move(value),"数据已导入，但目标配置实时同步失败："+sync_error);return;}
                    complete(std::move(value),{});
                });
                return;
            }
            if(proxy_import&&proxy_&&http_proxy_&&(proxy_->Stats().running||http_proxy_->Stats().running)){
                data_->Submit("__proxyRuntimeConfiguration",Json::object(),[this,complete,value=std::move(value)](Json config,std::string config_error) mutable {
                    if(!config_error.empty()){complete(std::move(value),"数据已导入，但代理配置读取失败："+config_error);return;}
                    Json refreshed;std::string refresh_error;
                    if(!ApplyProxyRuntimeConfiguration(config,false,refreshed,refresh_error)){complete(std::move(value),"数据已导入，但代理实时同步失败："+refresh_error);return;}
                    complete(std::move(value),{});
                });
                return;
            }
            complete(std::move(value),{});
        };
        if(closing_||epoch!=file_epoch_){finish(nullptr,"导入已取消");return;}
        if(!error.empty()){finish(nullptr,std::move(error));return;}
        try{
            import_token_=token; // Plain XML must also be cancellable while apply is queued.
            if(!plan.at("encrypted").get<bool>()){data_->Submit("__applyImport",{{"token",token}},finish);return;}
            import_path_=job.args.at("_filePath").get<std::string>();
            bridge_->AskResult("prompt",{{"formId","encrypt-import"},{"arg",{{"Title",plan.at("title")},{"FilePath",import_path_}}}},
                [this,job,epoch,token,finish](Json answer,std::string failure) mutable {
                    if(closing_||epoch!=file_epoch_){finish(nullptr,"导入已取消");return;}
                    if(!failure.empty()){finish(nullptr,"导入已取消："+failure);return;}
                    if(answer.is_null()){auto cancelled=job.args;cancelled.erase("_filePath");data_->Submit(job.method,std::move(cancelled),finish);return;}
                    if(!answer.is_object()||!answer.contains("Password")||!answer["Password"].is_string()||answer["Password"].get<std::string>().empty()){finish(nullptr,"密码结果无效；未导入数据");return;}
                    data_->Submit("__applyImport",{{"token",token},{"password",answer.at("Password")}},finish);
                });
        }catch(const std::exception& e){finish(nullptr,e.what());}
    });
}
void Host::Script(const std::wstring& script){
    Check(view_->ExecuteScript(script.c_str(),Callback<ICoreWebView2ExecuteScriptCompletedHandler>([this,alive=std::weak_ptr(lifetime_)](HRESULT hr,LPCWSTR)->HRESULT{
        if(alive.expired()||closing_)return S_OK;
        if(FAILED(hr))Fail("ExecuteScript failed");return S_OK;
    }).Get()),"Execute test script");
}
void Host::BeginTest(){
    // Fixed inputs only for the isolated self-test chooser. No fixtures are
    // inserted into a normal user's database or shipped runtime directory.
    {std::ofstream f(options_.report/L"import.sc",std::ios::binary);f<<"<SendCollection><Collection><Socket>17</Socket><Type>TCP_Req</Type><IPFrom>127.0.0.1</IPFrom><IPTo>127.0.0.2</IPTo><Buffer>00 FF 80 41</Buffer></Collection><Collection><Socket>23</Socket><Type>UDP_Resp</Type><Buffer>01 02 03</Buffer></Collection></SendCollection>";if(!f)throw std::runtime_error("Cannot write send self-test fixture");}
    {std::ofstream f(options_.report/L"import.whs",std::ios::binary);f<<"<Stores><Data><PacketData>00 FF 80</PacketData></Data><Data><PacketData>41 42</PacketData></Data></Stores>";if(!f)throw std::runtime_error("Cannot write warehouse self-test fixture");}
    Script(LR"JS((()=>{
      const w=chrome.webview; let seq=0; const pending=new Map();
      w.addEventListener('message',e=>{const m=e.data;if(m.type==='result'&&pending.has(m.id)){const p=pending.get(m.id);pending.delete(m.id);m.ok?p.resolve(m.result):p.reject(new Error(m.error));}});
      const call=(method,args={})=>new Promise((resolve,reject)=>{const id='selftest-'+(++seq);pending.set(id,{resolve,reject});w.postMessage({type:'call',id,method,args});});
      const wait=async(f)=>{for(let i=0;i<150;i++){if(f())return;await new Promise(r=>setTimeout(r,40));}throw Error('DOM condition timed out');};
      (async()=>{
        const info=await call('getSystemCheck');if(info.version!=='2.3.0')throw Error('wrong native host');
        const instanceProbe=await call('probeDbPath',{path:info.dbDir});
        if(!instanceProbe.valid||instanceProbe.full!==info.dbDir)throw Error('instance path probe failed');
        await wait(()=>document.querySelector('.win .titlebar')&&document.querySelectorAll('.rack .cd').length>=2);
        // A hidden/background process can fail this platform-dependent probe.
        // Keep its exact result separate from editor acceptance, never fake it.
        const top=await call('setTopMost',{on:true});
        const normal=await call('setTopMost',{on:false});if(normal.topMost)throw Error('topmost reset failed');
        let unsupported=false;try{await call('__unimplemented_capture');}catch(e){unsupported=String(e).includes('尚未实现');}
        if(!unsupported)throw Error('unsupported method falsely succeeded');
        await call('__testConfirm');
        await wait(()=>document.querySelector('[role=alertdialog] .btn.primary'));
        document.querySelector('[role=alertdialog] .btn.primary').click();
        await wait(()=>document.body.textContent.includes('NATIVE_BRIDGE_EVENT_OK'));
        const modeCards=document.querySelectorAll('.rack .cd').length;
        const feeds=new Map(),notices=[];w.addEventListener('message',e=>{const m=e.data;if(m.type==='event'&&m.name==='feed:replace')feeds.set(m.data.list,m.data.rows);else if(m.type==='event'&&m.name==='feed:append')feeds.set(m.data.list,(feeds.get(m.data.list)||[]).concat(m.data.rows||[]));if(m.type==='event'&&m.name==='notify')notices.push(m.data);});
        const dialog=kind=>[...document.querySelectorAll('[role=dialog]')].find(d=>d.querySelector('.sub')?.textContent==='Controls/'+kind);
        const input=(el,value)=>{if(!el)throw Error('editor input missing');Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(el,String(value));el.dispatchEvent(new Event('input',{bubbles:true}));};
        const nav=async label=>{await call('__testStage',{stage:label});const el=[...document.querySelectorAll('.side .sb-item')].find(e=>e.querySelector('.t')?.textContent.trim()===label);if(!el)throw Error('navigation missing: '+label);el.click();await wait(()=>document.querySelector('.list-page .bar .btn.primary'));};
        const openEditor=async(kind)=>{document.querySelector('.list-page .row .ops .op:not(.del)').click();await wait(()=>dialog(kind)?.querySelector('.bd'));return dialog(kind);};
        const closeEditor=async(kind)=>{dialog(kind).querySelector('.ft .btn:not(.primary)').click();await wait(()=>!dialog(kind));};
        const clipEquals=async expected=>{for(let n=0;n<50;n++){if((await call('clipboardRead')).text===expected)return;await new Promise(r=>setTimeout(r,40));}throw Error('clipboard mismatch');};
        const exportPlain=async(d,title)=>{const count=notices.length;[...d.querySelectorAll('.runbar .btn')].find(e=>e.textContent.trim().includes('导出')).click();await wait(()=>document.querySelector('[role=dialog] .ft .btn.plain'));document.querySelector('[role=dialog] .ft .btn.plain').click();await wait(()=>notices.slice(count).some(x=>x.title===title));};
    )JS" LR"JS(
        const editors=async(restart)=>{
          await nav('发送列表');if(!restart){document.querySelector('.list-page .bar .btn.primary').click();await wait(()=>feeds.get(9)?.length===1&&document.querySelector('.list-page .row .name'));}
          let d=await openEditor('SendEdit');
          if(!restart){
            input(d.querySelector('.bd > .row .v input.inp'),'C++ 发送编辑测试');
            const imp=[...d.querySelectorAll('.runbar .btn')].find(e=>e.textContent.trim().includes('导入'));
            if(!imp)throw Error('send import button missing');
            await call('__testCancelNextFile');imp.click();await new Promise(r=>setTimeout(r,250));
            if(d.querySelectorAll('.row2').length)throw Error('cancelled chooser imported data');
            imp.click();await wait(()=>d.querySelectorAll('.row2').length===2&&document.body.textContent.includes('导入发送集成功'));
            d.querySelector('.row2 .op:not(.del)').click();await wait(()=>dialog('PacketEdit')?.querySelector('.fields input'));
            const p=dialog('PacketEdit');input(p.querySelector('.fields input'),99);
            const hex=p.querySelector('.hexed [tabindex="0"]');if(!hex)throw Error('original HexView missing');
            hex.focus();for(const key of ['A','A'])hex.dispatchEvent(new KeyboardEvent('keydown',{key,bubbles:true,cancelable:true}));
            for(const key of ['a','c'])hex.dispatchEvent(new KeyboardEvent('keydown',{key,ctrlKey:true,bubbles:true,cancelable:true}));
            await clipEquals('AA FF 80 41');await call('clipboardWrite',{text:'AA FF 80 42'});
            hex.dispatchEvent(new KeyboardEvent('keydown',{key:'v',ctrlKey:true,bubbles:true,cancelable:true}));
            await wait(()=>hex.querySelector('.hexs .b[data-i="3"]')?.textContent.trim()==='42');
            await call('clipboardWrite',{text:null});await clipEquals('');
            p.querySelector('.ft .btn.primary').click();await wait(()=>!dialog('PacketEdit')&&d.querySelector('.row2 .so')?.textContent==='99');
            if(!d.querySelector('.row2 .dt').textContent.startsWith('AA FF'))throw Error('HexView edit not saved');
            await call('__testCancelNextFile');await call('exportSendCollection',{_filePath:'untrusted-browser-path.sc'});
            await exportPlain(d,'导出发送集成功');
            await call('__testStage',{stage:'encrypted-export'});const secret='test-only-not-a-user-password',encrypted=call('exportSendCollection');
            await wait(()=>document.querySelector('[role=dialog] .ft .btn.plain'));const pw=document.querySelector('[role=dialog] .ft .btn.plain').closest('[role=dialog]');for(const field of pw.querySelectorAll('input'))input(field,secret);await wait(()=>!pw.querySelector('.ft .btn.primary').disabled);pw.querySelector('.ft .btn.primary').click();await encrypted;
            await call('__testStage',{stage:'encrypted-export-complete'});const grant=await call('__testUseLastEncryptedExport');
            if((await call('verifyEncryptPassword',{path:grant.path,password:secret})).ok)throw Error('password verifier accepted unselected file');
            await call('__testStage',{stage:'clear-before-encrypted-import'});d.querySelector('.runbar .btn.danger').click();await wait(()=>document.querySelector('[role=alertdialog] .btn.primary'));document.querySelector('[role=alertdialog] .btn.primary').click();await wait(()=>d.querySelectorAll('.row2').length===0);imp.click();
            await wait(()=>[...document.querySelectorAll('[role=dialog]')].some(e=>e.querySelector('.fld input')&&!e.querySelector('.ft .btn.plain')));
            const unlock=[...document.querySelectorAll('[role=dialog]')].find(e=>e.querySelector('.fld input')&&!e.querySelector('.ft .btn.plain'));
            if((await call('verifyEncryptPassword',{path:grant.path+'.forged',password:secret})).ok)throw Error('forged import path accepted');
            await call('__testStage',{stage:'encrypted-import-wrong-password'});input(unlock.querySelector('input'),'wrong-password');await wait(()=>!unlock.querySelector('.ft .btn.primary').disabled);unlock.querySelector('.ft .btn.primary').click();await wait(()=>unlock.querySelector('.err'));
            if(d.querySelectorAll('.row2').length!==0)throw Error('wrong password imported data');
            input(unlock.querySelector('input'),secret);await wait(()=>!unlock.querySelector('.ft .btn.primary').disabled);unlock.querySelector('.ft .btn.primary').click();await wait(()=>!unlock.isConnected&&d.querySelectorAll('.row2').length===2);
            if((await call('verifyEncryptPassword',{path:grant.path,password:secret})).ok)throw Error('consumed import grant remained usable');
            await exportPlain(d,'导出发送集成功');
            d.querySelector('.ft .btn.primary').click();await wait(()=>!dialog('SendEdit')&&feeds.get(9)?.[0]?.PacketCount===2);
          }else{
            await wait(()=>d.querySelectorAll('.row2').length===2);
            if(d.querySelector('.bd > .row input').value!=='C++ 发送编辑测试'||d.querySelector('.row2 .so').textContent!=='99'||!d.querySelector('.row2 .dt').textContent.startsWith('AA FF'))throw Error('send editor restart data mismatch');
            await closeEditor('SendEdit');
          }
    )JS" LR"JS(
          await nav('仓库列表');if(!restart){document.querySelector('.list-page .bar .btn.primary').click();await wait(()=>feeds.get(11)?.length===1&&document.querySelector('.list-page .row .name'));}
          d=await openEditor('WareHouseEdit');
          if(!restart){
            input(d.querySelector('.bd > .row input'),'C++ 仓储编辑测试');
            [...d.querySelectorAll('.runbar .btn')].find(e=>e.textContent.trim().includes('导入')).click();
            await wait(()=>d.querySelectorAll('.row2').length===2&&document.body.textContent.includes('导入仓储数据成功'));
            await exportPlain(d,'导出仓储数据成功');
            d.querySelector('.row2').click();await wait(()=>[...d.querySelectorAll('.runbar .btn')].some(e=>e.textContent.includes('复制')&&!e.disabled));[...d.querySelectorAll('.runbar .btn')].find(e=>e.textContent.includes('复制')).click();await clipEquals('00 FF 80\r\n');
            d.querySelector('.runbar .btn.danger').click();await wait(()=>document.querySelector('[role=alertdialog] .btn:not(.primary)'));
            document.querySelector('[role=alertdialog] .btn:not(.primary)').click();await wait(()=>!document.querySelector('[role=alertdialog]'));
            if(d.querySelectorAll('.row2').length!==2)throw Error('cancelled store clear lost entries');
            d.querySelector('.ft .btn.primary').click();await wait(()=>!dialog('WareHouseEdit')&&feeds.get(11)?.[0]?.Name==='C++ 仓储编辑测试');
          }else{
            await wait(()=>d.querySelectorAll('.row2').length===2&&d.querySelector('.row2 .dt')?.textContent==='00 FF 80');
            if(d.querySelector('.bd > .row input').value!=='C++ 仓储编辑测试')throw Error('warehouse name restart mismatch');await closeEditor('WareHouseEdit');
          }
          document.querySelector('.list-page .bar .btn.warn').click();
          const autoDialog=()=>[...document.querySelectorAll('[role=dialog]')].find(x=>x.querySelector('.sub')?.textContent==='Auto Store');
          const ruleDialog=()=>[...document.querySelectorAll('[role=dialog]')].find(x=>x.querySelector('.sub')?.textContent==='Auto-Store Rule');
          await wait(()=>autoDialog()?.querySelector('.lbar .mini')&&feeds.has(12));
          if(!restart&&!(feeds.get(12)||[]).some(x=>x.PacketHead==='16 03 01')){
            autoDialog().querySelector('.lbar .mini').click();await wait(()=>ruleDialog()?.querySelector('input.inp'));
            input(ruleDialog().querySelector('input.inp'),'16 03 01');ruleDialog().querySelector('.ft .btn.primary').click();
            await wait(()=>!ruleDialog()&&(feeds.get(12)||[]).some(x=>x.PacketHead==='16 03 01'));
            await wait(()=>autoDialog()?.querySelector('.trow .ck button'));
            autoDialog().querySelector('.trow .ck button').click();await wait(()=>feeds.get(12)[0].IsEnable===true);
            await wait(()=>autoDialog()?.querySelector('.bd > .row .v .chk'));autoDialog().querySelector('.bd > .row .v .chk').click();autoDialog().querySelector('.ft .btn.primary').click();await wait(()=>!autoDialog());
          }else{
            await wait(()=>autoDialog().querySelector('.trow .head')?.textContent.trim()==='16 03 01');
            if(!feeds.get(12)[0].IsEnable||(await call('getAutoStoresMeta')).enable)throw Error('auto-store restart state mismatch');
            autoDialog().querySelector('.ft .btn:not(.primary)').click();await wait(()=>!autoDialog());
          }
          await nav('机器人列表');if(!restart){document.querySelector('.list-page .bar .btn.primary').click();await wait(()=>feeds.get(10)?.length===1&&document.querySelector('.list-page .row .name'));}
          d=await openEditor('RobotEdit');
          if(!restart){
            input(d.querySelector('.wbar input.nm'),'C++ 指令闭环测试');
            for(const [type,value] of [[2,2],[1,25],[3,null]]){d.querySelector('.tile.c'+type).click();await wait(()=>d.querySelector('.pcfg.c'+type));if(value!==null)input(d.querySelector('.pcfg input.inp.num:not(:disabled)'),value);const before=d.querySelectorAll('.flow .blk').length;d.querySelector('.pfoot .btn.ins').click();await wait(()=>d.querySelectorAll('.flow .blk').length===before+1);}
            d.querySelector('.ft .btn.primary').click();await wait(()=>!dialog('RobotEdit')&&feeds.get(10)?.[0]?.InstructionCount===3);
            d=await openEditor('RobotEdit');d.querySelector('.tile.c1').click();await wait(()=>d.querySelector('.pcfg.c1'));d.querySelector('.pfoot .btn.ins').click();await wait(()=>d.querySelectorAll('.flow .blk').length===4);await closeEditor('RobotEdit');
            d=await openEditor('RobotEdit');
          }
          await wait(()=>d.querySelectorAll('.flow .blk').length===3);
          if(d.querySelector('.wbar input.nm').value!=='C++ 指令闭环测试'||!d.querySelector('.flow .blk.c1').textContent.includes('25'))throw Error('robot draft/restart mismatch');
          return {originalEditorButtons:true,originalHexViewEdited:true,originalExportButtons:!restart,originalClipboardButtons:!restart,encryptedExportAndImport:!restart,wrongPasswordRetried:!restart,importGrantRestricted:!restart,clipboardTest:'UI uses isolated memory clipboard; real OS clipboard tested separately in private window station',importNotifications:true,chooserCancelKeptData:true,robotCancelKeptSavedInstructions:true,autoStoresRoundTrip:true,editorRestartPersistence:restart,editorCounts:[feeds.get(9)[0].PacketCount,feeds.get(10)[0].InstructionCount,feeds.get(11)[0].DataCount],chooserTest:'fixed-path seam; production Windows picker UI not automated'};
        };
    )JS" LR"JS(
        const prefs=await call('getPrefs');if(!prefs.isDark||prefs.language!=='zh-CN')throw Error('unexpected fresh DB prefs');
        await call('setLanguage',{language:'ja-JP'});if((await call('getPrefs')).language!=='ja-JP')throw Error('language not saved');
        await call('setLanguage',{language:'zh-CN'});
        document.querySelector('.rack .cd.cy').click();
        await wait(()=>document.querySelector('.side .sb-item')&&feeds.has(8)&&feeds.has(15)&&feeds.has(16));
        const firewallIp='192.0.2.77';
        const settingsButton=[...document.querySelectorAll('.modebar .tb')].find(e=>e.textContent.includes('设置'));
        if(!settingsButton)throw Error('original settings button missing');settingsButton.click();
        await wait(()=>[...document.querySelectorAll('.cm-it')].some(e=>e.querySelector('.tx')?.textContent.trim()==='防火墙设置'));
        const firewallItem=[...document.querySelectorAll('.cm-it')].find(e=>e.querySelector('.tx')?.textContent.trim()==='防火墙设置');
        if(!firewallItem)throw Error('original firewall menu item missing');firewallItem.click();
        const firewallDialog=()=>[...document.querySelectorAll('[role=dialog]')].find(d=>d.querySelector('.sub')?.textContent==='Access Control');
        await wait(()=>firewallDialog()?.querySelector('.lbar .mini'));
        if(!(feeds.get(15)||[]).some(r=>r.IPAddress===firewallIp)){
          firewallDialog().querySelector('.lbar .mini').click();
          const ruleDialog=()=>[...document.querySelectorAll('[role=dialog]')].find(d=>d.querySelector('.sub')?.textContent==='IP Rule');
          await wait(()=>ruleDialog()?.querySelector('input[placeholder="192.168.1.100"]'));
          input(ruleDialog().querySelector('input[placeholder="192.168.1.100"]'),firewallIp);
          ruleDialog().querySelector('.ft .btn.primary').click();
          await wait(()=>!ruleDialog()&&(feeds.get(15)||[]).some(r=>r.IPAddress===firewallIp));
        }
        await wait(()=>[...firewallDialog().querySelectorAll('.trow .ip')].some(e=>e.textContent.trim()===firewallIp));
        firewallDialog().querySelector('.ft .btn:not(.primary)').click();
        await wait(()=>!firewallDialog());
        const firewallIpRuleRoundTrip=true;
        const accountName='C++ 账号闭环测试',accountPassword="P@ss'中";
        const accountNav=[...document.querySelectorAll('.side .sb-item')].find(e=>e.querySelector('.t')?.textContent.trim()==='账号列表');
        if(!accountNav)throw Error('original account navigation missing');accountNav.click();
        await wait(()=>document.querySelector('.list-page.acct .bar .btn.primary')&&feeds.has(5));
        const accountDialog=()=>[...document.querySelectorAll('[role=dialog]')].find(d=>d.querySelector('.sub')?.textContent==='Proxy Account');
        if(!feeds.get(5).some(r=>r.UserName===accountName)){
          document.querySelector('.list-page.acct .bar .btn.primary').click();await wait(()=>accountDialog()?.querySelectorAll('.bd input.inp').length>=2);
          const fields=accountDialog().querySelectorAll('.bd input.inp');input(fields[0],accountName);input(fields[1],accountPassword);
          accountDialog().querySelector('.ft .btn.primary').click();
          await wait(()=>!accountDialog()&&feeds.get(5)?.some(r=>r.UserName===accountName));
        }
        const account=feeds.get(5).find(r=>r.UserName===accountName);if(!account||(await call('getAccountPassword',{id:account.Id})).password!==accountPassword)throw Error('account password round trip failed');
        const batchNames=['C++批量-001','C++批量-002'];
        if(!batchNames.every(name=>feeds.get(5).some(r=>r.UserName===name))){
          const accountButtons=document.querySelectorAll('.list-page.acct .bar .btn');accountButtons[1].click();
          const batchDialog=()=>[...document.querySelectorAll('[role=dialog]')].find(d=>d.querySelector('.sub')?.textContent==='Batch Create');await wait(()=>batchDialog()?.querySelectorAll('.rd').length===2);
          const batch=batchDialog();batch.querySelectorAll('.rd')[1].click();input(batch.querySelector('input.pf'),'C++批量-');const nums=batch.querySelectorAll('input.num');input(nums[0],2);input(nums[1],8);
          [...batch.querySelectorAll('.grp.bar .mini')].find(e=>e.textContent.includes('生成')).click();await wait(()=>batch.querySelectorAll('.drow').length===2);
          const noticeCount=notices.length;[...batch.querySelectorAll('.grp.bar .mini')].find(e=>e.textContent.includes('导出')).click();await wait(()=>notices.length>noticeCount&&notices.at(-1).title==='导出到Excel成功');
          batch.querySelector('.ft .btn.primary').click();await wait(()=>!batchDialog()&&batchNames.every(name=>feeds.get(5).some(r=>r.UserName===name)));
        }
        if(!batchNames.every(name=>feeds.get(5).some(r=>r.UserName===name)))throw Error('batch account restart persistence failed');
        const accountRoundTrip=true;
        const batchAccountRoundTrip=true;
    )JS" LR"JS(
        if(!(feeds.get(13)||[]).some(r=>r.Host==='ui-map.example')){
          const saved=await call('saveMapLocal',{host:'ui-map.example',port:8080,remotePath:'/asset',localPath:'C:\\WPE64\\asset.bin'});if(saved.error)throw Error(saved.error);
          const redirected=await call('saveMapRemote',{hostFrom:'ui-from.example',portFrom:80,pathFrom:'/old',hostTo:'ui-to.example',portTo:8081,pathTo:'/new'});if(redirected.error)throw Error(redirected.error);
          await call('saveMapSetting',{enableLocal:true,enableRemote:true});
        }
        settingsButton.click();await wait(()=>[...document.querySelectorAll('.cm-it')].some(e=>e.querySelector('.tx')?.textContent.trim()==='映射设置'));
        [...document.querySelectorAll('.cm-it')].find(e=>e.querySelector('.tx')?.textContent.trim()==='映射设置').click();
        const mapDialog=()=>[...document.querySelectorAll('[role=dialog]')].find(d=>d.querySelector('.sub')?.textContent==='Address Mapping');await wait(()=>mapDialog()?.textContent.includes('ui-map.example')&&mapDialog()?.textContent.includes('ui-to.example'));mapDialog().querySelector('.ft .btn:not(.primary)').click();await wait(()=>!mapDialog());
        await nav('WPC 配置');
        if(!(feeds.get(17)||[]).some(r=>r.Name==='C++ WPC 节点')){
          const saved=await call('saveServer',{enable:true,name:'C++ WPC 节点',ip:'127.0.0.1',port:1080,forgotUrl:'/forgot',registerUrl:'/register',verifyUrl:'/verify'});if(saved.error)throw Error(saved.error);
          const server=feeds.get(17).find(r=>r.Name==='C++ WPC 节点');const rule=await call('saveServerRule',{sid:server.Id,enable:true,type:1,argument:'example.com;example.org',ruleAction:0});if(rule.error)throw Error(rule.error);
          const notice=await call('saveNotice',{type:2,title:'C++ WPC 公告',content:'公告正文',more:'/more'});if(notice.error)throw Error(notice.error);
        }
        await wait(()=>document.querySelector('.list-page.wpc .row .name')?.textContent==='C++ WPC 节点');const server=feeds.get(17).find(r=>r.Name==='C++ WPC 节点');if(!server||server.RuleCount!==2||!(feeds.get(18)||[]).some(r=>r.Title==='C++ WPC 公告'))throw Error('WPC configuration round trip failed');
        const configurationListsRoundTrip=true;
        const filterNav=[...document.querySelectorAll('.side .sb-item')].find(e=>e.querySelector('.t')?.textContent.trim()==='滤镜列表');
        if(!filterNav)throw Error('original filter navigation missing');filterNav.click();
        await wait(()=>document.querySelector('.list-page .bar .btn.primary'));
        if(feeds.get(8).length){
          const old=feeds.get(8);if(old.length!==1||old[0].Name!=='C++ 数据闭环测试'||!old[0].IsEnable)throw Error('restart list persistence failed');
          const restored=(await call('getFilterEdit',{id:old[0].Id})).row;
          if(restored.Modify[0].Index!==-1||!restored.Modify[0].Progression)throw Error('restart editor persistence failed');
          await wait(()=>document.querySelector('.list-page .row .name')?.textContent==='C++ 数据闭环测试');
          const editorResult=await editors(true);const switched=await call('saveInstance',{path:info.dbDir});if(!switched.ok)throw Error('instance path switch failed');await call('__testDone',{ok:true,restartPersistence:true,instancePathRoundTrip:true,firewallIpRuleRoundTrip,accountRoundTrip,batchAccountRoundTrip,configurationListsRoundTrip,originalListDom:true,persistentFilterId:old[0].Id,dbFull:info.dbFull,topmostProbe:top.topMost?'passed':'failed-background-request-not-applied',...editorResult});return;
        }
        document.querySelector('.list-page .bar .btn.primary').click();
        await wait(()=>feeds.get(8)?.length===1&&document.querySelector('.list-page .row .name'));
        const id=feeds.get(8)[0].Id;const edit=(await call('getFilterEdit',{id})).row;
        edit.Name='C++ 数据闭环测试';edit.Mode=1;edit.StartFrom=1;
        edit.Search=[{Index:0,Value:'AA',Exclude:true}];edit.Modify=[{Index:-1,Value:'BB',Progression:true,Random:false}];
        const saved=await call('saveFilterEdit',{row:edit});if(!saved.ok)throw Error(saved.error);
        await wait(()=>document.querySelector('.list-page .row .name')?.textContent==='C++ 数据闭环测试');
        document.querySelector('.list-page .row .chk').click();
        await wait(()=>feeds.get(8)?.[0]?.IsEnable===true);
        const back=(await call('getFilterEdit',{id})).row;if(back.Modify[0].Index!==-1)throw Error('negative offset lost');
        const deletion=call('filterListAction',{action:6,ids:[id]});
        await wait(()=>document.querySelector('[role=alertdialog] .btn:not(.primary)'));
        document.querySelector('[role=alertdialog] .btn:not(.primary)').click();await deletion;
        if(!(await call('getFilterEdit',{id})).row)throw Error('cancelled deletion changed data');
        const editorResult=await editors(false);const switched=await call('saveInstance',{path:info.dbDir});if(!switched.ok)throw Error('instance path switch failed');await call('__testDone',{ok:true,titlebar:!!document.querySelector('.titlebar'),modeCards,instancePathRoundTrip:true,unsupportedRejected:unsupported,windowRoundTrip:!!top.topMost,topmostProbe:top.topMost?'passed':'failed-background-request-not-applied',firewallIpRuleRoundTrip,accountRoundTrip,batchAccountRoundTrip,configurationListsRoundTrip,originalListDom:true,originalAddAndEnableButtons:true,negativeOffsetRoundTrip:true,cancelledDeletionKeptData:true,persistentFilterId:id,dbFull:info.dbFull,url:location.href,...editorResult});
      })().catch(error=>call('__testDone',{ok:false,error:String(error)}));
    })())JS");
}
void Host::CaptureAndFinish(){
    if(done_)return;
    ComPtr<IStream> output;
    Check(SHCreateStreamOnFileEx((options_.report/L"original-vue.png").c_str(),STGM_CREATE|STGM_WRITE|STGM_SHARE_EXCLUSIVE,FILE_ATTRIBUTE_NORMAL,TRUE,nullptr,&output),"Open preview output");
    Check(view_->CapturePreview(COREWEBVIEW2_CAPTURE_PREVIEW_IMAGE_FORMAT_PNG,output.Get(),Callback<ICoreWebView2CapturePreviewCompletedHandler>([this,output,alive=std::weak_ptr(lifetime_)](HRESULT hr)->HRESULT{
        if(alive.expired()||closing_)return S_OK;
        return Guard([&]{Check(hr,"Capture original Vue preview");Check(output->Commit(STGC_DEFAULT),"Commit preview");Finish(report_.value("originalVueConfirmed",false)&&report_.contains("frontend")&&report_["frontend"].value("ok",false));});
    }).Get()),"Capture preview");
}
void Host::Fail(const std::string& message){
    if(done_||closing_||failure_posted_)return;
    failure_posted_=true;exit_code_=1;
    report_["error"]=message;
    PostMessageW(window_,app_failure,0,0);
}
void Host::Finish(bool success){
    if(done_)return;done_=true;exit_code_=success?0:1;
    report_["result"]=success?"passed":"failed";report_["webMessagesReceived"]=messages_;report_["nativeDrag"]=native_drag_;
    report_["scope"]="Exchange/editor acceptance: original Vue/HexView/export/copy/paste -> native RPC/SQLite/files. UI clipboard uses isolated memory; OS clipboard verified separately on private station. File chooser fixed-path seam. topmostProbe non-gating; no picker UI automation, capture/proxy/injection/execution";
    if(options_.test){std::ofstream file(options_.report/L"host-self-test.json",std::ios::binary);file<<report_.dump(2);file.flush();if(!file)exit_code_=1;}
    PostMessageW(window_,WM_CLOSE,0,0);
}
} // namespace
int WINAPI wWinMain(HINSTANCE,HINSTANCE,PWSTR,int){
    const HRESULT initialized=CoInitializeEx(nullptr,COINIT_APARTMENTTHREADED);
    if(FAILED(initialized))return 1;
    int result=1;
    try{Host host(Arguments());result=host.Run();}
    catch(const std::exception& error){
        OutputDebugStringW(Wide(error.what()).c_str());
        if(!wcsstr(GetCommandLineW(),L"--self-test"))MessageBoxW(nullptr,Wide(error.what()).c_str(),L"WPE C++ 启动失败",MB_OK|MB_ICONERROR);
    }
    CoUninitialize();return result;
}
