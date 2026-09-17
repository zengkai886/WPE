#pragma once
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objbase.h>
#include "web_bridge.h"
#include <algorithm>
#include <charconv>
#include <iomanip>
#include <regex>
#include <optional>
#include <sstream>

namespace wpe::shell::data_detail {
inline const std::array<std::string,4> tables={"Filter","Send","Robot","WareHouse"};
inline const std::array<std::string,4> children={"","SendCollection","RobotInstruction","WareHouseData"};
inline std::string S(const Json& j,const char* key,std::string fallback={}){
    const auto it=j.find(key);if(it==j.end()||it->is_null())return fallback;
    return it->is_string()?it->get<std::string>():it->dump();
}
inline int N(const Json& j,const char* key,int fallback=0){const auto it=j.find(key);return it==j.end()||it->is_null()?fallback:it->get<int>();}
inline bool B(const Json& j,const char* key,bool fallback=false){const auto it=j.find(key);return it==j.end()||it->is_null()?fallback:it->is_boolean()?it->get<bool>():it->get<int>()!=0;}
inline std::string Upper(std::string s){for(auto& c:s)if(c>='a'&&c<='z')c=static_cast<char>(c-32);return s;}
inline std::string Trim(const std::string& s,bool removeAll=false){
    if(s.empty())return {};
    if(s.size()>static_cast<std::size_t>(INT_MAX))throw std::length_error("Text exceeds Windows conversion limit");
    const auto size=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0);
    if(!size)throw std::invalid_argument("Invalid UTF-8 text");
    std::wstring text(static_cast<std::size_t>(size),L'\0');MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),text.data(),size);
    // .NET Framework 4.8 Char.IsWhiteSpace, not the C locale's ASCII isspace.
    auto space=[](wchar_t c){return (c>=9&&c<=13)||c==0x20||c==0x85||c==0xA0||c==0x1680||
        (c>=0x2000&&c<=0x200A)||c==0x2028||c==0x2029||c==0x202F||c==0x205F||c==0x3000;};
    if(removeAll)text.erase(std::remove_if(text.begin(),text.end(),space),text.end());
    std::size_t from=0,to=text.size();while(from<to&&space(text[from]))++from;while(to>from&&space(text[to-1]))--to;
    if(from==to)return {};
    const auto length=static_cast<int>(to-from);const auto bytes=WideCharToMultiByte(CP_UTF8,0,text.data()+from,length,nullptr,0,nullptr,nullptr);
    std::string result(static_cast<std::size_t>(bytes),'\0');WideCharToMultiByte(CP_UTF8,0,text.data()+from,length,result.data(),bytes,nullptr,nullptr);return result;
}
inline std::string Guid(){GUID guid{};if(FAILED(CoCreateGuid(&guid)))throw std::runtime_error("GUID generation failed");wchar_t text[40]{};StringFromGUID2(guid,text,40);std::string out;for(int i=1;i<37;++i)out+=static_cast<char>(text[i]);return Upper(out);}
inline const std::string zero_guid="00000000-0000-0000-0000-000000000000";
inline std::string NormalGuid(const std::string& s){
    if(std::regex_match(s,std::regex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")))return Upper(s);
    return zero_guid;
}
inline Json Good(){return {{"ok",true}};}
inline Json Bad(const std::string& message){return {{"ok",false},{"error",message}};}
inline std::vector<std::string> Split(const std::string& s,char separator){std::vector<std::string> result;std::istringstream input(s);std::string item;while(std::getline(input,item,separator))result.push_back(item);return result;}
inline bool Integer(const std::string& s,int& number){
    // NumberStyles.Integer whitespace is narrower than String.Trim whitespace.
    auto space=[](char c){return c==' '||(c>='\t'&&c<='\r');};
    std::string_view t=s;while(!t.empty()&&space(t.front()))t.remove_prefix(1);while(!t.empty()&&space(t.back()))t.remove_suffix(1);
    if(t.starts_with('+')){t.remove_prefix(1);if(t.empty()||t[0]<'0'||t[0]>'9')return false;}
    auto [end,ec]=std::from_chars(t.data(),t.data()+t.size(),number);return !t.empty()&&ec==std::errc{}&&end==t.data()+t.size();
}
inline std::optional<std::uint32_t> IPv4Value(const std::string& input){
    const auto text=Trim(input);std::uint32_t value=0;std::size_t start=0;
    for(int part=0;part<4;++part){const auto end=text.find('.',start);if((part<3&&end==text.npos)||(part==3&&end!=text.npos))return {};
        const auto piece=text.substr(start,(end==text.npos?text.size():end)-start);if(piece.empty()||piece.size()>3)return {};int number=0;
        const auto [last,ec]=std::from_chars(piece.data(),piece.data()+piece.size(),number);if(ec!=std::errc{}||last!=piece.data()+piece.size()||number<0||number>255)return {};
        value=(value<<8)|static_cast<std::uint32_t>(number);start=end==text.npos?text.size():end+1;
    }return value;
}
inline std::optional<std::pair<std::uint32_t,std::uint32_t>> IpRuleRange(const std::string& input){
    const auto text=Trim(input);const auto dash=text.find('-');
    if(dash!=std::string::npos){if(text.find('-',dash+1)!=std::string::npos)return {};const auto first=IPv4Value(text.substr(0,dash)),last=IPv4Value(text.substr(dash+1));if(!first||!last)return {};return std::pair{*first,*last};}
    const auto slash=text.find('/');if(slash!=std::string::npos){if(text.find('/',slash+1)!=std::string::npos)return {};const auto base=IPv4Value(text.substr(0,slash));int bits=0;if(!base||!Integer(text.substr(slash+1),bits)||bits<0||bits>32)return {};
        const std::uint32_t mask=bits==0?0u:0xffffffffu<<(32-bits);const auto first=*base&mask;return std::pair{first,static_cast<std::uint32_t>(first|~mask)};}
    const auto value=IPv4Value(text);if(!value)return {};return std::pair{*value,*value};
}
inline int DaysInMonth(int year,int month){static constexpr int days[]={0,31,28,31,30,31,30,31,31,30,31,30,31};if(month<1||month>12)return 0;return month==2&&((year%4==0&&year%100!=0)||year%400==0)?29:days[month];}
inline std::optional<std::string> DateTimeText(const std::string& input){
    std::smatch match;static const std::regex pattern(R"(^\s*(\d{4})[-/](\d{1,2})[-/](\d{1,2})[ T](\d{1,2}):(\d{1,2})(?::(\d{1,2}))?\s*$)");if(!std::regex_match(input,match,pattern))return {};
    const int year=std::stoi(match[1].str()),month=std::stoi(match[2].str()),day=std::stoi(match[3].str()),hour=std::stoi(match[4].str()),minute=std::stoi(match[5].str()),second=match[6].matched?std::stoi(match[6].str()):0;
    if(year<1||year>9999||day<1||day>DaysInMonth(year,month)||hour>23||minute>59||second>59)return {};
    std::ostringstream out;out<<std::setfill('0')<<std::setw(4)<<year<<'-'<<std::setw(2)<<month<<'-'<<std::setw(2)<<day<<' '<<std::setw(2)<<hour<<':'<<std::setw(2)<<minute<<':'<<std::setw(2)<<second;return out.str();
}
inline std::string XmlDate(std::string text){std::replace(text.begin(),text.end(),'-','/');return text;}
inline std::string LocalDateTime(int addHours=0){
    FILETIME utc{};GetSystemTimeAsFileTime(&utc);ULARGE_INTEGER value{};value.LowPart=utc.dwLowDateTime;value.HighPart=utc.dwHighDateTime;value.QuadPart+=static_cast<std::uint64_t>(std::max(0,addHours))*3600ull*10000000ull;utc.dwLowDateTime=value.LowPart;utc.dwHighDateTime=value.HighPart;
    FILETIME local{};SYSTEMTIME time{};if(!FileTimeToLocalFileTime(&utc,&local)||!FileTimeToSystemTime(&local,&time))throw std::runtime_error("Unable to read local time");
    std::ostringstream out;out<<std::setfill('0')<<std::setw(4)<<time.wYear<<'-'<<std::setw(2)<<time.wMonth<<'-'<<std::setw(2)<<time.wDay<<' '<<std::setw(2)<<time.wHour<<':'<<std::setw(2)<<time.wMinute<<':'<<std::setw(2)<<time.wSecond;return out.str();
}
inline int Mask(const std::string& s){int value=0,i=0;for(const auto& part:Split(s,':')){if(i>=12)break;if(part=="1")value|=1<<i;++i;}return value;}
inline std::string Function(int mask){std::string s;for(int i=0;i<12;++i){if(i)s+=':';s+=(mask&(1<<i))?'1':'0';}return s;}
inline std::string Color(const Json& j,const char* key){std::ostringstream out;out<<'#'<<std::uppercase<<std::hex<<std::setw(6)<<std::setfill('0')<<(static_cast<std::uint32_t>(N(j,key))&0xFFFFFF);return out.str();}
inline std::string Hex(const Json& binary,std::size_t limit=60){
    if(!binary.is_binary())return {};const auto& b=binary.get_binary();const char digits[]="0123456789ABCDEF";std::string out;
    for(std::size_t i=0;i<std::min(b.size(),limit);++i){if(i)out+=' ';out+=digits[b[i]>>4];out+=digits[b[i]&15];}if(b.size()>limit)out+=" ...";return out;
}
inline std::size_t Size(const Json& binary){return binary.is_binary()?binary.get_binary().size():0;}
inline Json RuntimeChildren(Json rows,int list,std::uint64_t& packet_id){
    for(auto& child:rows)child["_id"]=list==11?Guid():std::to_string(++packet_id);return rows;
}
inline std::optional<std::string> TryGuid(std::string s){
    // Guid.TryParse also accepts the hexadecimal X form. Whitespace is ignored
    // inside that form, but not inside the ordinary D/N/B/P representations.
    if(s.find("0x")!=s.npos||s.find("0X")!=s.npos){
        const auto compact=Trim(s,true);
        std::smatch match;static const std::regex x(R"(\{0[xX]([0-9a-fA-F]+),0[xX]([0-9a-fA-F]+),0[xX]([0-9a-fA-F]+),\{0[xX]([0-9a-fA-F]+),0[xX]([0-9a-fA-F]+),0[xX]([0-9a-fA-F]+),0[xX]([0-9a-fA-F]+),0[xX]([0-9a-fA-F]+),0[xX]([0-9a-fA-F]+),0[xX]([0-9a-fA-F]+),0[xX]([0-9a-fA-F]+)\}\})");
        if(!std::regex_match(compact,match,x))return {};
        s.clear();for(std::size_t i=1;i<match.size();++i){const std::size_t width=i==1?8:i<4?4:2;auto part=match[i].str();const auto start=part.find_first_not_of('0');part=start==part.npos?"0":part.substr(start);if(part.size()>width)return {};s+=std::string(width-part.size(),'0')+part;}
    }
    s=Trim(s);if(s.size()>1&&((s.front()=='{'&&s.back()=='}')||(s.front()=='('&&s.back()==')'))){if(s.size()!=38)return {};s=s.substr(1,s.size()-2);}
    if(std::regex_match(s,std::regex("[0-9a-fA-F]{32}")))s=s.substr(0,8)+'-'+s.substr(8,4)+'-'+s.substr(12,4)+'-'+s.substr(16,4)+'-'+s.substr(20);
    if(!std::regex_match(s,std::regex("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")))return {};return Upper(s);
}
}
