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
}
