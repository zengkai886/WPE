#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlwapi.h>
#include <xmllite.h>
#include <wrl.h>
#include <fstream>
#include "editor_xml.h"
#include "data_util.h"
#include "xml_document.h"
#include "xml_crypto.h"
namespace wpe::shell {
using Microsoft::WRL::ComPtr;
using namespace data_detail;
namespace {
void XmlCheck(HRESULT hr){if(FAILED(hr))throw std::runtime_error("XML 导入失败：文件损坏、格式不支持或密码不正确");}
std::string Utf8(const wchar_t* p,UINT n){
    if(!n)return {};const int size=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,p,static_cast<int>(n),nullptr,0,nullptr,nullptr);
    if(!size)throw std::runtime_error("XML 文本编码错误");std::string out(static_cast<std::size_t>(size),'\0');
    WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,p,static_cast<int>(n),out.data(),size,nullptr,nullptr);return out;
}
Json Unhex(const std::string& s){
    std::string clean;for(char c:s)if(c!=' '&&c!='-'&&c!=':')clean+=c;
    std::vector<std::uint8_t> bytes;if(clean.size()%2)return Json::binary(bytes);
    auto nibble=[](char c){return c>='0'&&c<='9'?c-'0':c>='A'&&c<='F'?c-'A'+10:c>='a'&&c<='f'?c-'a'+10:-1;};
    for(std::size_t i=0;i<clean.size();i+=2){int hi=nibble(clean[i]),lo=nibble(clean[i+1]);if(hi<0||lo<0)return Json::binary(std::vector<std::uint8_t>{});bytes.push_back(static_cast<std::uint8_t>((hi<<4)|lo));}
    return Json::binary(bytes);
}
const std::array<const char*,23> packetNames={"WS1_Send","WS2_Send","WS1_SendTo","WS2_SendTo","WS1_Recv","WS2_Recv","WS1_RecvFrom","WS2_RecvFrom","WSASend","WSASendTo","WSARecv","WSARecvEx","WSARecvFrom","TCP_Req","UDP_Req","TCP_Resp","UDP_Resp","HTTP_Req","HTTP_Resp","HTTPS_Req","HTTPS_Resp","WebSocket_Req","WebSocket_Resp"};
int PacketType(const std::string& name){
    const auto text=Trim(name);for(std::size_t i=0;i<packetNames.size();++i)if(text==packetNames[i])return static_cast<int>(i);
    int value=0;return Integer(text,value)?value:0;
}
std::string EscapeXml(const std::string& s){
    if(s.size()>INT_MAX)throw std::length_error("XML 字段过长");
    if(!s.empty()){
        const auto size=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0);
        if(!size)throw std::runtime_error("XML 字段包含无效 UTF-8");
        std::wstring wide(static_cast<std::size_t>(size),L'\0');MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),wide.data(),size);
        for(wchar_t c:wide)if((c<0x20&&c!=9&&c!=10&&c!=13)||c==0xFFFE||c==0xFFFF)throw std::runtime_error("XML 字段包含无效控制字符");
    }
    std::string out;for(std::size_t i=0;i<s.size();++i){switch(s[i]){
        case '&':out+="&amp;";break;case '<':out+="&lt;";break;case '>':out+="&gt;";break;
        case '\r':if(i+1<s.size()&&s[i+1]=='\n')++i;[[fallthrough]];
        case '\n':out+="\r\n";break;default:out+=s[i];break;
    }}return out;
}
class AtomicOutput {
    std::filesystem::path target_,temporary_;HANDLE file_=INVALID_HANDLE_VALUE;bool committed_=false;
public:
    explicit AtomicOutput(const std::filesystem::path& target):target_(target){
        const auto id=Guid();temporary_=target.parent_path()/(L".wpe-export-"+std::wstring(id.begin(),id.end())+L".tmp");
        // A replacement must not expose an existing restricted file through a
        // more permissive temporary. Apply its DACL at creation, before bytes.
        DWORD needed=0;std::vector<std::uint8_t> security;
        if(!GetFileSecurityW(target.c_str(),DACL_SECURITY_INFORMATION,nullptr,0,&needed)){
            const auto error=GetLastError();if(error==ERROR_INSUFFICIENT_BUFFER){security.resize(needed);if(!GetFileSecurityW(target.c_str(),DACL_SECURITY_INFORMATION,security.data(),needed,&needed))throw std::runtime_error("无法读取原导出文件权限");}
            else if(error!=ERROR_FILE_NOT_FOUND)throw std::runtime_error("无法检查原导出文件权限");
        }
        SECURITY_ATTRIBUTES attributes{sizeof(SECURITY_ATTRIBUTES),security.empty()?nullptr:security.data(),FALSE};
        file_=CreateFileW(temporary_.c_str(),GENERIC_WRITE,0,security.empty()?nullptr:&attributes,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr);
        if(file_==INVALID_HANDLE_VALUE)throw std::runtime_error("无法创建导出文件：请检查路径与写入权限");
    }
    ~AtomicOutput(){if(file_!=INVALID_HANDLE_VALUE)CloseHandle(file_);if(!committed_)DeleteFileW(temporary_.c_str());}
    AtomicOutput(const AtomicOutput&)=delete;AtomicOutput& operator=(const AtomicOutput&)=delete;
    void Write(std::string_view s){while(!s.empty()){const auto count=static_cast<DWORD>(std::min<std::size_t>(s.size(),1024*1024));DWORD written=0;if(!WriteFile(file_,s.data(),count,&written,nullptr)||written!=count)throw std::runtime_error("导出文件写入失败，原文件未替换");s.remove_prefix(written);}}
    void Commit(){
        if(!FlushFileBuffers(file_))throw std::runtime_error("导出文件刷新失败，原文件未替换");
        const auto handle=file_;file_=INVALID_HANDLE_VALUE;if(!CloseHandle(handle))throw std::runtime_error("导出文件关闭失败");
        if(MoveFileExW(temporary_.c_str(),target_.c_str(),MOVEFILE_WRITE_THROUGH)){committed_=true;return;}
        // Do not ignore merge/ACL errors. A backup also prevents ReplaceFile's
        // partial-failure cases from destroying the only copy of the old file.
        auto backup=temporary_;backup+=L".bak";
        if(GetFileAttributesW(backup.c_str())!=INVALID_FILE_ATTRIBUTES)throw std::runtime_error("导出恢复文件已存在，停止替换");
        if(!ReplaceFileW(target_.c_str(),temporary_.c_str(),backup.c_str(),0,nullptr,nullptr)){
            const auto error=GetLastError();
            if(GetFileAttributesW(backup.c_str())!=INVALID_FILE_ATTRIBUTES){
                if(!MoveFileExW(backup.c_str(),target_.c_str(),MOVEFILE_WRITE_THROUGH))throw std::runtime_error("导出替换失败，原文件保留于恢复文件："+backup.string());
            }
            throw std::runtime_error("无法替换导出文件：文件被占用或没有写入权限（"+std::to_string(error)+"）");
        }
        committed_=true;
        if(!DeleteFileW(backup.c_str()))throw std::runtime_error("导出已写入，但旧文件恢复副本清理失败："+backup.string());
    }
};
}
void WriteXmlFileBytes(const std::filesystem::path& path,std::string_view bytes){AtomicOutput file(path);file.Write(bytes);file.Commit();}
void WriteEditorXml(const std::filesystem::path& path,const Json& rows,bool send,const std::string& password){
    if(!password.empty()){
        XmlNode root(send?"SendCollection":"Stores");for(const auto& row:rows){
            if(!row.at("Buffer").is_binary())throw std::runtime_error("导出封包 Buffer 不是二进制数据");XmlNode child(send?"Collection":"Data");
            if(send){const auto type=N(row,"Type");child.nodes={XmlNode("Socket",std::to_string(N(row,"Socket"))),XmlNode("Type",type>=0&&type<static_cast<int>(packetNames.size())?packetNames[type]:std::to_string(type)),XmlNode("IPFrom",S(row,"IPFrom")),XmlNode("IPTo",S(row,"IPTo"))};}
            child.nodes.emplace_back(send?"Buffer":"PacketData",Hex(row["Buffer"],std::numeric_limits<std::size_t>::max()));root.nodes.push_back(std::move(child));
        }WriteXmlFile(path,root,password);return;
    }
    AtomicOutput file(path);file.Write("\xEF\xBB\xBF<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\r\n");
    const std::string root=send?"SendCollection":"Stores",child=send?"Collection":"Data";
    if(rows.empty()){file.Write("<"+root+" />");file.Commit();return;}
    file.Write("<"+root+">\r\n");
    auto element=[&](const std::string& name,const std::string& value){file.Write("    <"+name+">"+EscapeXml(value)+"</"+name+">\r\n");};
    for(const auto& row:rows){if(!row.at("Buffer").is_binary())throw std::runtime_error("导出封包 Buffer 不是二进制数据");file.Write("  <"+child+">\r\n");if(send){
        element("Socket",std::to_string(N(row,"Socket")));const auto type=N(row,"Type");element("Type",type>=0&&type<static_cast<int>(packetNames.size())?packetNames[type]:std::to_string(type));
        element("IPFrom",S(row,"IPFrom"));element("IPTo",S(row,"IPTo"));
    }element(send?"Buffer":"PacketData",Hex(row.at("Buffer"),std::numeric_limits<std::size_t>::max()));file.Write("  </"+child+">\r\n");}
    file.Write("</"+root+">");file.Commit();
}
static Json ConvertEditorRows(const Json& raw,const std::string& root,bool send){
    if(send&&root!="SendCollection"&&root!="SendList")throw std::runtime_error("不是原版发送集 XML 文件");
    Json result=Json::array();for(const auto& item:raw){
        if(!send){if(item.contains("PacketData"))result.push_back({{"Buffer",Unhex(S(item,"PacketData"))}});continue;}
        const char* buffer=root=="SendList"?"Data":"Buffer";if(!item.contains(buffer))continue;
        int socket=0;if(item.contains("Socket")&&!Integer(S(item,"Socket"),socket))throw std::runtime_error("XML Socket 不是有效的 32 位整数，未导入任何条目");
        result.push_back({{"Socket",socket},{"Type",PacketType(S(item,"Type"))},{"IPFrom",S(item,"IPFrom")},{"IPTo",S(item,root=="SendList"?"ToAddress":"IPTo")},{"Buffer",Unhex(S(item,buffer))}});
    }return result;
}
static Json ReadEditorStream(IStream* stream,bool send){
    // Stream from the selected file rather than copying/capping its raw bytes.
    // Denying concurrent writes gives this import a stable read-only snapshot.
    ComPtr<IXmlReader> reader;XmlCheck(CreateXmlReader(__uuidof(IXmlReader),reinterpret_cast<void**>(reader.GetAddressOf()),nullptr));
    XmlCheck(reader->SetProperty(XmlReaderProperty_DtdProcessing,DtdProcessing_Prohibit));
    XmlCheck(reader->SetProperty(XmlReaderProperty_MaxElementDepth,64));XmlCheck(reader->SetInput(stream));
    Json raw=Json::array(),row=Json::object();std::string root,field;XmlNodeType type{};HRESULT hr;
    while((hr=reader->Read(&type))==S_OK){
        UINT depth=0;XmlCheck(reader->GetDepth(&depth));
        if(type==XmlNodeType_Element){
            const wchar_t* name=nullptr;UINT len=0;XmlCheck(reader->GetLocalName(&name,&len));const auto tag=Utf8(name,len);
            if(depth==0)root=tag;
            if(depth==1){row=Json::object();if(reader->IsEmptyElement())raw.push_back(row);}
            if(depth==2){
                // XElement.Element returns the first matching child, not the last.
                const wchar_t* uri=nullptr;UINT uriLen=0;XmlCheck(reader->GetNamespaceUri(&uri,&uriLen));
                field=uriLen||row.contains(tag)?"":tag;if(!field.empty())row[field]="";
            }
        }else if(type==XmlNodeType_Text||type==XmlNodeType_CDATA||type==XmlNodeType_Whitespace){
            if(depth>=3&&!field.empty()){const wchar_t* value=nullptr;UINT len=0;XmlCheck(reader->GetValue(&value,&len));row[field]=S(row,field.c_str())+Utf8(value,len);}
        }else if(type==XmlNodeType_EndElement){
            // XmlLite reports the closing node one level below its opening node.
            if(depth==3)field.clear();if(depth==2)raw.push_back(std::move(row));
        }
    }
    XmlCheck(hr);if(root.empty())throw std::runtime_error("XML 缺少根元素");
    return ConvertEditorRows(raw,root,send);
}
Json ReadEditorXmlNode(const XmlNode& root,bool send){
    Json raw=Json::array();for(const auto& node:root.nodes){Json row=Json::object();for(const auto& field:node.nodes)if(field.namespace_uri.empty()&&!row.contains(field.name))row[field.name]=field.text.value_or("");raw.push_back(std::move(row));}
    return ConvertEditorRows(raw,root.name,send);
}
Json ReadEditorXml(const std::filesystem::path& path,bool send){ComPtr<IStream> stream;XmlCheck(SHCreateStreamOnFileEx(path.c_str(),STGM_READ|STGM_SHARE_DENY_WRITE,FILE_ATTRIBUTE_NORMAL,FALSE,nullptr,&stream));return ReadEditorStream(stream.Get(),send);}
Json ReadEditorXmlContent(std::string_view bytes,bool send){if(bytes.size()>INT_MAX)throw std::length_error("XML 文件过长");ComPtr<IStream> stream;stream.Attach(SHCreateMemStream(reinterpret_cast<const BYTE*>(bytes.data()),static_cast<UINT>(bytes.size())));if(!stream)throw std::bad_alloc();return ReadEditorStream(stream.Get(),send);}
}
