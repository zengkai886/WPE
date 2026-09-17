#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlwapi.h>
#include <xmllite.h>
#include <wrl.h>
#include <fstream>
#include "editor_xml.h"
#include "data_util.h"
namespace wpe::shell {
using Microsoft::WRL::ComPtr;
using namespace data_detail;
namespace {
void XmlCheck(HRESULT hr){if(FAILED(hr))throw std::runtime_error("XML 导入失败：文件损坏、格式不支持或已加密（密码导入尚未实现）");}
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
int PacketType(const std::string& name){
    static const std::array<const char*,23> names={"WS1_Send","WS2_Send","WS1_SendTo","WS2_SendTo","WS1_Recv","WS2_Recv","WS1_RecvFrom","WS2_RecvFrom","WSASend","WSASendTo","WSARecv","WSARecvEx","WSARecvFrom","TCP_Req","UDP_Req","TCP_Resp","UDP_Resp","HTTP_Req","HTTP_Resp","HTTPS_Req","HTTPS_Resp","WebSocket_Req","WebSocket_Resp"};
    const auto text=Trim(name);for(std::size_t i=0;i<names.size();++i)if(text==names[i])return static_cast<int>(i);
    int value=0;return Integer(text,value)?value:0;
}
}
Json ReadEditorXml(const std::filesystem::path& path,bool send){
    // Stream from the selected file rather than copying/capping its raw bytes.
    // Denying concurrent writes gives this import a stable read-only snapshot.
    ComPtr<IStream> stream;const auto opened=SHCreateStreamOnFileEx(path.c_str(),STGM_READ|STGM_SHARE_DENY_WRITE,FILE_ATTRIBUTE_NORMAL,FALSE,nullptr,&stream);
    if(FAILED(opened))throw std::runtime_error("无法读取导入文件");
    ComPtr<IXmlReader> reader;XmlCheck(CreateXmlReader(__uuidof(IXmlReader),reinterpret_cast<void**>(reader.GetAddressOf()),nullptr));
    XmlCheck(reader->SetProperty(XmlReaderProperty_DtdProcessing,DtdProcessing_Prohibit));
    XmlCheck(reader->SetProperty(XmlReaderProperty_MaxElementDepth,64));XmlCheck(reader->SetInput(stream.Get()));
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
    if(send&&root!="SendCollection"&&root!="SendList")throw std::runtime_error("不是原版发送集 XML 文件");
    Json result=Json::array();for(const auto& item:raw){
        if(!send){if(item.contains("PacketData"))result.push_back({{"Buffer",Unhex(S(item,"PacketData"))}});continue;}
        const char* buffer=root=="SendList"?"Data":"Buffer";if(!item.contains(buffer))continue;
        int socket=0;if(item.contains("Socket")&&!Integer(S(item,"Socket"),socket))throw std::runtime_error("XML Socket 不是有效的 32 位整数，未导入任何条目");
        result.push_back({{"Socket",socket},{"Type",PacketType(S(item,"Type"))},{"IPFrom",S(item,"IPFrom")},{"IPTo",S(item,root=="SendList"?"ToAddress":"IPTo")},{"Buffer",Unhex(S(item,buffer))}});
    }return result;
}
}
