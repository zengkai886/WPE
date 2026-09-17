#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlwapi.h>
#include <xmllite.h>
#include <wrl.h>
#include <stdexcept>
#include <algorithm>
#include "xml_document.h"
#include "xml_crypto.h"
namespace wpe::shell {
using Microsoft::WRL::ComPtr;
namespace {
void Check(HRESULT hr){if(FAILED(hr))throw std::runtime_error("XML 文件损坏、格式不支持或密码不正确");}
std::string Utf8(const wchar_t* p,UINT n){
    if(!n)return {};const auto size=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,p,static_cast<int>(n),nullptr,0,nullptr,nullptr);if(!size)throw std::runtime_error("XML Unicode 文本无效");
    std::string s(static_cast<std::size_t>(size),0);WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,p,static_cast<int>(n),s.data(),size,nullptr,nullptr);return s;
}
std::string Escape(std::string_view s,bool attr=false){
    if(s.size()>INT_MAX)throw std::length_error("XML 字段过长");
    if(!s.empty()){
        const auto n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),nullptr,0);if(!n)throw std::runtime_error("XML 字段包含无效 UTF-8");
        std::wstring w(static_cast<std::size_t>(n),0);MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,s.data(),static_cast<int>(s.size()),w.data(),n);
        for(auto c:w)if((c<32&&c!=9&&c!=10&&c!=13)||c==0xfffe||c==0xffff)throw std::runtime_error("XML 字段包含无效控制字符");
    }
    std::string out;for(std::size_t i=0;i<s.size();++i){const char c=s[i];
        if(c=='&')out+="&amp;";else if(c=='<')out+="&lt;";else if(c=='>')out+="&gt;";else if(attr&&c=='\"')out+="&quot;";
        else if(attr&&(c=='\r'||c=='\n'||c=='\t'))out+=c=='\r'?"&#xD;":c=='\n'?"&#xA;":"&#x9;";
        else if(c=='\r'||c=='\n'){if(c=='\r'&&i+1<s.size()&&s[i+1]=='\n')++i;out+="\r\n";}else out+=c;
    }return out;
}
void Append(std::string& out,const XmlNode& n,std::size_t depth){
    out+=std::string(depth*2,' ')+"<"+n.name;for(const auto& [key,value]:n.attributes)out+=" "+key+"=\""+Escape(value,true)+"\"";
    if(n.nodes.empty()&&!n.text){out+=" />";return;}out+='>';
    if(n.nodes.empty())out+=Escape(n.text.value_or(""));else{out+="\r\n";for(const auto& child:n.nodes){Append(out,child,depth+1);out+="\r\n";}out+=std::string(depth*2,' ');}
    out+="</"+n.name+">";
}
}
std::string SerializeXml(const XmlNode& root){std::string out="\xEF\xBB\xBF<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?>\r\n";Append(out,root,0);return out;}
XmlNode ParseXml(std::string_view bytes){
    if(bytes.size()>INT_MAX)throw std::length_error("XML 文件超出原 .NET 字节数组范围");
    ComPtr<IStream> stream;stream.Attach(SHCreateMemStream(reinterpret_cast<const BYTE*>(bytes.data()),static_cast<UINT>(bytes.size())));if(!stream)throw std::bad_alloc();
    ComPtr<IXmlReader> reader;Check(CreateXmlReader(__uuidof(IXmlReader),reinterpret_cast<void**>(reader.GetAddressOf()),nullptr));
    Check(reader->SetProperty(XmlReaderProperty_DtdProcessing,DtdProcessing_Prohibit));Check(reader->SetProperty(XmlReaderProperty_MaxElementDepth,64));Check(reader->SetInput(stream.Get()));
    std::optional<XmlNode> root;std::vector<XmlNode*> stack;XmlNodeType type{};HRESULT hr;
    while((hr=reader->Read(&type))==S_OK){
        if(type==XmlNodeType_Element){const wchar_t* p=nullptr;UINT length=0;Check(reader->GetQualifiedName(&p,&length));XmlNode node(Utf8(p,length));const bool empty=reader->IsEmptyElement()!=FALSE;
            Check(reader->GetNamespaceUri(&p,&length));node.namespace_uri=Utf8(p,length);node.preserve_whitespace=!stack.empty()&&stack.back()->preserve_whitespace;
            if(!empty)node.text="";
            if(reader->MoveToFirstAttribute()==S_OK){do{Check(reader->GetQualifiedName(&p,&length));const auto name=Utf8(p,length);Check(reader->GetValue(&p,&length));node.attributes.emplace_back(name,Utf8(p,length));}while(reader->MoveToNextAttribute()==S_OK);Check(reader->MoveToElement());}
            for(const auto& [key,value]:node.attributes)if(key=="xml:space")node.preserve_whitespace=value=="preserve";
            XmlNode* current=nullptr;if(stack.empty()){if(root)throw std::runtime_error("XML 存在多个根元素");root=std::move(node);current=&*root;}else{stack.back()->nodes.push_back(std::move(node));current=&stack.back()->nodes.back();}
            if(!empty)stack.push_back(current);
        }else if(type==XmlNodeType_EndElement){if(stack.empty())throw std::runtime_error("XML 元素未配对");stack.pop_back();}
        else if(type==XmlNodeType_Text||type==XmlNodeType_CDATA||type==XmlNodeType_Whitespace){
            const wchar_t* p=nullptr;UINT length=0;Check(reader->GetValue(&p,&length));const auto value=Utf8(p,length);
            if(type!=XmlNodeType_Whitespace||(!stack.empty()&&stack.back()->preserve_whitespace))for(auto* node:stack)node->text=node->text.value_or("")+value;
        }
    }Check(hr);if(!root)throw std::runtime_error("XML 缺少根元素");return std::move(*root);
}
std::string ReadXmlFileBytes(const std::filesystem::path& path){
    ComPtr<IStream> f;Check(SHCreateStreamOnFileEx(path.c_str(),STGM_READ|STGM_SHARE_DENY_WRITE,FILE_ATTRIBUTE_NORMAL,FALSE,nullptr,&f));STATSTG stat{};Check(f->Stat(&stat,STATFLAG_NONAME));
    if(stat.cbSize.QuadPart>INT_MAX)throw std::length_error("文件超出原 .NET 字节数组范围");std::string bytes(static_cast<std::size_t>(stat.cbSize.QuadPart),0);
    for(std::size_t offset=0;offset<bytes.size();){const auto count=static_cast<ULONG>(std::min<std::size_t>(bytes.size()-offset,1024*1024));ULONG got=0;Check(f->Read(bytes.data()+offset,count,&got));if(got!=count)throw std::runtime_error("读取文件时遇到截断");offset+=got;}return bytes;
}
void WriteXmlFile(const std::filesystem::path& path,const XmlNode& root,const std::string& password){auto bytes=SerializeXml(root);if(!password.empty())bytes=CryptXml(bytes,password,true);WriteXmlFileBytes(path,bytes);}
}
