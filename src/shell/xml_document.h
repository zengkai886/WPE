#pragma once
#include <string_view>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>
namespace wpe::shell {
struct XmlNode {
    std::string name;
    std::string namespace_uri;
    bool preserve_whitespace{};
    std::optional<std::string> text;
    std::vector<std::pair<std::string,std::string>> attributes;
    std::vector<XmlNode> nodes;
    explicit XmlNode(std::string tag):name(std::move(tag)){}
    XmlNode(std::string tag,std::string value):name(std::move(tag)),text(std::move(value)){}
    std::string_view LocalName()const{const auto colon=name.find(':');return std::string_view(name).substr(colon==name.npos?0:colon+1);}
    const XmlNode* Get(const std::string& tag)const{for(const auto& n:nodes)if(n.name==tag&&n.namespace_uri.empty())return &n;return nullptr;}
    std::string Value(const std::string& tag,std::string fallback={})const{auto n=Get(tag);return n?n->text.value_or(""):fallback;}
};
XmlNode ParseXml(std::string_view bytes);
std::string SerializeXml(const XmlNode& root);
std::string ReadXmlFileBytes(const std::filesystem::path& path);
void WriteXmlFileBytes(const std::filesystem::path& path,std::string_view bytes);
void WriteXmlFile(const std::filesystem::path& path,const XmlNode& root,const std::string& password={});
}
