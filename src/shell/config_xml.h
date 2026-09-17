#pragma once
#include "xml_document.h"
#include "web_bridge.h"
#include <set>
namespace wpe::shell {
XmlNode ParentListXml(int list,const Json& rows);
Json ParseParentList(int list,const XmlNode& root,std::set<std::string> existing,std::uint64_t& packetId,const Json& config);
XmlNode SystemConfigXml(const Json& config);
Json ParseSystemConfig(const XmlNode& node,const Json& current);
}
