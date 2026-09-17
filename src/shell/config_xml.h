#pragma once
#include "xml_document.h"
#include "web_bridge.h"
#include <set>
namespace wpe::shell {
XmlNode ParentListXml(int list,const Json& rows);
Json ParseParentList(int list,const XmlNode& root,std::set<std::string> existing,std::uint64_t& packetId,const Json& config);
XmlNode SystemConfigXml(const Json& config);
Json ParseSystemConfig(const XmlNode& node,const Json& current);
XmlNode InjectModeXml(const Json& config);
Json ParseInjectMode(const XmlNode& node,const Json& current);
XmlNode ProxyModeXml(const Json& config);
Json ParseProxyMode(const XmlNode& node,const Json& current);
XmlNode IpRuleListXml(bool black,const Json& rows);
Json ParseIpRuleList(bool black,const XmlNode& root,const Json& current);
XmlNode AccountListXml(const Json& rows);
Json ParseAccountList(const XmlNode& root,const Json& current);
XmlNode AutoStoresXml(const Json& rows);
Json ParseAutoStores(const XmlNode& root,const Json& current,bool append);
XmlNode MapListXml(bool remote,const Json& rows);
Json ParseMapList(bool remote,const XmlNode& root,const Json& current,bool append);
XmlNode ServerListXml(const Json& rows);
Json ParseServerList(const XmlNode& root);
XmlNode NoticeListXml(const Json& rows);
Json ParseNoticeList(const XmlNode& root);
}
