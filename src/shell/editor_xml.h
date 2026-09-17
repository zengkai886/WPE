#pragma once
#include "web_bridge.h"
#include <filesystem>
namespace wpe::shell {
// Returns database-shaped children, without GUID or runtime IDs. File I/O is worker-only.
Json ReadEditorXml(const std::filesystem::path& path,bool sendCollection);
}
