#pragma once
#include <string>
#include <string_view>
namespace wpe::shell {
// Compatibility with the supplied .NET Framework code, NOT a new file format:
// ACP(password) -> MD5 bytes 4..11 -> uppercase ASCII hex -> AES-128 CBC key=IV.
std::string CryptXml(std::string_view bytes,const std::string& password,bool encrypt);
}
