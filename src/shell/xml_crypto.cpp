#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <array>
#include <stdexcept>
#include "xml_crypto.h"
namespace wpe::shell {
namespace {
void Check(NTSTATUS s){if(s<0)throw std::runtime_error("文件加解密失败：密码错误、文件损坏或系统加密接口不可用");}
struct Algorithm {BCRYPT_ALG_HANDLE h{};explicit Algorithm(LPCWSTR id){Check(BCryptOpenAlgorithmProvider(&h,id,nullptr,0));}~Algorithm(){if(h)BCryptCloseAlgorithmProvider(h,0);}Algorithm(const Algorithm&)=delete;};
struct Hash {BCRYPT_HASH_HANDLE h{};~Hash(){if(h)BCryptDestroyHash(h);}};
struct Key {BCRYPT_KEY_HANDLE h{};~Key(){if(h)BCryptDestroyKey(h);}};
struct Secret {std::array<UCHAR,16> key{},iv{},digest{};~Secret(){SecureZeroMemory(this,sizeof(*this));}};
}
std::string CryptXml(std::string_view bytes,const std::string& password,bool encrypt){
    if(password.empty())throw std::invalid_argument("加密文件需要非空密码");
    if(password.size()>INT_MAX||bytes.size()>INT_MAX)throw std::length_error("文件或密码超出原 .NET 字节数组范围");
    const int n=MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,password.data(),static_cast<int>(password.size()),nullptr,0);
    if(!n)throw std::invalid_argument("密码不是有效 UTF-8");std::wstring wide(static_cast<std::size_t>(n),0);
    MultiByteToWideChar(CP_UTF8,MB_ERR_INVALID_CHARS,password.data(),static_cast<int>(password.size()),wide.data(),n);
    const int count=WideCharToMultiByte(CP_ACP,0,wide.data(),n,nullptr,0,nullptr,nullptr);
    if(!count)throw std::runtime_error("无法按系统代码页转换密码");std::string ansi(static_cast<std::size_t>(count),0);
    WideCharToMultiByte(CP_ACP,0,wide.data(),n,ansi.data(),count,nullptr,nullptr);SecureZeroMemory(wide.data(),wide.size()*sizeof(wchar_t));
    Secret secret;Algorithm md5(BCRYPT_MD5_ALGORITHM);Hash hash;Check(BCryptCreateHash(md5.h,&hash.h,nullptr,0,nullptr,0,0));
    const auto hashed=BCryptHashData(hash.h,reinterpret_cast<PUCHAR>(ansi.data()),static_cast<ULONG>(ansi.size()),0);SecureZeroMemory(ansi.data(),ansi.size());Check(hashed);
    Check(BCryptFinishHash(hash.h,secret.digest.data(),16,0));const char hex[]="0123456789ABCDEF";
    for(std::size_t i=0;i<8;++i){secret.key[2*i]=hex[secret.digest[i+4]>>4];secret.key[2*i+1]=hex[secret.digest[i+4]&15];}secret.iv=secret.key;
    Algorithm aes(BCRYPT_AES_ALGORITHM);Check(BCryptSetProperty(aes.h,BCRYPT_CHAINING_MODE,reinterpret_cast<PUCHAR>(const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),sizeof(BCRYPT_CHAIN_MODE_CBC),0));
    Key key;Check(BCryptGenerateSymmetricKey(aes.h,&key.h,nullptr,0,secret.key.data(),16,0));
    const auto transform=encrypt?BCryptEncrypt:BCryptDecrypt;ULONG length=0;
    auto input=reinterpret_cast<PUCHAR>(const_cast<char*>(bytes.data()));
    Check(transform(key.h,input,static_cast<ULONG>(bytes.size()),nullptr,secret.iv.data(),16,nullptr,0,&length,BCRYPT_BLOCK_PADDING));
    secret.iv=secret.key;std::string output(length,0);
    const auto status=transform(key.h,input,static_cast<ULONG>(bytes.size()),nullptr,secret.iv.data(),16,reinterpret_cast<PUCHAR>(output.data()),length,&length,BCRYPT_BLOCK_PADDING);
    if(status<0){SecureZeroMemory(output.data(),output.size());Check(status);}output.resize(length);return output;
}
}
