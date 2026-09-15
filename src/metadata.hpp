#pragma once
#include <filesystem>
#include <fstream>
#include <map>
#include <string>
#include <stdexcept>
#include <cstdint>

namespace metadata {
struct Attributes { std::string label, id; };
using Records=std::map<std::uint32_t,Attributes>;
inline std::filesystem::path path(const std::filesystem::path& key){
 auto result=key;result+=".meta";return result;
}
inline void number(std::ostream& out,std::uint32_t n){
 for(int shift=24;shift>=0;shift-=8)out.put(static_cast<char>((n>>shift)&255));
}
inline std::uint32_t number(std::istream& in){
 std::uint32_t n=0;
 for(int i=0;i<4;i++){int c=in.get();if(c<0)throw std::runtime_error("Truncated metadata");n=(n<<8)|static_cast<unsigned>(c);}
 return n;
}
inline void bytes(std::ostream& out,const std::string& s){
 if(s.size()>65536)throw std::runtime_error("Metadata field too large");
 number(out,static_cast<std::uint32_t>(s.size()));out.write(s.data(),s.size());
}
inline std::string bytes(std::istream& in){
 auto n=number(in);if(n>65536)throw std::runtime_error("Metadata field too large");
 std::string s(n,'\0');in.read(s.data(),n);if(!in)throw std::runtime_error("Truncated metadata");return s;
}
inline Records read(const std::filesystem::path& key){
 auto file=path(key);
 if(!std::filesystem::exists(file))return {};
 if(std::filesystem::file_size(file)>1024*1024)throw std::runtime_error("Metadata too large");
 std::ifstream in(file,std::ios::binary);
 if(number(in)!=0x48534D31)throw std::runtime_error("Unknown metadata format");
 auto count=number(in);if(count>4)throw std::runtime_error("Too many metadata records");
 Records records;
 for(std::uint32_t i=0;i<count;i++){
  auto cls=number(in);if(cls<1||cls>4)throw std::runtime_error("Invalid metadata class");
  Attributes a;a.label=bytes(in);a.id=bytes(in);
  if(!records.emplace(cls,std::move(a)).second)throw std::runtime_error("Duplicate metadata class");
 }
 if(in.peek()!=std::char_traits<char>::eof())throw std::runtime_error("Trailing metadata bytes");
 return records;
}
// Create-only publication. The simulator currently supports one process per token.
inline void create(const std::filesystem::path& key,const Records& records){
 auto file=path(key);auto temp=file;temp+=".tmp";
 if(std::filesystem::exists(file)||std::filesystem::exists(temp))throw std::runtime_error("Metadata already exists");
 try{
  std::ofstream out(temp,std::ios::binary|std::ios::trunc);
  number(out,0x48534D31);number(out,static_cast<std::uint32_t>(records.size()));
  for(const auto& [cls,a]:records){number(out,cls);bytes(out,a.label);bytes(out,a.id);}
  out.close();if(!out)throw std::runtime_error("Metadata write failed");
  std::filesystem::rename(temp,file);
 }catch(...){std::error_code ec;std::filesystem::remove(temp,ec);throw;}
}
}
