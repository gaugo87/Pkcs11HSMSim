#include "storage/metadata.hpp"
#include <fstream>
#include <stdexcept>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace hsm::metadata
{
// HSM1 stores label/ID; HSM2 additionally stores per-class boolean policies.
static constexpr std::uint32_t legacyFormat = 0x48534D31;
static constexpr std::uint32_t policyFormat = 0x48534D32;
std::filesystem::path path(const std::filesystem::path& key)
{
    auto result = key;
    result += ".meta";
    return result;
}
static void writeUint32(std::ostream& out, std::uint32_t n)
{
    for (int shift = 24; shift >= 0; shift -= 8)
    {
        out.put(static_cast<char>((n >> shift) & 255));
    }
}
static std::uint32_t readUint32(std::istream& in)
{
    std::uint32_t n = 0;
    for (int i = 0; i < 4; i++)
    {
        int c = in.get();
        if (c < 0)
        {
            throw std::runtime_error("Truncated metadata");
        }
        n = (n << 8) | static_cast<unsigned>(c);
    }
    return n;
}
static void writeString(std::ostream& out, const std::string& s)
{
    if (s.size() > 65536)
    {
        throw std::runtime_error("Metadata field too large");
    }
    writeUint32(out, static_cast<std::uint32_t>(s.size()));
    out.write(s.data(), s.size());
}
static std::string readString(std::istream& in)
{
    auto n = readUint32(in);
    if (n > 65536)
    {
        throw std::runtime_error("Metadata field too large");
    }
    std::string s(n, '\0');
    in.read(s.data(), n);
    if (!in)
    {
        throw std::runtime_error("Truncated metadata");
    }
    return s;
}
Records read(const std::filesystem::path& key)
{
    auto file = path(key);
    if (!std::filesystem::exists(file))
    {
        return {};
    }
    if (std::filesystem::file_size(file) > 1024 * 1024)
    {
        throw std::runtime_error("Metadata too large");
    }
    std::ifstream in(file, std::ios::binary);
    auto version = readUint32(in);
    if (version != legacyFormat && version != policyFormat)
    {
        throw std::runtime_error("Unknown metadata format");
    }
    auto count = readUint32(in);
    if (count > 4)
    {
        throw std::runtime_error("Too many metadata records");
    }
    Records records;
    for (std::uint32_t i = 0; i < count; i++)
    {
        auto cls = readUint32(in);
        if (cls < 1 || cls > 4)
        {
            throw std::runtime_error("Invalid metadata class");
        }
        Attributes a;
        a.label = readString(in);
        a.id = readString(in);
        if (version == policyFormat)
        {
            auto n = readUint32(in);
            if (n > 32)
            {
                throw std::runtime_error("Too many policy attributes");
            }
            for (std::uint32_t j = 0; j < n; ++j)
            {
                auto type = readUint32(in), value = readUint32(in);
                if (value > 1 || !a.policy.emplace(type, value != 0).second)
                {
                    throw std::runtime_error("Invalid policy metadata");
                }
            }
        }
        if (!records.emplace(cls, std::move(a)).second)
        {
            throw std::runtime_error("Duplicate metadata class");
        }
    }
    if (in.peek() != std::char_traits<char>::eof())
    {
        throw std::runtime_error("Trailing metadata bytes");
    }
    return records;
}
// Create-only publication, or atomic replacement for attribute updates.
// The simulator currently supports one process per token.
void create(const std::filesystem::path& key, const Records& records, bool replace)
{
    auto file = path(key);
    auto temp = file;
    temp += ".tmp";
    if ((!replace && std::filesystem::exists(file)) || std::filesystem::exists(temp))
    {
        throw std::runtime_error("Metadata already exists");
    }
    try
    {
        std::ofstream out(temp, std::ios::binary | std::ios::trunc);
        writeUint32(out, policyFormat);
        writeUint32(out, static_cast<std::uint32_t>(records.size()));
        for (const auto& [cls, a] : records)
        {
            writeUint32(out, cls);
            writeString(out, a.label);
            writeString(out, a.id);
            writeUint32(out, static_cast<std::uint32_t>(a.policy.size()));
            for (auto [type, value] : a.policy)
            {
                writeUint32(out, type);
                writeUint32(out, value ? 1 : 0);
            }
        }
        out.close();
        if (!out)
        {
            throw std::runtime_error("Metadata write failed");
        }
#ifdef _WIN32
        if (!MoveFileExW(temp.c_str(), file.c_str(), replace ? MOVEFILE_REPLACE_EXISTING : 0))
        {
            throw std::runtime_error("Metadata rename failed");
        }
#else
        std::filesystem::rename(temp, file);
#endif
    }
    catch (...)
    {
        std::error_code ec;
        std::filesystem::remove(temp, ec);
        throw;
    }
}

} // namespace hsm::metadata
