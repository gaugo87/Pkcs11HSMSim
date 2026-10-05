#include "core/utilities.hpp"
#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>

namespace hsm
{

void writePaddedString(CK_CHAR* destination, size_t capacity, const char* value)
{
    std::memset(destination, ' ', capacity);
    std::memcpy(destination, value, std::min(capacity, std::strlen(value)));
}

std::string environmentValue(const char* name, const char* fallback)
{
    const char* value = std::getenv(name);
    return value && *value ? value : fallback;
}

std::string encodeHex(const unsigned char* bytes, size_t length)
{
    static constexpr char digits[] = "0123456789ABCDEF";
    std::string encoded;
    encoded.reserve(length * 2);
    for (size_t i = 0; i < length; i++)
    {
        encoded.push_back(digits[bytes[i] >> 4]);
        encoded.push_back(digits[bytes[i] & 15]);
    }
    return encoded;
}

std::vector<unsigned char> decodeHex(std::string encoded)
{
    encoded.erase(std::remove_if(encoded.begin(), encoded.end(),
                      [](unsigned char c)
                      {
                          return std::isspace(c);
                      }),
        encoded.end());
    if (encoded.size() % 2)
    {
        return {};
    }
    std::vector<unsigned char> bytes(encoded.size() / 2);
    for (size_t i = 0; i < bytes.size(); i++)
    {
        try
        {
            bytes[i] = (unsigned char)std::stoul(encoded.substr(i * 2, 2), nullptr, 16);
        }
        catch (...)
        {
            return {};
        }
    }
    return bytes;
}

std::string safeFilename(std::string label)
{
    for (auto& c : label)
    {
        if (!std::isalnum((unsigned char)c) && c != '-' && c != '_')
        {
            c = '_';
        }
    }
    return label.empty() ? "key" : label;
}

} // namespace hsm
