#pragma once
#include <cstdint>
#include <filesystem>
#include <map>
#include <string>

namespace hsm::metadata
{
struct Attributes
{
    std::string label;
    std::string id;
    std::map<std::uint32_t, bool> policy;
};
using Records = std::map<std::uint32_t, Attributes>;
std::filesystem::path path(const std::filesystem::path& key);
Records read(const std::filesystem::path& key);
// Create-only publication, or atomic replacement for attribute updates.
// The simulator supports one process per token directory.
void create(const std::filesystem::path& key, const Records& records, bool replace = false);
} // namespace hsm::metadata
