#include "storage/slots.hpp"
#include "core/utilities.hpp"
#include <algorithm>
#include <fstream>
#include <limits>
#include <openssl/crypto.h>
#include <stdexcept>
#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace hsm
{

static std::optional<std::string> readPassword(const fs::path& path)
{
    if (!fs::exists(path))
    {
        return std::nullopt;
    }
    std::ifstream input(path, std::ios::binary);
    if (!input || !fs::is_regular_file(path))
    {
        throw std::runtime_error("Cannot read slot password file");
    }
    // Bound the read; allow a UTF-8 BOM and one trailing CRLF.
    char buffer[maximumPinLength + 6];
    input.read(buffer, sizeof(buffer));
    if (input.bad() || input.gcount() == sizeof(buffer))
    {
        throw std::runtime_error("Invalid slot password file");
    }
    std::string value(buffer, static_cast<size_t>(input.gcount()));
    if (value.starts_with("\xEF\xBB\xBF"))
    {
        value.erase(0, 3);
    }
    if (value.ends_with('\n'))
    {
        value.pop_back();
        if (value.ends_with('\r'))
        {
            value.pop_back();
        }
    }
    if (validatePin(reinterpret_cast<CK_CHAR_PTR>(value.data()), value.size()) != CKR_OK)
    {
        throw std::runtime_error("Invalid slot password file");
    }
    return value;
}

static void loadPasswords(Slot& slot)
{
    slot.userPin = readPassword(slot.directory / "pin.txt");
    const auto fallback = environmentValue("HSM_SIM_PIN", "");
    if (!slot.userPin && !fallback.empty())
    {
        if (fallback.size() > maximumPinLength ||
            fallback.find_first_of("\r\n") != std::string::npos)
        {
            throw std::runtime_error("Invalid HSM_SIM_PIN");
        }
        slot.userPin = fallback;
    }
    slot.soPin = readPassword(slot.directory / "so-pin.txt");
    slot.p12Password = readPassword(slot.directory / "p12-password.txt")
                           .value_or(environmentValue("HSM_SIM_P12_PASSWORD", ""));
}

static std::optional<CK_SLOT_ID> parseSlotId(const std::string& name)
{
    const auto separator = name.find('_');
    if (separator == std::string::npos || separator == 0 ||
        !std::all_of(name.begin(), name.begin() + separator,
            [](char c)
            {
                return c >= '0' && c <= '9';
            }))
    {
        return std::nullopt;
    }
    if (separator + 1 == name.size())
    {
        throw std::runtime_error("Empty slot label");
    }
    CK_SLOT_ID id = 0;
    for (size_t i = 0; i < separator; ++i)
    {
        const auto digit = static_cast<CK_SLOT_ID>(name[i] - '0');
        if (id > (std::numeric_limits<CK_SLOT_ID>::max() - digit) / 10)
        {
            throw std::runtime_error("Slot ID out of range");
        }
        id = id * 10 + digit;
    }
    return id;
}

void discoverSlots()
{
    fs::create_directories(runtime.storageRoot);
    std::map<CK_SLOT_ID, Slot> slots;
    for (const auto& entry : fs::directory_iterator(runtime.storageRoot))
    {
        if (!entry.is_directory())
        {
            continue;
        }
        const auto encodedName = entry.path().filename().u8string();
        const std::string name(encodedName.begin(), encodedName.end());
        const auto id = parseSlotId(name);
        if (!id)
        {
            continue;
        }
        Slot slot;
        slot.id = *id;
        slot.label = name.substr(name.find('_') + 1);
        slot.directory = entry.path();
        loadPasswords(slot);
        if (!slots.emplace(*id, std::move(slot)).second)
        {
            throw std::runtime_error("Duplicate slot ID");
        }
    }
    if (slots.empty())
    {
        Slot slot;
        slot.id = 1;
        slot.label = "HSM Simulator";
        slot.directory = runtime.storageRoot;
        slot.legacyLayout = true;
        loadPasswords(slot);
        slots.emplace(slot.id, std::move(slot));
    }
    else if (fs::exists(runtime.storageRoot / "asymmetric") ||
        fs::exists(runtime.storageRoot / "symmetric"))
    {
        throw std::runtime_error("Mixed legacy and multi-slot layouts");
    }
    runtime.slots = std::move(slots);
}

CK_RV validatePin(CK_CHAR_PTR pin, CK_ULONG length)
{
    if (!pin && length)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (length > maximumPinLength)
    {
        return CKR_PIN_LEN_RANGE;
    }
    for (CK_ULONG i = 0; i < length; ++i)
    {
        if (pin[i] == 0 || pin[i] == '\r' || pin[i] == '\n')
        {
            return CKR_PIN_INVALID;
        }
    }
    return CKR_OK;
}

CK_RV checkPin(const std::optional<std::string>& expected, CK_CHAR_PTR pin, CK_ULONG length)
{
    if (!pin && length)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (!expected)
    {
        return CKR_USER_PIN_NOT_INITIALIZED;
    }
    if (length != expected->size() || (length && CRYPTO_memcmp(pin, expected->data(), length)))
    {
        return CKR_PIN_INCORRECT;
    }
    return CKR_OK;
}

CK_RV storePin(Slot& slot, CK_USER_TYPE userType, CK_CHAR_PTR pin, CK_ULONG length)
{
    auto result = validatePin(pin, length);
    if (result != CKR_OK)
    {
        return result;
    }
    std::string value;
    if (length)
    {
        value.assign(reinterpret_cast<const char*>(pin), length);
    }
    auto path = slot.directory / (userType == CKU_SO ? "so-pin.txt" : "pin.txt");
    auto temporary = path;
    temporary += ".tmp";
    // Never overwrite a stale temporary file belonging to another writer.
    if (fs::exists(temporary))
    {
        return CKR_DEVICE_ERROR;
    }
    try
    {
        std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
        output.write(value.data(), static_cast<std::streamsize>(value.size()));
        output.close();
        if (!output)
        {
            throw std::runtime_error("Cannot write slot PIN");
        }
#ifdef _WIN32
        if (!MoveFileExW(temporary.c_str(), path.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        {
            throw std::runtime_error("Cannot replace slot PIN");
        }
#else
        fs::rename(temporary, path);
#endif
    }
    catch (...)
    {
        std::error_code error;
        fs::remove(temporary, error);
        return CKR_DEVICE_ERROR;
    }
    (userType == CKU_SO ? slot.soPin : slot.userPin) = std::move(value);
    return CKR_OK;
}

} // namespace hsm
