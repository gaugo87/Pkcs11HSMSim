#include "pkcs11/token.hpp"
#include "core/runtime.hpp"
#include "core/utilities.hpp"
#include "crypto/mechanisms.hpp"
#include "storage/key_store.hpp"
#include "storage/slots.hpp"
#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace hsm
{

CK_RV Initialize(CK_VOID_PTR arguments)
{
    if (runtime.initialized)
    {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    if (arguments && ((CK_C_INITIALIZE_ARGS_PTR)arguments)->pReserved)
    {
        return CKR_ARGUMENTS_BAD;
    }
    runtime.storageRoot = fs::u8path(environmentValue("HSM_SIM_DATA_DIR", "data"));
    try
    {
        discoverSlots();
        loadTokenObjects();
    }
    catch (...)
    {
        runtime.objects.clear();
        runtime.slots.clear();
        return CKR_DEVICE_ERROR;
    }
    runtime.initialized = true;
    return CKR_OK;
}

CK_RV Finalize(CK_VOID_PTR reserved)
{
    if (!runtime.initialized)
    {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    if (reserved)
    {
        return CKR_ARGUMENTS_BAD;
    }
    runtime.slots.clear();
    runtime.sessions.clear();
    runtime.objects.clear();
    runtime.initialized = false;
    return CKR_OK;
}

CK_RV GetInfo(CK_INFO_PTR info)
{
    if (!info)
    {
        return CKR_ARGUMENTS_BAD;
    }
    std::memset(info, 0, sizeof(*info));
    info->cryptokiVersion = {3, 2};
    writePaddedString(info->manufacturerID, 32, "OpenAI");
    writePaddedString(info->libraryDescription, 32, "HSM Simulator");
    info->libraryVersion = {0, 7};
    return initializationStatus();
}

CK_RV GetSlotList(CK_BBOOL, CK_SLOT_ID_PTR slots, CK_ULONG_PTR count)
{
    if (!count)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (!slots)
    {
        *count = static_cast<CK_ULONG>(runtime.slots.size());
        return CKR_OK;
    }
    if (*count < runtime.slots.size())
    {
        *count = static_cast<CK_ULONG>(runtime.slots.size());
        return CKR_BUFFER_TOO_SMALL;
    }
    size_t index = 0;
    for (const auto& [id, slot] : runtime.slots)
    {
        slots[index++] = id;
    }
    *count = static_cast<CK_ULONG>(runtime.slots.size());
    return initializationStatus();
}

CK_RV GetSlotInfo(CK_SLOT_ID slotId, CK_SLOT_INFO_PTR info)
{
    if (!findSlot(slotId))
    {
        return CKR_SLOT_ID_INVALID;
    }
    if (!info)
    {
        return CKR_ARGUMENTS_BAD;
    }
    std::memset(info, 0, sizeof(*info));
    writePaddedString(info->slotDescription, 64, findSlot(slotId)->label.c_str());
    writePaddedString(info->manufacturerID, 32, "OpenAI");
    info->flags = CKF_TOKEN_PRESENT;
    info->hardwareVersion = {1, 0};
    info->firmwareVersion = {0, 1};
    return initializationStatus();
}

CK_RV GetTokenInfo(CK_SLOT_ID slotId, CK_TOKEN_INFO_PTR info)
{
    if (!findSlot(slotId))
    {
        return CKR_SLOT_ID_INVALID;
    }
    if (!info)
    {
        return CKR_ARGUMENTS_BAD;
    }
    std::memset(info, 0, sizeof(*info));
    const auto& slot = *findSlot(slotId);
    writePaddedString(info->label, 32, slot.label.c_str());
    writePaddedString(info->manufacturerID, 32, "OpenAI");
    writePaddedString(info->model, 16, "FILE-HSM");
    std::ostringstream serial;
    serial << std::hex << std::setw(16) << std::setfill('0') << slotId;
    writePaddedString(info->serialNumber, 16, serial.str().c_str());
    info->flags = CKF_RNG | CKF_TOKEN_INITIALIZED;
    if (slot.requiresLogin())
    {
        info->flags |= CKF_LOGIN_REQUIRED;
    }
    if (slot.userPin || !slot.requiresLogin())
    {
        info->flags |= CKF_USER_PIN_INITIALIZED;
    }
    info->ulMaxSessionCount = info->ulMaxRwSessionCount = CK_UNAVAILABLE_INFORMATION;
    for (const auto& [handle, session] : runtime.sessions)
    {
        if (session.slotId == slotId)
        {
            ++info->ulSessionCount;
            if (session.flags & CKF_RW_SESSION)
            {
                ++info->ulRwSessionCount;
            }
        }
    }
    info->ulMinPinLen = 0;
    info->ulMaxPinLen = maximumPinLength;
    info->hardwareVersion = {1, 0};
    info->firmwareVersion = {0, 1};
    return initializationStatus();
}

CK_RV GetMechanismList(CK_SLOT_ID slotId, CK_MECHANISM_TYPE_PTR mechanisms, CK_ULONG_PTR count)
{
    if (!findSlot(slotId))
    {
        return CKR_SLOT_ID_INVALID;
    }
    if (!count)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (!mechanisms)
    {
        *count = supportedMechanisms.size();
        return CKR_OK;
    }
    if (*count < supportedMechanisms.size())
    {
        *count = supportedMechanisms.size();
        return CKR_BUFFER_TOO_SMALL;
    }
    std::copy(supportedMechanisms.begin(), supportedMechanisms.end(), mechanisms);
    *count = supportedMechanisms.size();
    return CKR_OK;
}

CK_RV GetMechanismInfo(CK_SLOT_ID slotId, CK_MECHANISM_TYPE mechanism, CK_MECHANISM_INFO_PTR info)
{
    if (!findSlot(slotId))
    {
        return CKR_SLOT_ID_INVALID;
    }
    if (!info)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (std::find(supportedMechanisms.begin(), supportedMechanisms.end(), mechanism) ==
        supportedMechanisms.end())
    {
        return CKR_MECHANISM_INVALID;
    }
    info->ulMinKeySize = 0;
    info->ulMaxKeySize = 0;
    info->flags = 0;
    if (mechanism == CKM_AES_ECB_ENCRYPT_DATA)
    {
        info->ulMinKeySize = 16;
        info->ulMaxKeySize = 32;
        info->flags = CKF_DERIVE;
    }
    else if (mechanism == CKM_AES_KEY_GEN)
    {
        info->flags = CKF_GENERATE;
    }
    else if (mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN || mechanism == CKM_EC_KEY_PAIR_GEN ||
        mechanism == CKM_ML_DSA_KEY_PAIR_GEN || mechanism == CKM_SLH_DSA_KEY_PAIR_GEN)
    {
        info->flags = CKF_GENERATE_KEY_PAIR;
    }
    else if (mechanism == CKM_AES_KEY_WRAP || mechanism == CKM_AES_KEY_WRAP_PAD)
    {
        info->flags = CKF_WRAP | CKF_UNWRAP;
    }
    else
    {
        info->flags = CKF_SIGN | CKF_VERIFY;
    }
    return CKR_OK;
}

} // namespace hsm
