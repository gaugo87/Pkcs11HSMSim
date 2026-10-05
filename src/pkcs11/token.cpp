#include "pkcs11/token.hpp"
#include "core/runtime.hpp"
#include "core/utilities.hpp"
#include "crypto/mechanisms.hpp"
#include "storage/key_store.hpp"
#include <algorithm>
#include <cstring>

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
        loadTokenObjects();
    }
    catch (...)
    {
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
    info->libraryVersion = {0, 6};
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
        *count = 1;
        return CKR_OK;
    }
    if (*count < 1)
    {
        *count = 1;
        return CKR_BUFFER_TOO_SMALL;
    }
    slots[0] = virtualSlotId;
    *count = 1;
    return initializationStatus();
}

CK_RV GetSlotInfo(CK_SLOT_ID slotId, CK_SLOT_INFO_PTR info)
{
    if (slotId != virtualSlotId)
    {
        return CKR_SLOT_ID_INVALID;
    }
    if (!info)
    {
        return CKR_ARGUMENTS_BAD;
    }
    std::memset(info, 0, sizeof(*info));
    writePaddedString(info->slotDescription, 64, "File-backed virtual HSM slot");
    writePaddedString(info->manufacturerID, 32, "OpenAI");
    info->flags = CKF_TOKEN_PRESENT;
    info->hardwareVersion = {1, 0};
    info->firmwareVersion = {0, 1};
    return initializationStatus();
}

CK_RV GetTokenInfo(CK_SLOT_ID slotId, CK_TOKEN_INFO_PTR info)
{
    if (slotId != virtualSlotId)
    {
        return CKR_SLOT_ID_INVALID;
    }
    if (!info)
    {
        return CKR_ARGUMENTS_BAD;
    }
    std::memset(info, 0, sizeof(*info));
    writePaddedString(info->label, 32, "HSM Simulator");
    writePaddedString(info->manufacturerID, 32, "OpenAI");
    writePaddedString(info->model, 16, "FILE-HSM");
    writePaddedString(info->serialNumber, 16, "0000000000000001");
    info->flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED;
    info->ulMaxSessionCount = info->ulMaxRwSessionCount = CK_UNAVAILABLE_INFORMATION;
    info->ulSessionCount = info->ulRwSessionCount = (CK_ULONG)runtime.sessions.size();
    info->ulMinPinLen = 0;
    info->ulMaxPinLen = 256;
    info->hardwareVersion = {1, 0};
    info->firmwareVersion = {0, 1};
    return initializationStatus();
}

CK_RV GetMechanismList(CK_SLOT_ID slotId, CK_MECHANISM_TYPE_PTR mechanisms, CK_ULONG_PTR count)
{
    if (slotId != virtualSlotId)
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
    if (slotId != virtualSlotId)
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
