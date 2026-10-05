#include "objects/objects.hpp"
#include "core/runtime.hpp"
#include "objects/attributes.hpp"
#include "objects/policy.hpp"
#include "storage/metadata.hpp"
#include <algorithm>
#include <cstring>

namespace hsm
{

CK_RV DestroyObject(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE objectHandle)
{
    if (!findSession(sessionHandle))
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    auto* object = findObject(objectHandle);
    if (!object)
    {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    if (!policyValue(*object, CKA_DESTROYABLE))
    {
        return CKR_ACTION_PROHIBITED;
    }
    if (!object->ownerSession && !(findSession(sessionHandle)->flags & CKF_RW_SESSION))
    {
        return CKR_SESSION_READ_ONLY;
    }
    for (const auto& [id, other] : runtime.objects)
    {
        if (!object->ownerSession && other.path == object->path &&
            !policyValue(other, CKA_DESTROYABLE))
        {
            return CKR_ACTION_PROHIBITED;
        }
    }
    if (object->ownerSession)
    {
        runtime.objects.erase(objectHandle);
        return CKR_OK;
    }
    auto path = object->path;
    std::error_code ec;
    fs::remove(path, ec);
    if (ec)
    {
        return CKR_DEVICE_ERROR;
    }
    fs::remove(metadata::path(path), ec);
    for (auto i = runtime.objects.begin(); i != runtime.objects.end();)
    {
        if (i->second.path == path)
        {
            i = runtime.objects.erase(i);
        }
        else
        {
            ++i;
        }
    }
    return ec ? CKR_DEVICE_ERROR : CKR_OK;
}

CK_RV FindObjectsInit(
    CK_SESSION_HANDLE sessionHandle, CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount)
{
    auto* session = findSession(sessionHandle);
    if (!session)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!attributes && attributeCount)
    {
        return CKR_ARGUMENTS_BAD;
    }
    for (CK_ULONG i = 0; i < attributeCount; i++)
    {
        if (!attributes[i].pValue && attributes[i].ulValueLen)
        {
            return CKR_ARGUMENTS_BAD;
        }
    }
    if (session->searchActive)
    {
        return CKR_OPERATION_ACTIVE;
    }
    session->matches.clear();
    for (auto& [id, object] : runtime.objects)
    {
        bool matches = true;
        for (CK_ULONG i = 0; i < attributeCount && matches; i++)
        {
            CK_ATTRIBUTE probe{attributes[i].type, nullptr, 0};
            if (readAttributes(&object, &probe, 1) != CKR_OK ||
                probe.ulValueLen != attributes[i].ulValueLen)
            {
                matches = false;
                break;
            }
            std::vector<unsigned char> value(probe.ulValueLen);
            probe.pValue = value.data();
            if (readAttributes(&object, &probe, 1) != CKR_OK)
            {
                matches = false;
                break;
            }
            if (probe.ulValueLen &&
                std::memcmp(value.data(), attributes[i].pValue, probe.ulValueLen) != 0)
            {
                matches = false;
            }
        }
        if (matches)
        {
            session->matches.push_back(id);
        }
    }
    std::sort(session->matches.begin(), session->matches.end());
    session->searchOffset = 0;
    session->searchActive = true;
    return CKR_OK;
}

CK_RV FindObjects(CK_SESSION_HANDLE sessionHandle, CK_OBJECT_HANDLE_PTR objects, CK_ULONG capacity,
    CK_ULONG_PTR count)
{
    auto* session = findSession(sessionHandle);
    if (!session)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!session->searchActive)
    {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (!count || (!objects && capacity))
    {
        return CKR_ARGUMENTS_BAD;
    }
    *count = 0;
    while (*count < capacity && session->searchOffset < session->matches.size())
    {
        objects[(*count)++] = session->matches[session->searchOffset++];
    }
    return CKR_OK;
}

CK_RV FindObjectsFinal(CK_SESSION_HANDLE sessionHandle)
{
    auto* session = findSession(sessionHandle);
    if (!session)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!session->searchActive)
    {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    session->searchActive = false;
    session->matches.clear();
    return CKR_OK;
}

} // namespace hsm
