#include "core/runtime.hpp"

namespace hsm
{

RuntimeState runtime;

CK_RV initializationStatus()
{
    return runtime.initialized ? CKR_OK : CKR_CRYPTOKI_NOT_INITIALIZED;
}

Session* findSession(CK_SESSION_HANDLE handle)
{
    auto entry = runtime.sessions.find(handle);
    return entry == runtime.sessions.end() ? nullptr : &entry->second;
}

Object* findObject(CK_OBJECT_HANDLE handle)
{
    auto entry = runtime.objects.find(handle);
    return entry == runtime.objects.end() ? nullptr : &entry->second;
}

} // namespace hsm
