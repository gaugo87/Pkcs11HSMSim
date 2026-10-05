#pragma once
#include "core/runtime.hpp"
#include <new>

namespace hsm
{
// The only lock/exception boundary for stateful exported calls. Internal services
// run with this lock held; they must never call an exported C_* entry point.
template <class Function, class... Arguments>
CK_RV invoke(bool needsInitialization, Function function, Arguments... arguments) noexcept
{
    try
    {
        std::scoped_lock lock(runtime.mutex);
        if (needsInitialization && !runtime.initialized)
        {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        return function(arguments...);
    }
    catch (const std::bad_alloc&)
    {
        return CKR_HOST_MEMORY;
    }
    catch (const std::filesystem::filesystem_error&)
    {
        return CKR_DEVICE_ERROR;
    }
    catch (...)
    {
        return CKR_GENERAL_ERROR;
    }
}

inline CK_RV unsupportedOperation() noexcept
{
    return invoke(true,
        []() -> CK_RV
        {
            return CKR_FUNCTION_NOT_SUPPORTED;
        });
}
} // namespace hsm
