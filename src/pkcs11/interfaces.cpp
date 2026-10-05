#include "pkcs11.h"
#include <algorithm>
#include <cstring>
#include <iterator>

// Function tables are built from the unchanged OASIS declarations.
static CK_FUNCTION_LIST functions = []
{
    CK_FUNCTION_LIST table{};
    table.version = {2, 40};
#define CK_PKCS11_2_0_ONLY
#define CK_PKCS11_FUNCTION_INFO(name) table.name = name;
#include "oasis/pkcs11f.h"
#undef CK_PKCS11_FUNCTION_INFO
#undef CK_PKCS11_2_0_ONLY
    return table;
}();
static CK_FUNCTION_LIST_3_0 functions30 = []
{
    CK_FUNCTION_LIST_3_0 table{};
    table.version = {3, 0};
#define CK_PKCS11_3_0_ONLY
#define CK_PKCS11_FUNCTION_INFO(name) table.name = name;
#include "oasis/pkcs11f.h"
#undef CK_PKCS11_FUNCTION_INFO
#undef CK_PKCS11_3_0_ONLY
    return table;
}();
static CK_FUNCTION_LIST_3_2 functions32 = []
{
    CK_FUNCTION_LIST_3_2 table{};
    table.version = {3, 2};
#define CK_PKCS11_FUNCTION_INFO(name) table.name = name;
#include "oasis/pkcs11f.h"
#undef CK_PKCS11_FUNCTION_INFO
    return table;
}();
static CK_UTF8CHAR interfaceName[] = "PKCS 11";
static CK_INTERFACE interfaces[] = {{interfaceName, &functions32, 0},
    {interfaceName, &functions30, 0}, {interfaceName, &functions, 0}};
CK_EXPORT CK_RV CK_CALL C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR p)
{
    if (!p)
    {
        return CKR_ARGUMENTS_BAD;
    }
    *p = &functions;
    return CKR_OK;
}
CK_EXPORT CK_RV CK_CALL C_GetInterfaceList(CK_INTERFACE_PTR out, CK_ULONG_PTR count)
{
    if (!count)
    {
        return CKR_ARGUMENTS_BAD;
    }
    constexpr CK_ULONG size = sizeof interfaces / sizeof interfaces[0];
    if (!out)
    {
        *count = size;
        return CKR_OK;
    }
    if (*count < size)
    {
        *count = size;
        return CKR_BUFFER_TOO_SMALL;
    }
    std::copy(std::begin(interfaces), std::end(interfaces), out);
    *count = size;
    return CKR_OK;
}
CK_EXPORT CK_RV CK_CALL C_GetInterface(
    CK_UTF8CHAR_PTR name, CK_VERSION_PTR version, CK_INTERFACE_PTR_PTR out, CK_FLAGS flags)
{
    if (!out)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (flags || (name && std::strcmp(reinterpret_cast<const char*>(name), "PKCS 11") != 0))
    {
        return CKR_ARGUMENTS_BAD;
    }
    for (auto& item : interfaces)
    {
        const auto* v = static_cast<const CK_VERSION*>(item.pFunctionList);
        if (!version || (version->major == v->major && version->minor == v->minor))
        {
            *out = &item;
            return CKR_OK;
        }
    }
    return CKR_ARGUMENTS_BAD;
}
