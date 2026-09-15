#pragma once
// Platform adapter only. The OASIS headers in oasis/ are kept byte-for-byte.
#ifdef __cplusplus
#define CK_EXTERN extern "C"
#else
#define CK_EXTERN extern
#endif
#ifdef _WIN32
#define CK_CALL __cdecl
#ifdef HSM_SIM_BUILD
#define CK_VISIBILITY __declspec(dllexport)
#else
#define CK_VISIBILITY __declspec(dllimport)
#endif
#pragma pack(push, cryptoki, 1)
#else
#define CK_CALL
#define CK_VISIBILITY __attribute__((visibility("default")))
#endif
#define CK_EXPORT CK_EXTERN CK_VISIBILITY
#define CK_PTR *
#define CK_DECLARE_FUNCTION(result,name) CK_VISIBILITY result CK_CALL name
#define CK_DECLARE_FUNCTION_POINTER(result,name) result (CK_CALL *name)
#define CK_CALLBACK_FUNCTION(result,name) result (CK_CALL *name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#include "oasis/pkcs11.h"
#ifdef _WIN32
#pragma pack(pop, cryptoki)
#endif
