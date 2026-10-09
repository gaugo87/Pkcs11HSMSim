#include "crypto/key_generation.hpp"
#include "core/openssl.hpp"
#include "core/runtime.hpp"
#include "core/utilities.hpp"
#include "crypto/mechanisms.hpp"
#include "objects/policy.hpp"
#include "objects/template.hpp"
#include "storage/key_store.hpp"
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>

namespace hsm
{

CK_RV GenerateKey(CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_PTR mechanism,
    CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount, CK_OBJECT_HANDLE_PTR keyHandle)
{
    if (!findSession(sessionHandle))
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!mechanism || !keyHandle)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (mechanism->mechanism != CKM_AES_KEY_GEN)
    {
        return CKR_MECHANISM_INVALID;
    }
    auto result = validateCreationTemplate(attributes, attributeCount);
    if (result)
    {
        return result;
    }
    CK_ULONG keyLength = templateUnsigned(attributes, attributeCount, CKA_VALUE_LEN).value_or(32);
    if (keyLength != 16 && keyLength != 24 && keyLength != 32)
    {
        return CKR_KEY_SIZE_RANGE;
    }
    Object object;
    object.handle = runtime.nextObjectHandle++;
    object.objectClass = CKO_SECRET_KEY;
    object.keyType = CKK_AES;
    object.label = templateString(attributes, attributeCount, CKA_LABEL, "aes-key");
    object.id = templateString(attributes, attributeCount, CKA_ID, std::to_string(object.handle));
    object.path =
        (sessionSlot(sessionHandle).directory / "symmetric" / (safeFilename(object.label) + ".key"))
            .string();
    result = applyCreationTemplate(object, sessionHandle, attributes, attributeCount);
    if (result)
    {
        return result;
    }
    object.secretValue.resize(keyLength);
    if (RAND_bytes(object.secretValue.data(), (int)keyLength) != 1)
    {
        return CKR_DEVICE_ERROR;
    }
    if (!object.ownerSession)
    {
        result = saveSecretKey(object);
        if (result)
        {
            return result;
        }
    }
    auto handle = object.handle;
    runtime.objects.emplace(handle, std::move(object));
    if (!runtime.objects.at(handle).ownerSession)
    {
        result = persistMetadata(runtime.objects.at(handle).path);
        if (result)
        {
            return result;
        }
    }
    *keyHandle = handle;
    return CKR_OK;
}

CK_RV GenerateKeyPair(CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_PTR mechanism,
    CK_ATTRIBUTE_PTR publicTemplate, CK_ULONG publicCount, CK_ATTRIBUTE_PTR privateTemplate,
    CK_ULONG privateCount, CK_OBJECT_HANDLE_PTR publicHandle, CK_OBJECT_HANDLE_PTR privateHandle)
{
    if (!findSession(sessionHandle))
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!mechanism || !publicHandle || !privateHandle || (!publicTemplate && publicCount) ||
        (!privateTemplate && privateCount))
    {
        return CKR_ARGUMENTS_BAD;
    }
    auto validation = validateCreationTemplate(publicTemplate, publicCount);
    if (validation)
    {
        return validation;
    }
    validation = validateCreationTemplate(privateTemplate, privateCount);
    if (validation)
    {
        return validation;
    }
    if (isTokenTemplate(publicTemplate, publicCount) !=
        isTokenTemplate(privateTemplate, privateCount))
    {
        return CKR_TEMPLATE_INCONSISTENT;
    }
    std::string algorithm = generationAlgorithm(mechanism->mechanism, publicTemplate, publicCount);
    if (algorithm.empty())
    {
        return CKR_MECHANISM_INVALID;
    }
    Object publicPolicy, privatePolicy;
    publicPolicy.objectClass = CKO_PUBLIC_KEY;
    privatePolicy.objectClass = CKO_PRIVATE_KEY;
    publicPolicy.keyType = privatePolicy.keyType = algorithm == "RSA" ? CKK_RSA
        : algorithm == "EC"                                           ? CKK_EC
        : algorithm.rfind("ML-DSA", 0) == 0                           ? CKK_ML_DSA
                                                                      : CKK_SLH_DSA;
    validation = applyCreationTemplate(publicPolicy, sessionHandle, publicTemplate, publicCount);
    if (validation)
    {
        return validation;
    }
    validation = applyCreationTemplate(privatePolicy, sessionHandle, privateTemplate, privateCount);
    if (validation)
    {
        return validation;
    }
    OpenSslPtr<EVP_PKEY_CTX, EVP_PKEY_CTX_free> context(
        EVP_PKEY_CTX_new_from_name(nullptr, algorithm.c_str(), nullptr), EVP_PKEY_CTX_free);
    if (!context || EVP_PKEY_keygen_init(context.get()) <= 0)
    {
        return CKR_MECHANISM_INVALID;
    }
    if (algorithm == "RSA")
    {
        auto bits = templateUnsigned(publicTemplate, publicCount, CKA_MODULUS_BITS).value_or(3072);
        if (EVP_PKEY_CTX_set_rsa_keygen_bits(context.get(), (int)bits) <= 0)
        {
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }
    if (algorithm == "EC")
    {
        auto params = templateBytes(publicTemplate, publicCount, CKA_EC_PARAMS);
        if (!params)
        {
            return CKR_TEMPLATE_INCOMPLETE;
        }
        const unsigned char* cursor = params->data();
        OpenSslPtr<ASN1_OBJECT, ASN1_OBJECT_free> oid(
            d2i_ASN1_OBJECT(nullptr, &cursor, (long)params->size()), ASN1_OBJECT_free);
        if (!oid || cursor != params->data() + params->size())
        {
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        const char* group = OBJ_nid2sn(OBJ_obj2nid(oid.get()));
        if (!group || EVP_PKEY_CTX_set_group_name(context.get(), group) <= 0)
        {
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    }
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_generate(context.get(), &raw) <= 0)
    {
        return CKR_DEVICE_ERROR;
    }
    std::string label = templateString(privateTemplate, privateCount, CKA_LABEL,
        templateString(publicTemplate, publicCount, CKA_LABEL, "generated-key"));
    fs::path path =
        sessionSlot(sessionHandle).directory / "asymmetric" / (safeFilename(label) + ".p12");
    auto result = privatePolicy.ownerSession
        ? CKR_OK
        : saveKeyPair(sessionSlot(sessionHandle), path, raw, label);
    if (result)
    {
        EVP_PKEY_free(raw);
        return result;
    }
    CK_OBJECT_HANDLE privateObjectHandle = runtime.nextObjectHandle;
    registerKeyPair(sessionSlot(sessionHandle).id, label, path, raw, nullptr);
    auto commonId = templateString(privateTemplate, privateCount, CKA_ID,
        templateString(
            publicTemplate, publicCount, CKA_ID, runtime.objects.at(privateObjectHandle).id));
    runtime.objects.at(privateObjectHandle).id =
        templateString(privateTemplate, privateCount, CKA_ID, commonId);
    runtime.objects.at(privateObjectHandle + 1).id =
        templateString(publicTemplate, publicCount, CKA_ID, commonId);
    runtime.objects.at(privateObjectHandle + 1).label =
        templateString(publicTemplate, publicCount, CKA_LABEL, label);
    runtime.objects.at(privateObjectHandle).policy = privatePolicy.policy;
    runtime.objects.at(privateObjectHandle + 1).policy = publicPolicy.policy;
    runtime.objects.at(privateObjectHandle).ownerSession = privatePolicy.ownerSession;
    runtime.objects.at(privateObjectHandle + 1).ownerSession = publicPolicy.ownerSession;
    if (privatePolicy.ownerSession)
    {
        runtime.objects.at(privateObjectHandle).path.clear();
        runtime.objects.at(privateObjectHandle + 1).path.clear();
    }
    else
    {
        result = persistMetadata(path.string());
        if (result)
        {
            return result;
        }
    }
    *privateHandle = privateObjectHandle;
    *publicHandle = privateObjectHandle + 1;
    return CKR_OK;
}

CK_RV GenerateRandom(CK_SESSION_HANDLE sessionHandle, CK_BYTE_PTR output, CK_ULONG length)
{
    if (!findSession(sessionHandle))
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!output && length)
    {
        return CKR_ARGUMENTS_BAD;
    }
    return RAND_bytes(output, (int)length) == 1 ? CKR_OK : CKR_DEVICE_ERROR;
}

} // namespace hsm
