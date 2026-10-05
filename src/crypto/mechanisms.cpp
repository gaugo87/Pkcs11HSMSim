#include "crypto/mechanisms.hpp"
#include "objects/template.hpp"

namespace hsm
{

const std::array<CK_MECHANISM_TYPE, 22> supportedMechanisms = {CKM_AES_ECB_ENCRYPT_DATA,
    CKM_RSA_PKCS_KEY_PAIR_GEN, CKM_RSA_PKCS, CKM_SHA256_RSA_PKCS, CKM_SHA384_RSA_PKCS,
    CKM_SHA512_RSA_PKCS, CKM_EC_KEY_PAIR_GEN, CKM_ECDSA, CKM_ECDSA_SHA256, CKM_ECDSA_SHA384,
    CKM_ECDSA_SHA512, CKM_AES_KEY_GEN, CKM_AES_KEY_WRAP, CKM_AES_KEY_WRAP_PAD,
    CKM_ML_DSA_KEY_PAIR_GEN, CKM_ML_DSA, CKM_SLH_DSA_KEY_PAIR_GEN, CKM_SLH_DSA, CKM_RSA_PKCS_PSS,
    CKM_SHA256_RSA_PKCS_PSS, CKM_SHA384_RSA_PKCS_PSS, CKM_SHA512_RSA_PKCS_PSS};

CK_KEY_TYPE keyType(EVP_PKEY* key)
{
    if (EVP_PKEY_is_a(key, "RSA"))
    {
        return CKK_RSA;
    }
    if (EVP_PKEY_is_a(key, "EC"))
    {
        return CKK_EC;
    }
    if (std::string(EVP_PKEY_get0_type_name(key)).rfind("ML-DSA-", 0) == 0)
    {
        return CKK_ML_DSA;
    }
    if (std::string(EVP_PKEY_get0_type_name(key)).rfind("SLH-DSA-", 0) == 0)
    {
        return CKK_SLH_DSA;
    }
    return ~0UL;
}

std::string keyAlgorithmName(EVP_PKEY* key)
{
    const char* name = EVP_PKEY_get0_type_name(key);
    return name ? name : "";
}

bool isRsaPss(CK_MECHANISM_TYPE mechanism)
{
    return mechanism == CKM_RSA_PKCS_PSS || mechanism == CKM_SHA256_RSA_PKCS_PSS ||
        mechanism == CKM_SHA384_RSA_PKCS_PSS || mechanism == CKM_SHA512_RSA_PKCS_PSS;
}

bool supportsSignature(CK_KEY_TYPE type, CK_MECHANISM_TYPE mechanism)
{
    if (type == CKK_RSA)
    {
        return isRsaPss(mechanism) || mechanism == CKM_RSA_PKCS ||
            mechanism == CKM_SHA256_RSA_PKCS || mechanism == CKM_SHA384_RSA_PKCS ||
            mechanism == CKM_SHA512_RSA_PKCS;
    }
    if (type == CKK_EC)
    {
        return mechanism == CKM_ECDSA || mechanism == CKM_ECDSA_SHA256 ||
            mechanism == CKM_ECDSA_SHA384 || mechanism == CKM_ECDSA_SHA512;
    }
    if (type == CKK_ML_DSA)
    {
        return mechanism == CKM_ML_DSA;
    }
    if (type == CKK_SLH_DSA)
    {
        return mechanism == CKM_SLH_DSA;
    }
    return false;
}

const EVP_MD* pssDigest(CK_MECHANISM_TYPE mechanism)
{
    switch (mechanism)
    {
        case CKM_SHA256:
            return EVP_sha256();
        case CKM_SHA384:
            return EVP_sha384();
        case CKM_SHA512:
            return EVP_sha512();
        default:
            return nullptr;
    }
}

const EVP_MD* mgfDigest(CK_ULONG maskGenerationFunction)
{
    switch (maskGenerationFunction)
    {
        case CKG_MGF1_SHA256:
            return EVP_sha256();
        case CKG_MGF1_SHA384:
            return EVP_sha384();
        case CKG_MGF1_SHA512:
            return EVP_sha512();
        default:
            return nullptr;
    }
}

const EVP_MD* signatureDigest(CK_MECHANISM_TYPE mechanism)
{
    if (mechanism == CKM_SHA256_RSA_PKCS || mechanism == CKM_ECDSA_SHA256)
    {
        return EVP_sha256();
    }
    if (mechanism == CKM_SHA384_RSA_PKCS || mechanism == CKM_ECDSA_SHA384)
    {
        return EVP_sha384();
    }
    if (mechanism == CKM_SHA512_RSA_PKCS || mechanism == CKM_ECDSA_SHA512)
    {
        return EVP_sha512();
    }
    return nullptr;
}

CK_ULONG keyParameterSet(const Object& object)
{
    if (object.keyType == CKK_ML_DSA)
    {
        if (object.algorithmName.find("44") != std::string::npos)
        {
            return CKP_ML_DSA_44;
        }
        if (object.algorithmName.find("87") != std::string::npos)
        {
            return CKP_ML_DSA_87;
        }
        return CKP_ML_DSA_65;
    }
    if (object.keyType == CKK_SLH_DSA)
    {
        static const char* names[] = {"SHA2-128s", "SHAKE-128s", "SHA2-128f", "SHAKE-128f",
            "SHA2-192s", "SHAKE-192s", "SHA2-192f", "SHAKE-192f", "SHA2-256s", "SHAKE-256s",
            "SHA2-256f", "SHAKE-256f"};
        for (CK_ULONG i = 0; i < 12; i++)
        {
            if (object.algorithmName.find(names[i]) != std::string::npos)
            {
                return i + 1;
            }
        }
    }
    return 0;
}

std::string generationAlgorithm(
    CK_MECHANISM_TYPE mechanism, CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount)
{
    if (mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN)
    {
        return "RSA";
    }
    if (mechanism == CKM_EC_KEY_PAIR_GEN)
    {
        return "EC";
    }
    if (mechanism == CKM_ML_DSA_KEY_PAIR_GEN)
    {
        switch (
            templateUnsigned(attributes, attributeCount, CKA_PARAMETER_SET).value_or(CKP_ML_DSA_65))
        {
            case CKP_ML_DSA_44:
                return "ML-DSA-44";
            case CKP_ML_DSA_65:
                return "ML-DSA-65";
            case CKP_ML_DSA_87:
                return "ML-DSA-87";
            default:
                return {};
        }
    }
    if (mechanism == CKM_SLH_DSA_KEY_PAIR_GEN)
    {
        static const char* names[] = {"SLH-DSA-SHA2-128s", "SLH-DSA-SHAKE-128s",
            "SLH-DSA-SHA2-128f", "SLH-DSA-SHAKE-128f", "SLH-DSA-SHA2-192s", "SLH-DSA-SHAKE-192s",
            "SLH-DSA-SHA2-192f", "SLH-DSA-SHAKE-192f", "SLH-DSA-SHA2-256s", "SLH-DSA-SHAKE-256s",
            "SLH-DSA-SHA2-256f", "SLH-DSA-SHAKE-256f"};
        auto parameterSet = templateUnsigned(attributes, attributeCount, CKA_PARAMETER_SET)
                                .value_or(CKP_SLH_DSA_SHA2_128S);
        return parameterSet >= 1 && parameterSet <= 12 ? names[parameterSet - 1] : "";
    }
    return {};
}

} // namespace hsm
