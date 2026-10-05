#include "crypto/signature.hpp"
#include "core/openssl.hpp"
#include "core/runtime.hpp"
#include "crypto/mechanisms.hpp"
#include "objects/policy.hpp"
#include <algorithm>
#include <cstring>
#include <openssl/ec.h>
#include <openssl/rsa.h>

namespace hsm
{

// Raw mechanisms consume one complete block/digest. Hashing/PQ mechanisms buffer
// multipart input so the same EVP operation handles both API forms.
static constexpr size_t maxMultipartBytes = 64 * 1024 * 1024;

static bool isRawSignature(CK_MECHANISM_TYPE mechanism)
{
    return mechanism == CKM_RSA_PKCS || mechanism == CKM_ECDSA || mechanism == CKM_RSA_PKCS_PSS;
}

static CK_RV appendSignatureData(
    CK_SESSION_HANDLE sessionHandle, CK_BYTE_PTR data, CK_ULONG dataLength, bool verify)
{
    auto* session = findSession(sessionHandle);
    if (!session)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!session->operation.active || session->operation.verify != verify)
    {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (!data && dataLength)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (isRawSignature(session->operation.mechanism))
    {
        session->operation.active = false;
        return CKR_MECHANISM_INVALID;
    }
    if (dataLength > maxMultipartBytes ||
        session->operation.bufferedData.size() > maxMultipartBytes - dataLength)
    {
        session->operation.active = false;
        return CKR_DATA_LEN_RANGE;
    }
    if (dataLength)
    {
        session->operation.bufferedData.insert(
            session->operation.bufferedData.end(), data, data + dataLength);
    }
    return CKR_OK;
}

static bool configureRsaPss(EVP_PKEY_CTX* context, const CK_RSA_PKCS_PSS_PARAMS& parameters)
{
    return EVP_PKEY_CTX_set_rsa_padding(context, RSA_PKCS1_PSS_PADDING) > 0 &&
        EVP_PKEY_CTX_set_signature_md(context, pssDigest(parameters.hashAlg)) > 0 &&
        EVP_PKEY_CTX_set_rsa_mgf1_md(context, mgfDigest(parameters.mgf)) > 0 &&
        EVP_PKEY_CTX_set_rsa_pss_saltlen(context, (int)parameters.sLen) > 0;
}

static CK_RV executeSignature(Operation& operation, const unsigned char* data, size_t dataLength,
    unsigned char* signature, size_t* signatureLength, bool verify)
{
    Object* object = findObject(operation.keyHandle);
    if (!object || !object->asymmetricKey)
    {
        return CKR_KEY_HANDLE_INVALID;
    }
    if (!policyValue(*object, verify ? CKA_VERIFY : CKA_SIGN))
    {
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }
    const bool isEc = object->keyType == CKK_EC;
    const size_t coordinateWidth =
        isEc ? (EVP_PKEY_get_bits(object->asymmetricKey.get()) + 7) / 8 : 0;
    const size_t requiredLength =
        isEc ? 2 * coordinateWidth : EVP_PKEY_get_size(object->asymmetricKey.get());
    if (!verify)
    {
        if (!signature)
        {
            *signatureLength = requiredLength;
            return CKR_OK;
        }
        if (*signatureLength < requiredLength)
        {
            *signatureLength = requiredLength;
            return CKR_BUFFER_TOO_SMALL;
        }
    }
    else if (!signature || (isEc && *signatureLength != requiredLength))
    {
        return CKR_SIGNATURE_LEN_RANGE;
    }
    static const unsigned char empty = 0;
    if (!data)
    {
        data = &empty;
    }
    std::vector<unsigned char> encoded;
    // PKCS#11 uses fixed-width r || s; OpenSSL expects an ASN.1 DER signature.
    if (verify && isEc)
    {
        OpenSslPtr<ECDSA_SIG, ECDSA_SIG_free> pair(ECDSA_SIG_new(), ECDSA_SIG_free);
        BIGNUM* r = BN_bin2bn(signature, (int)coordinateWidth, nullptr);
        BIGNUM* s = BN_bin2bn(signature + coordinateWidth, (int)coordinateWidth, nullptr);
        if (!pair || !r || !s)
        {
            BN_free(r);
            BN_free(s);
            return CKR_HOST_MEMORY;
        }
        if (!ECDSA_SIG_set0(pair.get(), r, s))
        {
            BN_free(r);
            BN_free(s);
            return CKR_DEVICE_ERROR;
        }
        int derLength = i2d_ECDSA_SIG(pair.get(), nullptr);
        if (derLength <= 0)
        {
            return CKR_DEVICE_ERROR;
        }
        encoded.resize(derLength);
        auto cursor = encoded.data();
        i2d_ECDSA_SIG(pair.get(), &cursor);
    }
    std::vector<unsigned char> result(EVP_PKEY_get_size(object->asymmetricKey.get()));
    size_t resultLength = result.size();
    const unsigned char* inputSignature = isEc ? encoded.data() : signature;
    size_t inputSignatureLength = isEc ? encoded.size() : *signatureLength;
    const bool raw = isRawSignature(operation.mechanism);
    int ok = 0;
    // Raw RSA/ECDSA/PSS input is already prepared by the caller; never hash it again.
    if (raw)
    {
        if (operation.mechanism == CKM_RSA_PKCS && dataLength > requiredLength - 11)
        {
            return CKR_DATA_LEN_RANGE;
        }
        OpenSslPtr<EVP_PKEY_CTX, EVP_PKEY_CTX_free> context(
            EVP_PKEY_CTX_new_from_pkey(nullptr, object->asymmetricKey.get(), nullptr),
            EVP_PKEY_CTX_free);
        if (!context)
        {
            return CKR_HOST_MEMORY;
        }
        if ((verify ? EVP_PKEY_verify_init(context.get()) : EVP_PKEY_sign_init(context.get())) <= 0)
        {
            return CKR_DEVICE_ERROR;
        }
        if (operation.mechanism == CKM_RSA_PKCS_PSS)
        {
            if (dataLength != (size_t)EVP_MD_get_size(pssDigest(operation.pss.hashAlg)))
            {
                return CKR_DATA_LEN_RANGE;
            }
            if (!configureRsaPss(context.get(), operation.pss))
            {
                return CKR_MECHANISM_PARAM_INVALID;
            }
        }
        else if (!isEc && EVP_PKEY_CTX_set_rsa_padding(context.get(), RSA_PKCS1_PADDING) <= 0)
        {
            return CKR_DEVICE_ERROR;
        }
        ok = verify
            ? EVP_PKEY_verify(context.get(), inputSignature, inputSignatureLength, data, dataLength)
            : EVP_PKEY_sign(context.get(), result.data(), &resultLength, data, dataLength);
    }
    else
    {
        OpenSslPtr<EVP_MD_CTX, EVP_MD_CTX_free> context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        if (!context)
        {
            return CKR_HOST_MEMORY;
        }
        EVP_PKEY_CTX* keyContext = nullptr;
        const EVP_MD* digest = isRsaPss(operation.mechanism) ? pssDigest(operation.pss.hashAlg)
                                                             : signatureDigest(operation.mechanism);
        if ((verify ? EVP_DigestVerifyInit(
                          context.get(), &keyContext, digest, nullptr, object->asymmetricKey.get())
                    : EVP_DigestSignInit(context.get(), &keyContext, digest, nullptr,
                          object->asymmetricKey.get())) <= 0)
        {
            return CKR_MECHANISM_INVALID;
        }
        if (isRsaPss(operation.mechanism) && !configureRsaPss(keyContext, operation.pss))
        {
            return CKR_MECHANISM_PARAM_INVALID;
        }
        ok = verify ? EVP_DigestVerify(
                          context.get(), inputSignature, inputSignatureLength, data, dataLength)
                    : EVP_DigestSign(context.get(), result.data(), &resultLength, data, dataLength);
    }
    if (verify)
    {
        return ok == 1 ? CKR_OK : CKR_SIGNATURE_INVALID;
    }
    if (ok <= 0)
    {
        return CKR_DEVICE_ERROR;
    }
    if (isEc)
    {
        const unsigned char* cursor = result.data();
        OpenSslPtr<ECDSA_SIG, ECDSA_SIG_free> pair(
            d2i_ECDSA_SIG(nullptr, &cursor, (long)resultLength), ECDSA_SIG_free);
        if (!pair)
        {
            return CKR_DEVICE_ERROR;
        }
        const BIGNUM *r = nullptr, *s = nullptr;
        ECDSA_SIG_get0(pair.get(), &r, &s);
        if (BN_bn2binpad(r, signature, (int)coordinateWidth) != (int)coordinateWidth ||
            BN_bn2binpad(s, signature + coordinateWidth, (int)coordinateWidth) !=
                (int)coordinateWidth)
        {
            return CKR_DEVICE_ERROR;
        }
        *signatureLength = requiredLength;
    }
    else
    {
        std::memcpy(signature, result.data(), resultLength);
        *signatureLength = resultLength;
    }
    return CKR_OK;
}

static CK_RV initializeSignature(CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_PTR mechanism,
    CK_OBJECT_HANDLE keyHandle, bool verify)
{
    auto* session = findSession(sessionHandle);
    if (!session)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!mechanism)
    {
        return CKR_ARGUMENTS_BAD;
    }
    if (session->operation.active)
    {
        return CKR_OPERATION_ACTIVE;
    }
    auto* object = findObject(keyHandle);
    if (!object || !object->asymmetricKey)
    {
        return CKR_KEY_HANDLE_INVALID;
    }
    if (std::find(supportedMechanisms.begin(), supportedMechanisms.end(), mechanism->mechanism) ==
        supportedMechanisms.end())
    {
        return CKR_MECHANISM_INVALID;
    }
    if (!verify && object->objectClass != CKO_PRIVATE_KEY)
    {
        return CKR_KEY_TYPE_INCONSISTENT;
    }
    if (!supportsSignature(object->keyType, mechanism->mechanism))
    {
        return CKR_KEY_TYPE_INCONSISTENT;
    }
    if (!policyValue(*object, verify ? CKA_VERIFY : CKA_SIGN))
    {
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }
    CK_RSA_PKCS_PSS_PARAMS parameters{};
    if (isRsaPss(mechanism->mechanism))
    {
        if (!mechanism->pParameter || mechanism->ulParameterLen != sizeof parameters)
        {
            return CKR_MECHANISM_PARAM_INVALID;
        }
        std::memcpy(&parameters, mechanism->pParameter, sizeof parameters);
        const EVP_MD* hash = pssDigest(parameters.hashAlg);
        if (!hash || !mgfDigest(parameters.mgf))
        {
            return CKR_MECHANISM_PARAM_INVALID;
        }
        CK_MECHANISM_TYPE expected = mechanism->mechanism == CKM_SHA256_RSA_PKCS_PSS ? CKM_SHA256
            : mechanism->mechanism == CKM_SHA384_RSA_PKCS_PSS                        ? CKM_SHA384
            : mechanism->mechanism == CKM_SHA512_RSA_PKCS_PSS                        ? CKM_SHA512
                                                              : parameters.hashAlg;
        if (expected != parameters.hashAlg)
        {
            return CKR_MECHANISM_PARAM_INVALID;
        }
        // emLen = ceil((modBits - 1) / 8), per EMSA-PSS.
        const int maxSalt =
            (EVP_PKEY_get_bits(object->asymmetricKey.get()) + 6) / 8 - EVP_MD_get_size(hash) - 2;
        if (maxSalt < 0 || parameters.sLen > (CK_ULONG)maxSalt)
        {
            return CKR_MECHANISM_PARAM_INVALID;
        }
    }
    else if (mechanism->pParameter || mechanism->ulParameterLen)
    {
        return CKR_MECHANISM_PARAM_INVALID;
    }
    session->operation = {true, verify, mechanism->mechanism, keyHandle, {}, parameters};
    return CKR_OK;
}

CK_RV SignInit(
    CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE keyHandle)
{
    return initializeSignature(sessionHandle, mechanism, keyHandle, false);
}

CK_RV Sign(CK_SESSION_HANDLE sessionHandle, CK_BYTE_PTR data, CK_ULONG dataLength,
    CK_BYTE_PTR signature, CK_ULONG_PTR signatureLength)
{
    auto* session = findSession(sessionHandle);
    if (!session)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!session->operation.active || session->operation.verify)
    {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (!signatureLength || (!data && dataLength))
    {
        return CKR_ARGUMENTS_BAD;
    }
    size_t length = *signatureLength;
    auto result = executeSignature(session->operation, data, dataLength, signature, &length, false);
    *signatureLength = (CK_ULONG)length;
    // A size query or short buffer leaves the operation available for a retry.
    if (signature && result != CKR_BUFFER_TOO_SMALL)
    {
        session->operation.active = false;
    }
    return result;
}

CK_RV SignUpdate(CK_SESSION_HANDLE sessionHandle, CK_BYTE_PTR data, CK_ULONG dataLength)
{
    return appendSignatureData(sessionHandle, data, dataLength, false);
}

CK_RV SignFinal(
    CK_SESSION_HANDLE sessionHandle, CK_BYTE_PTR signature, CK_ULONG_PTR signatureLength)
{
    auto* session = findSession(sessionHandle);
    if (!session)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!session->operation.active || session->operation.verify)
    {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (!signatureLength)
    {
        return CKR_ARGUMENTS_BAD;
    }
    size_t length = *signatureLength;
    auto result = executeSignature(session->operation, session->operation.bufferedData.data(),
        session->operation.bufferedData.size(), signature, &length, false);
    *signatureLength = (CK_ULONG)length;
    // A size query or short buffer leaves the operation available for a retry.
    if (signature && result != CKR_BUFFER_TOO_SMALL)
    {
        session->operation.active = false;
    }
    return result;
}

CK_RV VerifyInit(
    CK_SESSION_HANDLE sessionHandle, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE keyHandle)
{
    return initializeSignature(sessionHandle, mechanism, keyHandle, true);
}

CK_RV Verify(CK_SESSION_HANDLE sessionHandle, CK_BYTE_PTR data, CK_ULONG dataLength,
    CK_BYTE_PTR signature, CK_ULONG signatureLength)
{
    auto* session = findSession(sessionHandle);
    if (!session)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!session->operation.active || !session->operation.verify)
    {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if ((!data && dataLength) || (!signature && signatureLength))
    {
        return CKR_ARGUMENTS_BAD;
    }
    size_t length = signatureLength;
    auto result = executeSignature(session->operation, data, dataLength, signature, &length, true);
    session->operation.active = false;
    return result;
}

CK_RV VerifyUpdate(CK_SESSION_HANDLE sessionHandle, CK_BYTE_PTR data, CK_ULONG dataLength)
{
    return appendSignatureData(sessionHandle, data, dataLength, true);
}

CK_RV VerifyFinal(CK_SESSION_HANDLE sessionHandle, CK_BYTE_PTR signature, CK_ULONG signatureLength)
{
    auto* session = findSession(sessionHandle);
    if (!session)
    {
        return CKR_SESSION_HANDLE_INVALID;
    }
    if (!session->operation.active || !session->operation.verify)
    {
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (!signature && signatureLength)
    {
        return CKR_ARGUMENTS_BAD;
    }
    size_t length = signatureLength;
    auto result = executeSignature(session->operation, session->operation.bufferedData.data(),
        session->operation.bufferedData.size(), signature, &length, true);
    session->operation.active = false;
    return result;
}

} // namespace hsm
