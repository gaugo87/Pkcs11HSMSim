#pragma once

#include "core/runtime.hpp"
#include <array>

namespace hsm
{

extern const std::array<CK_MECHANISM_TYPE, 22> supportedMechanisms;

// Mechanism catalog and mapping between PKCS#11 and OpenSSL algorithm names.
CK_KEY_TYPE keyType(EVP_PKEY* key);
std::string keyAlgorithmName(EVP_PKEY* key);
bool isRsaPss(CK_MECHANISM_TYPE mechanism);
bool supportsSignature(CK_KEY_TYPE type, CK_MECHANISM_TYPE mechanism);
const EVP_MD* pssDigest(CK_MECHANISM_TYPE mechanism);
const EVP_MD* mgfDigest(CK_ULONG maskGenerationFunction);
const EVP_MD* signatureDigest(CK_MECHANISM_TYPE mechanism);
CK_ULONG keyParameterSet(const Object& object);
std::string generationAlgorithm(
    CK_MECHANISM_TYPE mechanism, CK_ATTRIBUTE_PTR attributes, CK_ULONG attributeCount);

} // namespace hsm
