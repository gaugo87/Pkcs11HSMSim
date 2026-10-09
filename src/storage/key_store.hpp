#pragma once

#include "core/runtime.hpp"
#include "storage/metadata.hpp"
#include <openssl/x509.h>

namespace hsm
{

// Persistence of key files and publication of their PKCS#11 objects.
std::string objectIdForFilename(const std::string& filename);
CK_RV persistMetadata(std::string path);
// Takes ownership of the EVP key and optional certificate. Registers private,
// then public, then certificate objects sharing one backing file and default ID.
void registerKeyPair(CK_SLOT_ID slotId, const std::string& label, const fs::path& path,
    EVP_PKEY* privateKey, X509* certificate);
void loadTokenObjects();
CK_RV saveSecretKey(Object& object);
CK_RV saveKeyPair(const Slot& slot, const fs::path& path, EVP_PKEY* key, const std::string& label);
metadata::Records collectMetadata(const std::string& path, const Object* replacement = nullptr);

} // namespace hsm
