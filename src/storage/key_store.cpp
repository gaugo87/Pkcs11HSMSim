#include "storage/key_store.hpp"
#include "core/openssl.hpp"
#include "core/utilities.hpp"
#include "crypto/mechanisms.hpp"
#include <fstream>
#include <iterator>
#include <limits>
#include <openssl/pkcs12.h>
#include <stdexcept>

namespace hsm
{

std::string objectIdForFilename(const std::string& filename)
{
    unsigned char digest[32];
    unsigned digestLength = 0;
    if (EVP_Digest(
            filename.data(), filename.size(), digest, &digestLength, EVP_sha256(), nullptr) != 1)
    {
        throw std::runtime_error("ID digest failed");
    }
    return std::string(reinterpret_cast<char*>(digest), digestLength);
}

CK_RV persistMetadata(std::string path)
{
    try
    {
        auto records = collectMetadata(path);
        metadata::create(path, records);
        return CKR_OK;
    }
    catch (...)
    {
        // The key file was created by this operation; do not publish a partial object.
        for (auto it = runtime.objects.begin(); it != runtime.objects.end();)
        {
            if (it->second.path == path)
            {
                it = runtime.objects.erase(it);
            }
            else
            {
                ++it;
            }
        }
        std::error_code ec;
        fs::remove(path, ec);
        return CKR_DEVICE_ERROR;
    }
}

static std::shared_ptr<EVP_PKEY> publicKeyOnly(EVP_PKEY* privateKey)
{
    unsigned char* der = nullptr;
    int derLength = i2d_PUBKEY(privateKey, &der);
    if (derLength <= 0)
    {
        return {};
    }
    const unsigned char* cursor = der;
    EVP_PKEY* publicKey = d2i_PUBKEY(nullptr, &cursor, derLength);
    OPENSSL_free(der);
    return {publicKey, EVP_PKEY_free};
}

void registerKeyPair(
    const std::string& label, const fs::path& path, EVP_PKEY* privateKey, X509* certificate)
{
    auto sharedPrivateKey = std::shared_ptr<EVP_PKEY>(privateKey, EVP_PKEY_free);
    auto id = objectIdForFilename(path.filename().string());
    Object privateObject;
    privateObject.handle = runtime.nextObjectHandle++;
    privateObject.objectClass = CKO_PRIVATE_KEY;
    privateObject.keyType = keyType(privateKey);
    privateObject.label = label;
    privateObject.id = id;
    privateObject.path = path.string();
    privateObject.algorithmName = keyAlgorithmName(privateKey);
    privateObject.asymmetricKey = sharedPrivateKey;
    runtime.objects.emplace(privateObject.handle, privateObject);
    auto publicKey = publicKeyOnly(privateKey);
    if (publicKey)
    {
        Object publicObject;
        publicObject.handle = runtime.nextObjectHandle++;
        publicObject.objectClass = CKO_PUBLIC_KEY;
        publicObject.keyType = privateObject.keyType;
        publicObject.label = label;
        publicObject.id = id;
        publicObject.path = path.string();
        publicObject.algorithmName = privateObject.algorithmName;
        publicObject.asymmetricKey = publicKey;
        runtime.objects.emplace(publicObject.handle, std::move(publicObject));
    }
    if (certificate)
    {
        unsigned char* der = nullptr;
        int derLength = i2d_X509(certificate, &der);
        Object certificateObject;
        certificateObject.handle = runtime.nextObjectHandle++;
        certificateObject.objectClass = CKO_CERTIFICATE;
        certificateObject.label = label;
        certificateObject.id = id;
        certificateObject.path = path.string();
        if (derLength > 0)
        {
            certificateObject.certificateDer.assign(der, der + derLength);
            OPENSSL_free(der);
        }
        runtime.objects.emplace(certificateObject.handle, std::move(certificateObject));
        X509_free(certificate);
    }
}

static void loadAsymmetricFiles(const fs::path& directory, const std::string& password)
{
    for (auto& entry : fs::directory_iterator(directory))
    {
        if (entry.path().extension() != ".p12" && entry.path().extension() != ".pfx")
        {
            continue;
        }
        // Keep CRT file handles local: OpenSSL only receives memory buffers.
        std::ifstream input(entry.path(), std::ios::binary);
        if (!input)
        {
            continue;
        }
        std::vector<unsigned char> der((std::istreambuf_iterator<char>(input)), {});
        if (input.bad() || der.empty() ||
            der.size() > static_cast<size_t>(std::numeric_limits<long>::max()))
        {
            continue;
        }
        const unsigned char* cursor = der.data();
        PKCS12* container = d2i_PKCS12(nullptr, &cursor, static_cast<long>(der.size()));
        if (!container)
        {
            continue;
        }
        EVP_PKEY* privateKey = nullptr;
        X509* certificate = nullptr;
        if (PKCS12_parse(container, password.c_str(), &privateKey, &certificate, nullptr) == 1 &&
            privateKey)
        {
            registerKeyPair(entry.path().stem().string(), entry.path(), privateKey, certificate);
        }
        PKCS12_free(container);
    }
}

static void loadSymmetricFiles(const fs::path& directory)
{
    for (auto& entry : fs::directory_iterator(directory))
    {
        if (entry.path().extension() != ".key")
        {
            continue;
        }
        std::ifstream input(entry.path());
        std::string encoded((std::istreambuf_iterator<char>(input)), {});
        auto bytes = decodeHex(encoded);
        if (bytes.empty())
        {
            continue;
        }
        Object object;
        object.handle = runtime.nextObjectHandle++;
        object.objectClass = CKO_SECRET_KEY;
        object.keyType = CKK_AES;
        object.label = entry.path().stem().string();
        object.id = objectIdForFilename(entry.path().filename().string());
        object.path = entry.path().string();
        object.secretValue = std::move(bytes);
        runtime.objects.emplace(object.handle, std::move(object));
    }
}

static void loadObjectMetadata()
{
    for (auto& [handle, object] : runtime.objects)
    {
        auto records = metadata::read(object.path);
        auto record = records.find((std::uint32_t)object.objectClass);
        if (record != records.end())
        {
            object.label = record->second.label;
            object.id = record->second.id;
            object.policy = record->second.policy;
        }
    }
}

void loadTokenObjects()
{
    runtime.objects.clear();
    runtime.nextObjectHandle = 1;
    fs::create_directories(runtime.storageRoot / "asymmetric");
    fs::create_directories(runtime.storageRoot / "symmetric");
    const auto password = environmentValue("HSM_SIM_P12_PASSWORD", "");
    loadAsymmetricFiles(runtime.storageRoot / "asymmetric", password);
    loadSymmetricFiles(runtime.storageRoot / "symmetric");
    loadObjectMetadata();
}

CK_RV saveSecretKey(Object& object)
{
    if (fs::exists(object.path))
    {
        return CKR_TEMPLATE_INCONSISTENT;
    }
    std::ofstream output(object.path, std::ios::trunc);
    if (!output)
    {
        return CKR_DEVICE_ERROR;
    }
    output << encodeHex(object.secretValue.data(), object.secretValue.size()) << "\n";
    return output ? CKR_OK : CKR_DEVICE_ERROR;
}

CK_RV saveKeyPair(const fs::path& path, EVP_PKEY* key, const std::string& label)
{
    if (fs::exists(path))
    {
        return CKR_TEMPLATE_INCONSISTENT;
    }
    std::string password = environmentValue("HSM_SIM_P12_PASSWORD", "");
    OpenSslPtr<PKCS12, PKCS12_free> container(
        PKCS12_create(password.c_str(), label.c_str(), key, nullptr, nullptr, 0, 0, 0, 0, 0),
        PKCS12_free);
    if (!container)
    {
        return CKR_DEVICE_ERROR;
    }
    int length = i2d_PKCS12(container.get(), nullptr);
    if (length <= 0)
    {
        return CKR_DEVICE_ERROR;
    }
    std::vector<unsigned char> der(static_cast<size_t>(length));
    auto cursor = der.data();
    if (i2d_PKCS12(container.get(), &cursor) != length)
    {
        return CKR_DEVICE_ERROR;
    }
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output)
    {
        return CKR_DEVICE_ERROR;
    }
    output.write(reinterpret_cast<const char*>(der.data()), length);
    output.close();
    return output ? CKR_OK : CKR_DEVICE_ERROR;
}

metadata::Records collectMetadata(const std::string& path, const Object* replacement)
{
    metadata::Records records;
    for (const auto& [handle, stored] : runtime.objects)
    {
        if (!stored.ownerSession && stored.path == path)
        {
            const auto& object =
                replacement && replacement->handle == handle ? *replacement : stored;
            records.emplace(static_cast<std::uint32_t>(object.objectClass),
                metadata::Attributes{object.label, object.id, object.policy});
        }
    }
    return records;
}

} // namespace hsm
