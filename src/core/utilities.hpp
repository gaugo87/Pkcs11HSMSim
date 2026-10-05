#pragma once

#include "pkcs11.h"
#include <cstddef>
#include <string>
#include <vector>

namespace hsm
{

// Environment, byte encoding and PKCS#11 fixed-width string helpers.
void writePaddedString(CK_CHAR* destination, size_t capacity, const char* value);
std::string environmentValue(const char* name, const char* fallback);
std::string encodeHex(const unsigned char* bytes, size_t length);
std::vector<unsigned char> decodeHex(std::string encoded);
std::string safeFilename(std::string label);

} // namespace hsm
