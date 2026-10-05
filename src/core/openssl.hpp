#pragma once
#include <memory>

namespace hsm
{
// Owns OpenSSL allocations with the matching OpenSSL release function.
template <class T, void (*Free)(T*)> using OpenSslPtr = std::unique_ptr<T, decltype(Free)>;
} // namespace hsm
