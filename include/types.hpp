#pragma once

#ifndef TYPES_HPP
#define TYPES_HPP

#include <array>
#include <cfloat>   // 浮点类型极限
#include <climits>  // 整数类型极限
#include <cstddef>  //常用类型
#include <cstdint>  // 定长整数类型
#include <cstdlib>  // 通用工具

namespace wg {
constexpr size_t KEY_SIZE = 32;            // For both public and private keys
constexpr size_t PUBLIC_KEY_SIZE = 32;     // X25519 public key size
constexpr size_t PRIVATE_KEY_SIZE = 32;    // X25519 private key size
constexpr size_t SYMMETRIC_KEY_SIZE = 32;  // ChaCha20-Poly1305 key size
constexpr size_t CHAINING_KEY_SIZE = 32;   // Chaining key size
constexpr size_t PSK_SIZE = 32;            // Pre-shared key size

constexpr size_t TIMESTAMP_SIZE = 12;  // 8 bytes timestamp + 4 bytes noise
constexpr size_t COUNTER_SIZE = 8;     // 64-bit packet counter
constexpr size_t TAG_SIZE = 16;        // Poly1305 authentication tag
constexpr size_t NONCE_SIZE = 12;      // ChaCha20-Poly1305 nonce size
constexpr size_t XNONCE_SIZE = 24;     // XChaCha20 nonce size
constexpr size_t HASH_SIZE = 32;       // BLAKE2s hash output size
constexpr size_t HMAC_SIZE = 32;       // HMAC-BLAKE2s output size (32 bytes)
constexpr size_t MAC_SIZE = 16;    // BLAKE2s MAC size (16 bytes for keyed MAC)
constexpr size_t BLOCK_SIZE = 64;  // BLAKE2s block size

using PublicKey = std::array<uint8_t, PUBLIC_KEY_SIZE>;
using PrivateKey = std::array<uint8_t, PRIVATE_KEY_SIZE>;
using SymmetricKey = std::array<uint8_t, SYMMETRIC_KEY_SIZE>;
using ChainingKey = std::array<uint8_t, CHAINING_KEY_SIZE>;
using PreSharedKey = std::array<uint8_t, PSK_SIZE>;
using Hash = std::array<uint8_t, HASH_SIZE>;         // Blake2s hash 32
using SharedSecret = std::array<uint8_t, KEY_SIZE>;  // DH 结果

using KeypairIndex = uint32_t;

using Timestamp = std::array<uint8_t, TIMESTAMP_SIZE>;
using Tag = std::array<uint8_t, TAG_SIZE>;
using Nonce = std::array<uint8_t, NONCE_SIZE>;
using XNonce = std::array<uint8_t, XNONCE_SIZE>;
using Mac = std::array<uint8_t, MAC_SIZE>;    // Keyed-Blake2s 16
using Hmac = std::array<uint8_t, HMAC_SIZE>;  // Hmac-Blake2s 32

using Bytes32 = std::array<uint8_t, 32>;  // 有些中间变量需要不特指某种类型

}  // namespace wg

#endif  // TYPES_HPP