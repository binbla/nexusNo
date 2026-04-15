#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <span>
#include <tuple>
#include <utility>
#include <vector>

// ============================================================================
// 密码学工具库 - 定义了加密、解密、哈希、KDF等操作的抽象接口
// ============================================================================

namespace wg {

// ============================================================================
// Constants & Type Aliases
// ============================================================================

constexpr size_t KEY_SIZE = 32;            // For both public and private keys
constexpr size_t PUBLIC_KEY_SIZE = 32;     // X25519 public key size
constexpr size_t PRIVATE_KEY_SIZE = 32;    // X25519 private key size
constexpr size_t SYMMETRIC_KEY_SIZE = 32;  // ChaCha20-Poly1305 key size
constexpr size_t CHAINING_KEY_SIZE = 32;   // Chaining key size

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

using Timestamp = std::array<uint8_t, TIMESTAMP_SIZE>;
using Tag = std::array<uint8_t, TAG_SIZE>;
using Nonce = std::array<uint8_t, NONCE_SIZE>;
using XNonce = std::array<uint8_t, XNONCE_SIZE>;
using Mac = std::array<uint8_t, MAC_SIZE>;    // Keyed-Blake2s 16
using Hmac = std::array<uint8_t, HMAC_SIZE>;  // Hmac-Blake2s 32
using Hash = std::array<uint8_t, HASH_SIZE>;  // Blake2s hash 32
using SharedSecret = std::array<uint8_t, KEY_SIZE>;
using Bytes32 = std::array<uint8_t, 32>;  // 有些中间变量需要不特指某种类型
// ===================== CryptoProvider =====================

class CryptoProvider {
   public:
    /*
    ✔ DH (X25519)
    ✔ Hash (BLAKE2s)
    ✔ KDF (HKDF-like)
    ✔ AEAD (ChaCha20-Poly1305 / XChaCha20)
    ✔ RNG
    */
    virtual ~CryptoProvider() = default;

    // ===================== Key =====================

    // 生成静态密钥对（长期使用）
    virtual void generate_static_keypair(PrivateKey& priv, PublicKey& pub) = 0;

    // 生成临时密钥对（每次握手使用）
    virtual void generate_ephemeral_keypair(PrivateKey& priv,
                                            PublicKey& pub) = 0;

    // 从私钥派生公钥
    virtual void derive_public_key(const PrivateKey& priv, PublicKey& pub) = 0;

    // ===================== DH =====================

    // 计算 DH 输出，返回 false 表示失败（如无效公钥）

    virtual bool dh(const PrivateKey& priv, const PublicKey& pub,
                    SharedSecret& out) = 0;

    // ===================== AEAD =====================
    // 这个接口单独输出，ciphertext 和 tag 分开存储
    virtual void aead_encrypt_detached(const SymmetricKey& key,
                                       const Nonce& nonce,
                                       std::span<const uint8_t> ad,
                                       std::span<const uint8_t> plaintext,
                                       std::span<uint8_t> ciphertext,
                                       Tag& tag) = 0;
    // 这个接口会把 tag 附加在ciphertext 后面
    virtual void aead_encrypt(const SymmetricKey& key, const Nonce& nonce,
                              std::span<const uint8_t> ad,
                              std::span<const uint8_t> plaintext,
                              std::span<uint8_t> ciphertext) = 0;

    // 同理
    virtual bool aead_decrypt_detached(const SymmetricKey& key,
                                       const Nonce& nonce,
                                       std::span<const uint8_t> ad,
                                       std::span<const uint8_t> ciphertext,
                                       const Tag& tag,
                                       std::span<uint8_t> plaintext) = 0;
    // 同理
    virtual bool aead_decrypt(const SymmetricKey& key, const Nonce& nonce,
                              std::span<const uint8_t> ad,
                              std::span<const uint8_t> ciphertext,
                              std::span<uint8_t> plaintext) = 0;

    // ===================== XAEAD =====================

    virtual void xaead_encrypt_detached(const SymmetricKey& key,
                                        const XNonce& nonce,
                                        std::span<const uint8_t> ad,
                                        std::span<const uint8_t> plaintext,
                                        std::span<uint8_t> ciphertext,
                                        Tag& tag) = 0;
    virtual void xaead_encrypt(const SymmetricKey& key, const XNonce& nonce,
                               std::span<const uint8_t> ad,
                               std::span<const uint8_t> plaintext,
                               std::span<uint8_t> ciphertext) = 0;

    virtual bool xaead_decrypt_detached(const SymmetricKey& key,
                                        const XNonce& nonce,
                                        std::span<const uint8_t> ad,
                                        std::span<const uint8_t> ciphertext,
                                        const Tag& tag,
                                        std::span<uint8_t> plaintext) = 0;
    virtual bool xaead_decrypt(const SymmetricKey& key, const XNonce& nonce,
                               std::span<const uint8_t> ad,
                               std::span<const uint8_t> ciphertext,
                               std::span<uint8_t> plaintext) = 0;

    // ===================== Hash =====================
    virtual void hash(std::span<const uint8_t> data, Hash& out) = 0;
    virtual void hash2(std::span<const uint8_t> a, std::span<const uint8_t> b,
                       Hash& out) = 0;  // noise 要用。但不算是密码学原语操作

    virtual void mac(std::span<const uint8_t> data,
                     std::span<const uint8_t> key, Mac& out) = 0;

    // ===================== HMAC =====================

    virtual void hmac(std::span<const uint8_t> data,  //
                      std::span<const uint8_t> key,   //
                      std::span<uint8_t, HMAC_SIZE> out) = 0;

    // ===================== KDF =====================
    virtual void kdf1(const ChainingKey& chaining_key,  //
                      std::span<const uint8_t> data,    //
                      ChainingKey& out1) = 0;

    virtual void kdf2(const ChainingKey& chaining_key,  //
                      std::span<const uint8_t> data,    //
                      ChainingKey& out1,                //
                      SymmetricKey& out2) = 0;

    virtual void kdf3(const ChainingKey& chaining_key,  //
                      std::span<const uint8_t> data,    //
                      ChainingKey& out1,                //
                      Bytes32& out2,                    //
                      SymmetricKey& out3) = 0;

    // ===================== RNG =====================

    virtual void random_bytes(std::span<uint8_t> out) = 0;

    template <size_t N>
    void fill_random(std::array<uint8_t, N>& arr) {
        random_bytes(std::span<uint8_t>(arr.data(), N));
    }
};

// ===================== Factory =====================

/// Create a libsodium-based crypto provider
std::unique_ptr<CryptoProvider> create_libsodium_provider();

}  // namespace wg
