#pragma once

#include <algorithm>
#include <array>
#include <memory>
#include <tuple>
#include <utility>
#include <vector>

#include "types.hpp"

namespace wg {

// ============================================================================
// CryptoProvider - Abstract Interface for Cryptographic Operations
// 提供密码学组建功能，包括密钥生成、加密解密、哈希和KDF等
// ============================================================================

class CryptoProvider {
   public:
    virtual ~CryptoProvider() = default;

    // ========================================================================
    // Key Generation & Management
    // ========================================================================

    /// 生成新的静态密钥对x25519
    /// Generate a new keypair for static identity x25519
    /// @return pair of (private_key, public_key)
    virtual std::pair<PrivateKey, PublicKey> generate_static_keypair() = 0;

    /// 生成新的临时密钥对用于握手x25519 直接调用上面那个
    /// Generate a new ephemeral keypair for handshake x25519
    /// @return pair of (private_key, public_key)
    virtual std::pair<PrivateKey, PublicKey> generate_ephemeral_keypair() = 0;

    /// 从私钥派生公钥
    /// Derive public key from private key
    /// @param private_key The private key
    /// @return The corresponding public key
    virtual PublicKey derive_public_key(const PrivateKey& private_key) = 0;

    // ========================================================================
    // Key Exchange (DH)
    // ========================================================================

    /// 私钥与公钥的点乘运算，返回 32 字节输出，也就是secrets
    /// Perform Diffie-Hellman key exchange (X25519)
    /// @param private_key Our private key
    /// @param peer_public_key Peer's public key
    /// @return Shared secret (symmetric key), empty if operation fails
    virtual SymmetricKey dh(const PrivateKey& private_key,
                            const PublicKey& peer_public_key) = 0;

    // ========================================================================
    // Symmetric Encryption (ChaCha20-Poly1305)
    // ========================================================================

    /// 加密并认证数据
    /// Encrypt and authenticate data
    /// @param key Symmetric key
    /// @param nonce 12-byte nonce
    /// @param plaintext Data to encrypt
    /// @param aad Additional authenticated data (optional)
    /// @return Ciphertext + tag (appended), empty if operation fails
    virtual std::vector<uint8_t> encrypt(
        const SymmetricKey& key, const Nonce& nonce,
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& aad = {}) = 0;

    /// 解密并验证认证
    /// Decrypt and verify authentication
    /// @param key Symmetric key
    /// @param nonce 12-byte nonce
    /// @param ciphertext Ciphertext + tag
    /// @param aad Additional authenticated data (optional)
    /// @return Plaintext if successful, empty if authentication fails
    virtual std::vector<uint8_t> decrypt(
        const SymmetricKey& key, const Nonce& nonce,
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& aad = {}) = 0;

    /// XChaCha20-Poly1305 AEAD 加密(用于 cookie 等场景)
    virtual std::vector<uint8_t> xencrypt(
        const SymmetricKey& key, const XNonce& nonce,
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& aad = {}) = 0;

    /// XChaCha20-Poly1305 AEAD 解密
    virtual std::vector<uint8_t> xdecrypt(
        const SymmetricKey& key, const XNonce& nonce,
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& aad = {}) = 0;

    // ========================================================================
    // Key Derivation
    // ========================================================================

    /// HMAC-BLAKE2s-32
    /// @param key HMAC key
    /// @param data Input data
    /// @return 32-byte HMAC
    virtual Hmac hmac_blake2s(const std::vector<uint8_t>& key,
                              const std::vector<uint8_t>& data) = 0;

    /// HKDF-Extract+Expand with HMAC-BLAKE2s
    /// @param ikm input key material
    /// @param salt optional salt
    /// @param info context info
    /// @param out_len output size in bytes
    /// @return derived key bytes
    virtual std::vector<uint8_t> kdfn_hkdf_blake2s(
        const std::vector<uint8_t>& ikm, const std::vector<uint8_t>& salt,
        const std::vector<uint8_t>& info, size_t out_len) = 0;

    /// WireGuard-style Kdf1:
    /// out1 = HKDF(ck, input, "", 32)
    virtual SymmetricKey kdf1(const SymmetricKey& ck,
                              const std::vector<uint8_t>& input) = 0;

    /// WireGuard-style Kdf2:
    /// (out1, out2) = HKDF(ck, input, "", 64)
    virtual std::pair<SymmetricKey, SymmetricKey> kdf2(
        const SymmetricKey& ck, const std::vector<uint8_t>& input) = 0;

    /// WireGuard-style Kdf3:
    /// (out1, out2, out3) = HKDF(ck, input, "", 96)
    virtual std::tuple<SymmetricKey, SymmetricKey, SymmetricKey> kdf3(
        const SymmetricKey& ck, const std::vector<uint8_t>& input) = 0;

    // ========================================================================
    // Random Number Generation
    // ========================================================================

    /// Generate random bytes
    /// @param size Number of bytes to generate
    /// @return Random byte vector
    virtual std::vector<uint8_t> random_bytes(size_t size) = 0;

    /// Generate random bytes into array
    /// @param output Array to fill with random bytes
    template <size_t N>
    void fill_random(std::array<uint8_t, N>& output) {
        auto random = random_bytes(N);
        std::copy(random.begin(), random.end(), output.begin());
    }

    // ========================================================================
    // Hashing
    // ========================================================================

    /// Compute BLAKE2s hash (32-byte output)
    /// 普通BLAKE2s哈希函数
    /// @param data Input data
    /// @return Hash value (32 bytes)
    virtual Hmac blake2s(const std::vector<uint8_t>& data) = 0;

    /// keyed BLAKE2s MAC (16-byte output)
    /// BLAKE2s哈希函数的密钥化MAC变体
    /// @param key keyed BLAKE2s key
    /// @param data input data
    /// @return 16-byte MAC
    virtual Mac mac_blake2s_16(const std::vector<uint8_t>& key,
                               const std::vector<uint8_t>& data) = 0;
};

// ============================================================================
// CryptoProvider Factory
// ============================================================================

/// Create a libsodium-based crypto provider
std::unique_ptr<CryptoProvider> create_libsodium_provider();

}  // namespace wg
