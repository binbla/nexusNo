#include "../include/crypto_provider.hpp"

#include <sodium.h>

#include <cmath>
#include <cstring>
#include <stdexcept>

#include "../include/utils.hpp"

namespace wg {

namespace {

SymmetricKey as_symmetric_key(const std::vector<uint8_t>& data,
                              size_t offset = 0) {
    SymmetricKey out{};
    if (data.size() < offset + SYMMETRIC_KEY_SIZE) {
        return out;
    }
    std::copy(
        data.begin() + static_cast<std::ptrdiff_t>(offset),
        data.begin() + static_cast<std::ptrdiff_t>(offset + SYMMETRIC_KEY_SIZE),
        out.begin());
    return out;
}

std::vector<uint8_t> key_to_bytes(const SymmetricKey& key) {
    return std::vector<uint8_t>(key.begin(), key.end());
}

}  // namespace

// ============================================================================
// LibSodium CryptoProvider Implementation
// 密码学组建的具体实现，基于 libsodium 库
// ============================================================================

class LibSodiumProvider : public CryptoProvider {
   public:
    LibSodiumProvider() {
        if (sodium_init() < 0) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
    }

    ~LibSodiumProvider() override = default;

    // ========================================================================
    // Key Generation & Management
    // ========================================================================

    std::pair<PrivateKey, PublicKey> generate_static_keypair() override {
        // 生成x25519密钥对
        PublicKey pk;
        PrivateKey sk;
        crypto_kx_keypair(pk.data(), sk.data());  // Generate X25519 keypair
        return {sk, pk};
    }

    std::pair<PrivateKey, PublicKey> generate_ephemeral_keypair() override {
        // 通信过程中的临时密钥
        // Use the same keypair generation (both use Curve25519)
        return generate_static_keypair();  /// X25519 key generation is the same
                                           /// for static and ephemeral keys
    }

    PublicKey derive_public_key(const PrivateKey& private_key) override {
        // 从私钥派生公钥
        PublicKey public_key;
        // For X25519, we can derive the public key from private key
        crypto_scalarmult_base(public_key.data(), private_key.data());
        //
        return public_key;
    }

    // ========================================================================
    // Key Exchange (DH)
    // ========================================================================

    SymmetricKey dh(const PrivateKey& private_key,
                    const PublicKey& peer_public_key) override {
        SymmetricKey shared_secret;

        // Use crypto_scalarmult for X25519 key exchange
        if (crypto_scalarmult(shared_secret.data(), private_key.data(),
                              peer_public_key.data()) == 0) {
            return shared_secret;
        }

        // Return empty on failure
        SymmetricKey empty{};
        return empty;
    }

    // ========================================================================
    // Symmetric Encryption (ChaCha20-Poly1305)
    // ========================================================================

    std::vector<uint8_t> encrypt(const SymmetricKey& key, const Nonce& nonce,
                                 const std::vector<uint8_t>& plaintext,
                                 const std::vector<uint8_t>& aad) override {
        // Allocate space for ciphertext + tag
        std::vector<uint8_t> ciphertext(plaintext.size() +
                                        crypto_aead_chacha20poly1305_ABYTES);

        unsigned long long ciphertext_len = 0;

        int result = crypto_aead_chacha20poly1305_encrypt(
            ciphertext.data(), &ciphertext_len, plaintext.data(),
            plaintext.size(), aad.empty() ? nullptr : aad.data(), aad.size(),
            nullptr,  // secret (not used for AEAD)
            nonce.data(), key.data());

        if (result != 0) {
            return {};  // Return empty on error
        }

        ciphertext.resize(ciphertext_len);
        return ciphertext;
    }

    std::vector<uint8_t> decrypt(const SymmetricKey& key, const Nonce& nonce,
                                 const std::vector<uint8_t>& ciphertext,
                                 const std::vector<uint8_t>& aad) override {
        // Allocate space for plaintext
        std::vector<uint8_t> plaintext(ciphertext.size());
        unsigned long long plaintext_len = 0;

        int result = crypto_aead_chacha20poly1305_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr,  // secret (not used)
            ciphertext.data(), ciphertext.size(),
            aad.empty() ? nullptr : aad.data(), aad.size(), nonce.data(),
            key.data());

        if (result != 0) {
            return {};  // Return empty on authentication failure
        }

        plaintext.resize(plaintext_len);
        return plaintext;
    }

    std::vector<uint8_t> xencrypt(const SymmetricKey& key, const XNonce& nonce,
                                  const std::vector<uint8_t>& plaintext,
                                  const std::vector<uint8_t>& aad) override {
        std::vector<uint8_t> ciphertext(
            plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);

        unsigned long long ciphertext_len = 0;
        int result = crypto_aead_xchacha20poly1305_ietf_encrypt(
            ciphertext.data(), &ciphertext_len, plaintext.data(),
            plaintext.size(), aad.empty() ? nullptr : aad.data(), aad.size(),
            nullptr, nonce.data(), key.data());

        if (result != 0) {
            return {};
        }

        ciphertext.resize(ciphertext_len);
        return ciphertext;
    }

    std::vector<uint8_t> xdecrypt(const SymmetricKey& key, const XNonce& nonce,
                                  const std::vector<uint8_t>& ciphertext,
                                  const std::vector<uint8_t>& aad) override {
        std::vector<uint8_t> plaintext(ciphertext.size());
        unsigned long long plaintext_len = 0;

        int result = crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintext_len, nullptr, ciphertext.data(),
            ciphertext.size(), aad.empty() ? nullptr : aad.data(), aad.size(),
            nonce.data(), key.data());

        if (result != 0) {
            return {};
        }

        plaintext.resize(plaintext_len);
        return plaintext;
    }

    // ========================================================================
    // Key Derivation
    // ========================================================================

    Hmac hmac_blake2s(const std::vector<uint8_t>& key,
                      const std::vector<uint8_t>& data) override {
        constexpr size_t block_size = 64;
        std::vector<uint8_t> k = key;

        if (k.size() > block_size) {
            auto kh = blake2s(k);
            k.assign(kh.begin(), kh.end());
        }

        k.resize(block_size, 0);

        std::vector<uint8_t> o_key_pad(block_size);
        std::vector<uint8_t> i_key_pad(block_size);
        for (size_t i = 0; i < block_size; ++i) {
            o_key_pad[i] = static_cast<uint8_t>(k[i] ^ 0x5c);
            i_key_pad[i] = static_cast<uint8_t>(k[i] ^ 0x36);
        }

        std::vector<uint8_t> inner_input;
        inner_input.reserve(block_size + data.size());
        inner_input.insert(inner_input.end(), i_key_pad.begin(),
                           i_key_pad.end());
        inner_input.insert(inner_input.end(), data.begin(), data.end());
        auto inner_hash = blake2s(inner_input);

        std::vector<uint8_t> outer_input;
        outer_input.reserve(block_size + inner_hash.size());
        outer_input.insert(outer_input.end(), o_key_pad.begin(),
                           o_key_pad.end());
        outer_input.insert(outer_input.end(), inner_hash.begin(),
                           inner_hash.end());
        auto outer_hash = blake2s(outer_input);

        Hmac out;
        std::copy(outer_hash.begin(), outer_hash.end(), out.begin());
        return out;
    }

    std::vector<uint8_t> kdfn_hkdf_blake2s(const std::vector<uint8_t>& ikm,
                                           const std::vector<uint8_t>& salt,
                                           const std::vector<uint8_t>& info,
                                           size_t out_len) override {
        if (out_len == 0) {
            return {};
        }

        std::vector<uint8_t> used_salt = salt;
        if (used_salt.empty()) {
            used_salt.resize(HMAC_SIZE, 0);
        }

        Hmac prk = hmac_blake2s(used_salt, ikm);
        std::vector<uint8_t> prk_vec(prk.begin(), prk.end());

        const size_t hash_len = HMAC_SIZE;
        const size_t n = (out_len + hash_len - 1) / hash_len;
        if (n > 255) {
            return {};
        }

        std::vector<uint8_t> okm;
        okm.reserve(n * hash_len);
        std::vector<uint8_t> t;

        for (size_t i = 1; i <= n; ++i) {
            std::vector<uint8_t> input;
            input.reserve(t.size() + info.size() + 1);
            input.insert(input.end(), t.begin(), t.end());
            input.insert(input.end(), info.begin(), info.end());
            input.push_back(static_cast<uint8_t>(i));

            Hmac ti = hmac_blake2s(prk_vec, input);
            t.assign(ti.begin(), ti.end());
            okm.insert(okm.end(), t.begin(), t.end());
        }

        okm.resize(out_len);
        return okm;
    }

    SymmetricKey kdf1(const SymmetricKey& ck,
                      const std::vector<uint8_t>& input) override {
        auto okm =
            kdfn_hkdf_blake2s(input, key_to_bytes(ck), {}, SYMMETRIC_KEY_SIZE);
        return as_symmetric_key(okm);
    }

    std::pair<SymmetricKey, SymmetricKey> kdf2(
        const SymmetricKey& ck, const std::vector<uint8_t>& input) override {
        auto okm = kdfn_hkdf_blake2s(input, key_to_bytes(ck), {},
                                     SYMMETRIC_KEY_SIZE * 2);
        return {as_symmetric_key(okm, 0),
                as_symmetric_key(okm, SYMMETRIC_KEY_SIZE)};
    }

    std::tuple<SymmetricKey, SymmetricKey, SymmetricKey> kdf3(
        const SymmetricKey& ck, const std::vector<uint8_t>& input) override {
        auto okm = kdfn_hkdf_blake2s(input, key_to_bytes(ck), {},
                                     SYMMETRIC_KEY_SIZE * 3);
        return {as_symmetric_key(okm, 0),
                as_symmetric_key(okm, SYMMETRIC_KEY_SIZE),
                as_symmetric_key(okm, SYMMETRIC_KEY_SIZE * 2)};
    }

    // ========================================================================
    // Random Number Generation
    // ========================================================================

    std::vector<uint8_t> random_bytes(size_t size) override {
        std::vector<uint8_t> result(size);
        randombytes_buf(result.data(), size);
        return result;
    }

    // ========================================================================
    // Hashing
    // ========================================================================

    std::array<uint8_t, 32> blake2s(const std::vector<uint8_t>& data) override {
        std::array<uint8_t, 32> hash;
        crypto_generichash(hash.data(), hash.size(), data.data(), data.size(),
                           nullptr, 0);
        return hash;
    }

    Mac mac_blake2s_16(const std::vector<uint8_t>& key,
                       const std::vector<uint8_t>& data) override {
        Mac mac{};
        if (key.empty()) {
            return mac;
        }

        crypto_generichash(mac.data(), mac.size(), data.data(), data.size(),
                           key.data(), key.size());
        return mac;
    }
};

// ============================================================================
// Factory Function
// ============================================================================

std::unique_ptr<CryptoProvider> create_libsodium_provider() {
    return std::make_unique<LibSodiumProvider>();
}

}  // namespace wg
