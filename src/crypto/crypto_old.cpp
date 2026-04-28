#include <assert.h>
#include <sodium.h>

#include <cmath>
#include <cstring>
#include <span>
#include <stdexcept>

#include "../external/BLAKE2/sse/blake2.h"
#include "../include/crypto.hpp"
#include "../include/utils.hpp"

namespace wg {

// 只提供密码学功能
// 尽量避免裸数组使用
// 跟Noise协议耦合度挺高
class SodiumCryptoProvider : public CryptoProvider {
   public:
    SodiumCryptoProvider() {
        if (sodium_init() < 0) {
            abort();
        }
    }

    inline Nonce make_wg_nonce(uint64_t counter) noexcept {
        Nonce nonce{};
        nonce[4] = static_cast<uint8_t>(counter);
        nonce[5] = static_cast<uint8_t>(counter >> 8);
        nonce[6] = static_cast<uint8_t>(counter >> 16);
        nonce[7] = static_cast<uint8_t>(counter >> 24);
        nonce[8] = static_cast<uint8_t>(counter >> 32);
        nonce[9] = static_cast<uint8_t>(counter >> 40);
        nonce[10] = static_cast<uint8_t>(counter >> 48);
        nonce[11] = static_cast<uint8_t>(counter >> 56);
        return nonce;
    }

    static uint64_t wireguard_nonce64(const Nonce& nonce) noexcept {
        // WireGuard 语义: nonce = 32-bit zero || 64-bit LE counter
        // 这里直接取后 8 字节。
        return load_le64(nonce.data() + 4);
    }

    // ===================== Key =====================
    void generate_static_keypair(PrivateKey& priv, PublicKey& pub) override {
        fill_random(priv);
        clamp_x25519_private_key(priv);
        derive_public_key(priv, pub);
    }

    void generate_ephemeral_keypair(PrivateKey& priv, PublicKey& pub) override {
        fill_random(priv);
        clamp_x25519_private_key(priv);
        derive_public_key(priv, pub);
    }

    void derive_public_key(const PrivateKey& priv, PublicKey& pub) override {
        crypto_scalarmult_base(pub.data(), priv.data());
    }

    // ===================== DH =====================

    bool dh(const PrivateKey& priv, const PublicKey& pub,
            SharedSecret& out) override {
        return crypto_scalarmult(out.data(), priv.data(), pub.data()) == 0;
    }

    // ===================== AEAD =====================
    // nonce 完全由计数器决定（非随机）WireGuard 数据包加密（data packets）

    void aead_encrypt_detached(const SymmetricKey& key, const Nonce& nonce,
                               std::span<const uint8_t> ad,
                               std::span<const uint8_t> plaintext,
                               std::span<uint8_t> ciphertext,
                               Tag& tag) override {
        assert(ciphertext.size() == plaintext.size());
        assert(is_wireguard_aead_nonce(nonce));

        unsigned long long tag_len = 0;
        const int rc = crypto_aead_chacha20poly1305_ietf_encrypt_detached(
            ptr_or_null(ciphertext), tag.data(), &tag_len,
            ptr_or_null(plaintext),
            static_cast<unsigned long long>(plaintext.size()), ptr_or_null(ad),
            static_cast<unsigned long long>(ad.size()),
            nullptr,  // nsec, unused
            nonce.data(), key.data());

        assert(rc == 0);
        assert(tag_len == TAG_SIZE);
    }

    // combined 模式，直接把 tag 附加在 ciphertext 后面，减少一次内存复制
    void aead_encrypt(const SymmetricKey& key, const Nonce& nonce,
                      std::span<const uint8_t> ad,
                      std::span<const uint8_t> plaintext,
                      std::span<uint8_t> ciphertext) override {
        assert(ciphertext.size() == plaintext.size() + TAG_SIZE);
        assert(is_wireguard_aead_nonce(nonce));

        unsigned long long ciphertext_len = 0;
        const int rc = crypto_aead_chacha20poly1305_ietf_encrypt(
            ptr_or_null(ciphertext), &ciphertext_len, ptr_or_null(plaintext),
            static_cast<unsigned long long>(plaintext.size()), ptr_or_null(ad),
            static_cast<unsigned long long>(ad.size()),
            nullptr,  // nsec, unused
            nonce.data(), key.data());

        assert(rc == 0);
        assert(ciphertext_len == ciphertext.size());
    }

    // 没有用，如果要使用就要做一些修改
    [[nodiscard]] bool aead_decrypt_detached(
        const SymmetricKey& key, const Nonce& nonce,
        std::span<const uint8_t> ad, std::span<const uint8_t> ciphertext,
        const Tag& tag, std::span<uint8_t> plaintext) override {
        if (plaintext.size() != ciphertext.size()) {
            return false;
        }
        if (!is_wireguard_aead_nonce(nonce)) {
            return false;
        }

        const int rc = crypto_aead_chacha20poly1305_ietf_decrypt_detached(
            ptr_or_null(plaintext),
            nullptr,  // nsec, unused
            ptr_or_null(ciphertext),
            static_cast<unsigned long long>(ciphertext.size()), tag.data(),
            ptr_or_null(ad), static_cast<unsigned long long>(ad.size()),
            nonce.data(), key.data());

        return rc == 0;
    }

    [[nodiscard]] bool aead_decrypt(const SymmetricKey& key, const Nonce& nonce,
                                    std::span<const uint8_t> ad,
                                    std::span<const uint8_t> ciphertext,
                                    std::span<uint8_t> plaintext) override {
        // plaintext 是上层提供的缓冲区，大小应该不会出问题。
        // 跟解密失败无关
        assert(plaintext.size() == ciphertext.size() + TAG_SIZE);
        assert(is_wireguard_aead_nonce(nonce));

        unsigned long long plaintext_len = 0;
        const int rc = crypto_aead_chacha20poly1305_ietf_decrypt(
            ptr_or_null(plaintext), &plaintext_len,
            nullptr,  // nsec, unused
            ptr_or_null(ciphertext),
            static_cast<unsigned long long>(ciphertext.size()), ptr_or_null(ad),
            static_cast<unsigned long long>(ad.size()), nonce.data(),
            key.data());
        assert(plaintext_len == plaintext.size());
        return rc == 0;
    }

    // ===================== XAEAD =====================
    // 随机 24-byte nonce 握手 / cookie / session 相关加密
    void xaead_encrypt_detached(const SymmetricKey& key, const XNonce& nonce,
                                std::span<const uint8_t> ad,
                                std::span<const uint8_t> plaintext,
                                std::span<uint8_t> ciphertext,
                                Tag& tag) override {
        assert(ciphertext.size() == plaintext.size());

        unsigned long long mac_len = 0;
        const int rc = crypto_aead_xchacha20poly1305_ietf_encrypt_detached(
            ptr_or_null(ciphertext), tag.data(), &mac_len,
            ptr_or_null(plaintext),
            static_cast<unsigned long long>(plaintext.size()), ptr_or_null(ad),
            static_cast<unsigned long long>(ad.size()),
            nullptr,  // nsec, unused
            nonce.data(), key.data());

        assert(rc == 0);
        assert(mac_len == TAG_SIZE);
    }
    void xaead_encrypt(const SymmetricKey& key, const XNonce& nonce,
                       std::span<const uint8_t> ad,
                       std::span<const uint8_t> plaintext,
                       std::span<uint8_t> ciphertext) override {
        assert(ciphertext.size() == plaintext.size());

        unsigned long long ciphertext_len = 0;
        const int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
            ptr_or_null(ciphertext), &ciphertext_len, ptr_or_null(plaintext),
            static_cast<unsigned long long>(plaintext.size()), ptr_or_null(ad),
            static_cast<unsigned long long>(ad.size()),
            nullptr,  // nsec, unused
            nonce.data(), key.data());

        assert(rc == 0);
        assert(ciphertext_len == ciphertext.size());
    }

    [[nodiscard]] bool xaead_decrypt_detached(
        const SymmetricKey& key, const XNonce& nonce,
        std::span<const uint8_t> ad, std::span<const uint8_t> ciphertext,
        const Tag& tag, std::span<uint8_t> plaintext) override {
        if (plaintext.size() != ciphertext.size()) {
            return false;
        }

        const int rc = crypto_aead_xchacha20poly1305_ietf_decrypt_detached(
            ptr_or_null(plaintext),
            nullptr,  // nsec, unused
            ptr_or_null(ciphertext),
            static_cast<unsigned long long>(ciphertext.size()), tag.data(),
            ptr_or_null(ad), static_cast<unsigned long long>(ad.size()),
            nonce.data(), key.data());

        return rc == 0;
    }
    [[nodiscard]] bool xaead_decrypt(const SymmetricKey& key,
                                     const XNonce& nonce,
                                     std::span<const uint8_t> ad,
                                     std::span<const uint8_t> ciphertext,
                                     std::span<uint8_t> plaintext) override {
        if (plaintext.size() != ciphertext.size() - TAG_SIZE) {
            return false;
        }

        unsigned long long plaintext_len = 0;
        const int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
            ptr_or_null(plaintext), &plaintext_len,
            nullptr,  // nsec, unused
            ptr_or_null(ciphertext),
            static_cast<unsigned long long>(ciphertext.size()), ptr_or_null(ad),
            static_cast<unsigned long long>(ad.size()), nonce.data(),
            key.data());
        assert(plaintext_len == plaintext.size());  // 一般不会出问题

        return rc == 0;
    }

    // ===================== Hash =====================
    inline int blake2s_span(std::span<const uint8_t> in,   // 不固定输入
                            std::span<const uint8_t> key,  // 可选密钥
                            std::span<uint8_t> out) {      // 输出
        return blake2s(out.data(), out.size(), in.data(), in.size(), key.data(),
                       key.size());
    }

    void hash(std::span<const uint8_t> data,  // 不固定输入
              Hash& out) override {           // 输出固定32字节
        blake2s_span(data, {}, out);
    }

    void hash2(std::span<const uint8_t> a, std::span<const uint8_t> b,
               Hash& out) override {
        blake2s_state blake{};
        blake2s_init(&blake, out.size());
        blake2s_update(&blake, a.data(), a.size());
        blake2s_update(&blake, b.data(), b.size());
        blake2s_final(&blake, out.data(), out.size());
    }

    void mac(std::span<const uint8_t> data,  //
             std::span<const uint8_t> key,   //
             Mac& out) override {
        // Keyed BLAKE2s
        // 带上密钥的情况下输出 16 字节的 hash
        blake2s_span(data, key, out);
    }

    // ===================== HMAC =====================

    void hmac(std::span<const uint8_t> data, std::span<const uint8_t> key,
              std::span<uint8_t, HMAC_SIZE> out) override {
        std::array<uint8_t, BLOCK_SIZE> k0{};
        std::array<uint8_t, BLOCK_SIZE> ipad{};
        std::array<uint8_t, BLOCK_SIZE> opad{};
        std::array<uint8_t, HASH_SIZE> inner_hash{};

        // 1. Normalize key
        if (key.size() > BLOCK_SIZE) {
            blake2s(k0.data(), HASH_SIZE, key.data(), key.size(), nullptr, 0);
        } else {
            std::memcpy(k0.data(), key.data(), key.size());
        }

        // 2. Compute ipad and opad
        for (size_t i = 0; i < BLOCK_SIZE; ++i) {
            ipad[i] = static_cast<uint8_t>(k0[i] ^ 0x36);
            opad[i] = static_cast<uint8_t>(k0[i] ^ 0x5c);
        }

        // 3. Inner hash: H((K ⊕ ipad) || data)
        blake2s_state st{};
        blake2s_init(&st, HASH_SIZE);
        blake2s_update(&st, ipad.data(), ipad.size());
        blake2s_update(&st, data.data(), data.size());
        blake2s_final(&st, inner_hash.data(), inner_hash.size());

        // 4. Outer hash: H((K ⊕ opad) || inner_hash)
        blake2s_init(&st, HASH_SIZE);
        blake2s_update(&st, opad.data(), opad.size());
        blake2s_update(&st, inner_hash.data(), inner_hash.size());
        blake2s_final(&st, out.data(), out.size());

        // 5. clear sensitive memory (just for security)
        std::fill(k0.begin(), k0.end(), 0);
        std::fill(ipad.begin(), ipad.end(), 0);
        std::fill(opad.begin(), opad.end(), 0);
        std::fill(inner_hash.begin(), inner_hash.end(), 0);
        std::memset(&st, 0, sizeof(st));
    }
    // ===================== KDF =====================
    // wg的实现有goto来跳过不需要的输出。
    // 那我直接实现三个输出的版本
    void kdf1(const ChainingKey& chaining_key, std::span<const uint8_t> data,
              ChainingKey& out1) override {
        static_assert(CHAINING_KEY_SIZE <= HMAC_SIZE);

        std::array<uint8_t, HMAC_SIZE> secret{};
        std::array<uint8_t, HMAC_SIZE + 1> output{};

        // Extract: secret = HMAC(chaining_key, data)
        hmac(data, chaining_key,
             std::span<uint8_t, HMAC_SIZE>(secret.data(), HMAC_SIZE));

        // Expand first key: HMAC(secret, 0x01)
        output[0] = 1;
        hmac(std::span<const uint8_t>(output.data(), 1), secret,
             std::span<uint8_t, HMAC_SIZE>(output.data(), HMAC_SIZE));

        std::memcpy(out1.data(), output.data(), out1.size());
    }

    void kdf2(const ChainingKey& chaining_key, std::span<const uint8_t> data,
              ChainingKey& out1, SymmetricKey& out2) override {
        static_assert(CHAINING_KEY_SIZE <= HMAC_SIZE);
        static_assert(SYMMETRIC_KEY_SIZE <= HMAC_SIZE);

        std::array<uint8_t, HMAC_SIZE> secret{};
        std::array<uint8_t, HMAC_SIZE + 1> output{};

        // Extract: secret = HMAC(chaining_key, data)
        hmac(data, chaining_key,
             std::span<uint8_t, HMAC_SIZE>(secret.data(), HMAC_SIZE));

        // Expand first key: HMAC(secret, 0x01)
        output[0] = 1;
        hmac(std::span<const uint8_t>(output.data(), 1), secret,
             std::span<uint8_t, HMAC_SIZE>(output.data(), HMAC_SIZE));
        std::memcpy(out1.data(), output.data(), out1.size());

        // Expand second key: HMAC(secret, first_key || 0x02)
        output[HMAC_SIZE] = 2;
        hmac(std::span<const uint8_t>(output.data(), HMAC_SIZE + 1), secret,
             std::span<uint8_t, HMAC_SIZE>(output.data(), HMAC_SIZE));
        std::memcpy(out2.data(), output.data(), out2.size());
    }

    void kdf3(const ChainingKey& chaining_key, std::span<const uint8_t> data,
              ChainingKey& out1, Bytes32& out2, SymmetricKey& out3) override {
        static_assert(CHAINING_KEY_SIZE <= HMAC_SIZE);
        static_assert(SYMMETRIC_KEY_SIZE <= HMAC_SIZE);

        std::array<uint8_t, HMAC_SIZE> secret{};
        std::array<uint8_t, HMAC_SIZE + 1> output{};

        // Extract: secret = HMAC(chaining_key, data)
        hmac(data, chaining_key,
             std::span<uint8_t, HMAC_SIZE>(secret.data(), HMAC_SIZE));

        // Expand first key: HMAC(secret, 0x01)
        output[0] = 1;
        hmac(std::span<const uint8_t>(output.data(), 1), secret,
             std::span<uint8_t, HMAC_SIZE>(output.data(), HMAC_SIZE));
        std::memcpy(out1.data(), output.data(), out1.size());

        // Expand second key: HMAC(secret, first_key || 0x02)
        output[HMAC_SIZE] = 2;
        hmac(std::span<const uint8_t>(output.data(), HMAC_SIZE + 1), secret,
             std::span<uint8_t, HMAC_SIZE>(output.data(), HMAC_SIZE));
        std::memcpy(out2.data(), output.data(), out2.size());

        // Expand third key: HMAC(secret, second_key || 0x03)
        output[HMAC_SIZE] = 3;
        hmac(std::span<const uint8_t>(output.data(), HMAC_SIZE + 1), secret,
             std::span<uint8_t, HMAC_SIZE>(output.data(), HMAC_SIZE));
        std::memcpy(out3.data(), output.data(), out3.size());
    }
    // ===================== RNG =====================

    void random_bytes(std::span<uint8_t> out) override {
        randombytes_buf(out.data(), out.size());
    }

   private:
    // ===================== Internal Helpers =====================
    static_assert(SYMMETRIC_KEY_SIZE ==
                  crypto_aead_chacha20poly1305_ietf_KEYBYTES);
    static_assert(SYMMETRIC_KEY_SIZE ==
                  crypto_aead_xchacha20poly1305_ietf_KEYBYTES);

    static_assert(NONCE_SIZE == crypto_aead_chacha20poly1305_ietf_NPUBBYTES);
    static_assert(XNONCE_SIZE == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    static_assert(TAG_SIZE == crypto_aead_chacha20poly1305_ietf_ABYTES);
    static_assert(TAG_SIZE == crypto_aead_xchacha20poly1305_ietf_ABYTES);

    static const unsigned char* ptr_or_null(
        std::span<const uint8_t> s) noexcept {
        return s.empty() ? nullptr : s.data();
    }

    static unsigned char* ptr_or_null(std::span<uint8_t> s) noexcept {
        return s.empty() ? nullptr : s.data();
    }

    static bool is_wireguard_aead_nonce(const Nonce& nonce) noexcept {
        return nonce[0] == 0 && nonce[1] == 0 && nonce[2] == 0 && nonce[3] == 0;
    }

    static void clamp_x25519_private_key(PrivateKey& priv) {
        priv[0] &= 248;
        priv[31] &= 127;
        priv[31] |= 64;
    }

    static bool is_all_zero(std::span<const uint8_t> data) {
        uint8_t acc = 0;
        for (uint8_t b : data) {
            acc |= b;
        }
        return acc == 0;
    }
    static uint64_t load_le64(const uint8_t* p) noexcept {
        return (static_cast<uint64_t>(p[0])) |
               (static_cast<uint64_t>(p[1]) << 8) |
               (static_cast<uint64_t>(p[2]) << 16) |
               (static_cast<uint64_t>(p[3]) << 24) |
               (static_cast<uint64_t>(p[4]) << 32) |
               (static_cast<uint64_t>(p[5]) << 40) |
               (static_cast<uint64_t>(p[6]) << 48) |
               (static_cast<uint64_t>(p[7]) << 56);
    }
};

// ===================== Factory =====================

std::unique_ptr<CryptoProvider> create_libsodium_provider() {
    return std::make_unique<SodiumCryptoProvider>();
}

}  // namespace wg
