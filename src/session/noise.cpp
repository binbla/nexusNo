#include "../include/noise/noise.hpp"

#include "../include/crypto/crypto.hpp"
#include "../include/types.hpp"

namespace wg::noise {
bool initialize_base(ChainingKey& base_chaining_key, Hash& base_hash) {
    // 还得包装一下 常量字符串，转换成span传给crypto层的hash函数
    // 没关系，反正这个函数只调用一次，效率不是问题。
    std::span<const uint8_t> construction_span(
        reinterpret_cast<const uint8_t*>(kNoiseConstruction),
        sizeof(kNoiseConstruction) - 1);
    std::span<const uint8_t> identifier_span(
        reinterpret_cast<const uint8_t*>(kNoiseIdentifier),
        sizeof(kNoiseIdentifier) - 1);
    // C_i
    wg::crypto::hash(construction_span, base_chaining_key);
    // H_i
    wg::crypto::hash_concat(base_chaining_key, identifier_span, base_hash);
    return true;
}
bool initialize_handshake_from_base(const Hash& base_hash,
                                    const PublicKey& responder_static,
                                    Hash& hash) {
    // H_i
    wg::crypto::hash_concat(base_hash, responder_static, hash);
    return true;
}

bool mix_hash(Hash& hash, std::span<const uint8_t> data);
void mix_key(ChainingKey& chaining_key, std::span<const uint8_t> input);
void mix_key(ChainingKey& chaining_key, SymmetricKey& key,
             std::span<const uint8_t> input);
bool mix_dh(ChainingKey& chaining_key, SymmetricKey& key,
            const PrivateKey& private_key, const PublicKey& public_key);
bool mix_precomputed_dh(ChainingKey& chaining_key, SymmetricKey& key,
                        const SharedSecret& precomputed_secret);
void mix_ephemeral(const PublicKey& ephemeral_public, ChainingKey& chaining_key,
                   Hash& hash);
bool encrypt_and_hash(std::span<uint8_t> ciphertext,
                      std::span<const uint8_t> plaintext,
                      const SymmetricKey& key, Hash& hash);
bool decrypt_and_hash(std::span<uint8_t> plaintext,
                      std::span<const uint8_t> ciphertext,
                      const SymmetricKey& key, Hash& hash);
void mix_psk(ChainingKey& chaining_key, Hash& hash, SymmetricKey& key,
             const PreSharedKey& psk);
void derive_transport_keys(ChainingKey& chaining_key, SymmetricKey& key1,
                           SymmetricKey& key2);
}  // namespace wg::noise