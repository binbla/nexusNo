#include "../include/noise.hpp"

#include "../external/BLAKE2/sse/blake2.h"
#include "../include/crypto.hpp"
#include "mutex"
namespace wg {

bool ReplayCounter::check_and_update(uint64_t nonce) {
    if (nonce > max_seen_) {
        uint64_t shift = nonce - max_seen_;

        if (shift >= 64) {
            window_ = 0;
        } else {
            window_ <<= shift;
        }

        window_ |= 1;
        max_seen_ = nonce;
        return true;
    }

    uint64_t offset = max_seen_ - nonce;

    if (offset >= 64) {
        return false;  // 太旧
    }

    uint64_t mask = 1ULL << offset;

    if (window_ & mask) {
        return false;  // 重放
    }

    window_ |= mask;
    return true;
}
inline bool is_all_zero(std::span<const uint8_t> data) {
    for (auto b : data) {
        if (b != 0) {
            return false;
        }
    }
    return true;
}
// 初始化握手状态，设置协议通用的chaining key和handshake hash
// 这是一个语义设计上的缺陷，静态函数不能用成员变量，所以这里只能使用blake2s底层原语
// 以后再想办法优化设计。当前的思路是将密码学原语封装成一个独立的CryptoProvider类，NoiseProtocol依赖它来完成协议逻辑。这样就可以在CryptoProvider里提供一些底层原语的接口，NoiseProtocol直接调用这些接口来完成协议逻辑，而不需要在NoiseProtocol里直接使用blake2s等底层函数了。
void NoiseProtocol::init_once() {
    blake2s(handshake_init_chaining_key.data(),
            handshake_init_chaining_key.size(),
            reinterpret_cast<const uint8_t*>(handshake_name),
            sizeof(handshake_name) - 1, nullptr, 0);
    blake2s_state blake{};
    blake2s_init(&blake, handshake_init_hash.size());
    blake2s_update(&blake, handshake_init_chaining_key.data(),
                   handshake_init_chaining_key.size());
    blake2s_update(&blake, reinterpret_cast<const uint8_t*>(identifier_name),
                   sizeof(identifier_name) - 1);
    blake2s_final(&blake, handshake_init_hash.data(),
                  handshake_init_hash.size());
}

// 初始化
NoiseProtocol::NoiseProtocol(CryptoProvider& crypto,
                             const PrivateKey& local_private,
                             const PublicKey& local_public)
    : crypto_(crypto),
      local_private_(local_private),
      local_public_(local_public) {
    std::call_once(init_flag, &NoiseProtocol::init_once);
}
// 预先计算static-static DH结果，减少握手时的计算量
void NoiseProtocol::wg_noise_precompute_static_static(PrivateKey local_private,
                                                      PublicKey remote_static,
                                                      SharedSecret& out) {
    crypto_.dh(local_private, remote_static, out);
}
void NoiseProtocol::handshake_init(Handshake& hs,
                                   const PublicKey& remote_static) {
    // 仅仅是握手状态初始化，其他的hs里面的东西会在add_peer的时候就设置好了。
    // 所以这里只需要做ck和hi的初始化
    hs.clear_runtime();  // 先清空其他状态，避免残留
    hs.chaining_key = handshake_init_chaining_key;
    hs.hash = handshake_init_hash;
    mix_hash(hs.hash, remote_static);
}
bool NoiseProtocol::create_initiation(Peer& peer, HandshakeInitiation& out) {
    //
}
// 对应 WG: derive_keys(first_dst, second_dst, chaining_key)
inline void NoiseProtocol::derive_keys(DirectionalKey& first_dst,
                                       DirectionalKey& second_dst,
                                       const ChainingKey& chaining_key,
                                       uint64_t birthdate) {
    crypto_.kdf2(chaining_key, std::span<const uint8_t>{},  // data_len = 0
                 first_dst.key, second_dst.key);
    first_dst.birthdate = birthdate;
    second_dst.birthdate = birthdate;
    first_dst.is_valid = true;
    second_dst.is_valid = true;
}

// 对应 WG: mix_dh(chaining_key, key, private, public)
inline bool NoiseProtocol::mix_dh(ChainingKey& chaining_key, SymmetricKey& key,
                                  const PrivateKey& priv,
                                  const PublicKey& pub) {
    SharedSecret dh_value{};
    if (!crypto_.dh(priv, pub, dh_value)) {
        return false;
    }

    ChainingKey new_ck{};
    SymmetricKey new_key{};
    crypto_.kdf2(chaining_key, dh_value, new_ck, new_key);

    chaining_key = new_ck;
    key = new_key;
    return true;
}

// 对应 WG: mix_precomputed_dh(chaining_key, key, precomputed)
inline bool NoiseProtocol::mix_precomputed_dh(ChainingKey& chaining_key,
                                              SymmetricKey& key,
                                              const SharedSecret& precomputed) {
    if (is_all_zero(precomputed)) {
        return false;
    }
    ChainingKey new_ck{};
    SymmetricKey new_key{};
    crypto_.kdf2(chaining_key, precomputed, new_ck, new_key);

    chaining_key = new_ck;
    key = new_key;
    return true;
}

// 对应 WG: mix_hash(hash, src, src_len)
// 语义: hash = HASH(hash || src)
inline void NoiseProtocol::mix_hash(Hash& hash, std::span<const uint8_t> src) {
    // 这个操作我在密码学组件上做了一个封装。
    Bytes32 combined_prefix = hash;  // 这是 a
    // src 这是 b
    // 写到 原来的hash
    crypto_.hash2(combined_prefix, src, hash);
}

// 对应 WG: mix_psk(chaining_key, hash, key, psk)
// 语义:
//   (ck, temp_hash, key) = Kdf3(ck, psk)
//   hash = Hash(hash || temp_hash)
inline void NoiseProtocol::mix_psk(ChainingKey& chaining_key, Hash& hash,
                                   SymmetricKey& key, const SymmetricKey& psk) {
    ChainingKey new_ck{};

    // 这里第二个输出语义其实是 temp_hash，不是对称密钥。
    // 如果你当前 kdf3 还是 SymmetricKey& out2，就先用 32 字节临时块承接。
    Bytes32 temp_hash{};
    SymmetricKey new_key{};

    // 若你的 kdf3 第二个输出类型已经改成 Bytes32 / Hash / 32-byte
    // block，直接传即可。 若还没改，可以让 kdf3 暂时接受 std::span<uint8_t,32>
    // 或 Bytes32。
    crypto_.kdf3(chaining_key, psk, new_ck, temp_hash, new_key);

    chaining_key = new_ck;
    key = new_key;

    mix_hash(hash, temp_hash);
}

// 对应 WG: mix_psk(chaining_key, hash, key, psk)
// 语义:
//   (ck, temp_hash, key) = Kdf3(ck, psk)
//   hash = Hash(hash || temp_hash)
inline void NoiseProtocol::mix_psk(ChainingKey& chaining_key, Hash& hash,
                                   SymmetricKey& key, const SymmetricKey& psk) {
    ChainingKey new_ck{};
    Bytes32 temp_hash{};  // 这里第二个输出语义其实是 temp_hash
    SymmetricKey new_key{};

    crypto_.kdf3(chaining_key, psk, new_ck, temp_hash, new_key);

    chaining_key = new_ck;
    key = new_key;

    mix_hash(hash, temp_hash);
}
}  // namespace wg