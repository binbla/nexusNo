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
void NoiseProtocol::handshake_init(ChainingKey& ck, Hash& hash,
                                   const PublicKey& remote_static) {
    ck = handshake_init_chaining_key;
    hash = handshake_init_hash;
    mix_hash(hash, remote_static);
}  // 这玩意儿就是self版本的啊，也能预计算

// 对应 WG: derive_keys(first_dst,
// second_dst, chaining_key)
inline void NoiseProtocol::derive_keys(DirectionalKey& first_dst,
                                       DirectionalKey& second_dst,
                                       const ChainingKey& chaining_key,
                                       uint64_t birthdate) {
    crypto_.kdf2(chaining_key, std::span<const uint8_t>{},  // data_len
                                                            // = 0
                 first_dst.key, second_dst.key);
    first_dst.birthdate = birthdate;
    second_dst.birthdate = birthdate;
    first_dst.is_valid = true;
    second_dst.is_valid = true;
}

// 对应 WG: mix_dh(chaining_key, key,
// private, public)
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

// 对应 WG: mix_precomputed_dh(chaining_key,
// key, precomputed)
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

// 对应 WG: mix_psk(chaining_key, hash, key,
// psk) 语义:
//   (ck, temp_hash, key) = Kdf3(ck, psk)
//   hash = Hash(hash || temp_hash)
inline void NoiseProtocol::mix_psk(ChainingKey& chaining_key, Hash& hash,
                                   SymmetricKey& key, const SymmetricKey& psk) {
    ChainingKey new_ck{};
    Bytes32 temp_hash{};  // 这里第二个输出语义其实是
                          // temp_hash
    SymmetricKey new_key{};

    crypto_.kdf3(chaining_key, psk, new_ck, temp_hash, new_key);

    chaining_key = new_ck;
    key = new_key;

    mix_hash(hash, temp_hash);
}

// 用密码学组件的AEAD 处理消息
void NoiseProtocol::message_encrypt(std::span<uint8_t> dst_ciphertext,
                                    std::span<const uint8_t> src_plaintext,
                                    SymmetricKey& key, Hash& hash) {
    crypto_.aead_encrypt(key, Nonce{}, hash, src_plaintext, dst_ciphertext);
    mix_hash(hash, dst_ciphertext);
}
bool NoiseProtocol::message_decrypt(std::span<uint8_t> dst_plaintext,
                                    std::span<const uint8_t> src_ciphertext,
                                    SymmetricKey& key, Hash& hash) {
    if (crypto_.aead_decrypt(key, Nonce{}, hash, src_ciphertext, dst_plaintext))
        return false;
    mix_hash(hash, src_ciphertext);
    return true;
}

void NoiseProtocol::message_ephemeral(PublicKey& dst, const PublicKey& src,
                                      ChainingKey& ck, Hash& hash) {
    dst = src;
    mix_hash(hash, dst);
    mix_dh(ck, dst, local_private_, dst);
}

/* Noise 这里只管填写
type
sender_index
unencrypted_ephemeral
encrypted_static
encrypted_timestamp

MAC1/2都是cookie去填
*/
bool NoiseProtocol::create_initiation(Peer& peer, KeypairIndex local_index,
                                      HandshakeInitiation& out) {
    /*
    peer 拥有 远端的信息、hs、keypair
    manager等状态 local_index
    是本地的索引，放在消息里让对方知道，由core创建
    out 是要填充的消息结构体
    handshake_init->e->es->s->ss->{ t }

    ch和h是一直在变的，eph_priv是本地生成的临时私钥，eph_pub是对应的临时公钥

    */

    auto& hs = peer.handshake();

    // 1. 初始化消息头
    out.message_type = MessageType::HandshakeInitiation;
    out.sender_index = 0;
    out.ephemeral_public.fill(0);
    out.static_encrypted.fill(0);
    out.timestamp_encrypted.fill(0);
    out.mac1.fill(0);
    out.mac2.fill(0);

    // 2. 初始化 handshake state
    handshake_init(hs, peer.remote_static());
    // hs.hash = init_hash; hs.chaining_key =
    // init_ck; mix_hash(hs.hash,
    // hs.remote_static);

    // 3. 生成本地 ephemeral keypair
    // （E_i^{priv}, E_i^{pub}） =
    // DH-Generate()
    // TODO 后续优化，删掉临时变量
    PrivateKey eph_priv{};
    PublicKey eph_pub{};
    crypto_.generate_ephemeral_keypair(eph_priv, eph_pub);

    // 把临时密钥放到握手状态里，后面计算DH和消息认证码都要用
    hs.ephemeral_private = eph_priv;
    // msg.ephemeral = E_i^{pub}
    out.ephemeral_public = eph_pub;

    // 4. e
    // ck = Kdf1(ck, Ei_pub)
    // h = Hash(h || Ei_pub)
    message_ephemeral(out.ephemeral_public, out.ephemeral_public,
                      hs.chaining_key, hs.hash);

    // 5. es
    // (ck, key) = mix_dh(ck, e_priv, rs)
    SymmetricKey key{};
    if (!mix_dh(hs.chaining_key, key, hs.ephemeral_private, hs.remote_static)) {
        return false;
    }

    // 6. s
    // msg.static_encrypted = AEAD(key, h,
    // local_public)
    message_encrypt(out.static_encrypted, local_public_, key, hs.hash);

    // 7. ss
    // (ck, key) = kdf2(ck, secret)
    if (!mix_precomputed_dh(hs.chaining_key, key,
                            peer.precomputed_static_static())) {
        return false;
    }

    // 8. {t}
    // h = Hash(h || {t})
    Timestamp timestamp = tai64n_now();
    message_encrypt(out.timestamp_encrypted, timestamp, key, hs.hash);

    // 9. 记录本端索引
    hs.local_index = local_index;
    out.sender_index = local_index;  // sender_index
                                     // 是发起者的索引，放在消息里让对方知道

    // 10. 状态推进
    hs.state = HandshakeState::CreatedInitiation;
    return true;
}

Peer* NoiseProtocol::consume_initiation(const HandshakeInitiation& msg,
                                        PeerManager peers) {
    // 临时工作状态：先在栈上算完，再一次性提交到
    // peer.handshake
    SymmetricKey key{};  // 中间输出
    PublicKey s{};       // 对方的静态公钥，要decrypt出来
    PublicKey e{};       // 对方的临时公钥，直接从消息里拿出来就行
    Timestamp t{};       // 对方的时间戳，要decrypt出来

    Handshake temp_hs{};  // 用一个空白的握手开始
    // 1. 初始化临时 handshake 状态
    // 对 responder
    // 来说，这里传的是“本地静态公钥”
    // 初始化成对端的样子，应该可以写成一个常量，以后就直接做内存拷贝
    handshake_init(temp_hs,
                   local_public_);  // 初始化ck和h

    // 2. e
    e = msg.ephemeral_public;  // 取出公钥e
    message_ephemeral(e, e, temp_hs.chaining_key,
                      temp_hs.hash);  // mix e 到 hash 和
                                      // chaining_key

    // 3. es = DH(Sr_priv, Ei_pub)
    // 取得了对方ephemeral公钥，同时我们有自己的私钥，就可以计算出
    // DH
    // 结果了，这个结果是后续解密和认证的基础
    if (!mix_dh(temp_hs.chaining_key, key, local_private_, e)) {
        return nullptr;
    }

    // 如果这个步骤失败了，说明对方发来的消息有问题，直接丢弃。
    // 4. s = decrypt(encrypted_static)
    // 这是求解对方的公钥
    if (!message_decrypt(std::span<uint8_t>(s.data(), s.size()),
                         std::span<const uint8_t>(msg.static_encrypted.data(),
                                                  msg.static_encrypted.size()),
                         key, temp_hs.hash)) {
        return nullptr;
    }

    // 5. 用解出的静态公钥查 peer
    Peer* peer = peers.find_by_public_key(s);
    if (!peer) {
        return nullptr;  // 没找到，消息无效，直接丢弃
    }

    // 找到了就填充handshake
    auto& hs = peer->handshake();

    // 6. ss = precomputed DH(Sr_priv,
    // Si_pub)
    if (!mix_precomputed_dh(temp_hs.chaining_key, key,
                            peer->precomputed_static_static())) {
        return nullptr;
    }

    // 7. {t} = decrypt(encrypted_timestamp)
    // 取出对方的时间戳，准备做 replay attack
    // 检测
    if (!message_decrypt(
            std::span<uint8_t>(t.data(), t.size()),
            std::span<const uint8_t>(msg.timestamp_encrypted.data(),
                                     msg.timestamp_encrypted.size()),
            key, temp_hs.hash)) {
        return nullptr;
    }
    Timestamp now_ns = tai64n_now();
    // 8. replay / flood 检查
    const bool replay_attack =
        std::memcmp(t.data(), hs.latest_timestamp.data(), t.size()) <= 0;

    const bool flood_attack =
        hs.last_initiation_consumption + kInitiationMinIntervalNs > now_ns;

    if (replay_attack || flood_attack) {
        return nullptr;
    }

    // 9. 成功后，一次性提交到 peer.handshake
    hs.remote_ephemeral = e;

    if (std::memcmp(t.data(), hs.latest_timestamp.data(), t.size()) > 0) {
        hs.latest_timestamp = t;
    }

    hs.hash = hash;
    hs.chaining_key = chaining_key;
    hs.remote_index = src.sender_index;

    if (hs.last_initiation_consumption < now_ns) {
        hs.last_initiation_consumption = now_ns;
    }

    hs.state = HandshakeState::ConsumedInitiation;
    return peer;
};
}  // namespace wg