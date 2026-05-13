#include "include/noise/noise_protocol.hpp"

#include "include/core/index_table.hpp"
#include "include/noise/noise.hpp"
#include "include/types.hpp"

namespace wg {

bool NoiseProtocol::initialize(const PrivateKey& local_private,
                               const PublicKey& local_public) {
    if (wg::crypto::is_all_zero(local_private) ||
        wg::crypto::is_all_zero(local_public)) {
        return false;
    }
    local_private_ = local_private;
    local_public_ = local_public;

    // 预计算 base_chaining_key 和 base_hash
    if (!wg::noise::initialize_base(base_chaining_key_, base_hash_)) {
        return false;
    }

    initialized_ = true;
    return true;
}
bool NoiseProtocol::generate_identity(PrivateKey& out_private,
                                      PublicKey& out_public) {
    return wg::crypto::generate_static_keypair(out_private, out_public);
}
void NoiseProtocol::clear() {
    wg::crypto::secure_zero(local_private_);
    wg::crypto::secure_zero(local_public_);
    wg::crypto::secure_zero(base_chaining_key_);
    wg::crypto::secure_zero(base_hash_);
    initialized_ = false;
}

// 消息相关
bool NoiseProtocol::create_initiation(Peer& peer, KeypairIndex local_index,
                                      HandshakeInitiation& msg) {
    if (!initialized_) {
        return false;
    }

    // ------------------------------------------------------------
    // 初始化消息头
    // ------------------------------------------------------------
    msg.message_type = MessageType::HandshakeInitiation;
    msg.sender_index = local_index;
    msg.ephemeral_public.fill(0);
    msg.static_encrypted.fill(0);
    msg.timestamp_encrypted.fill(0);
    msg.mac1.fill(0);  // 这个交给上层去算
    msg.mac2.fill(0);

    // ------------------------------------------------------------
    // Ci := Hash(Construction)
    // Hi := Hash(Ci || Identifier)
    // Hi := Hash(Hi || Spub_r)
    // ------------------------------------------------------------

    // 初始化handshake状态 1-3
    Handshake& hs = peer.handshake();
    hs.clear_runtime();
    hs.chaining_key = base_chaining_key_;  // Ci = HASH(Construction)
    hs.hash = peer.base_hash();            // HASH(H_{init} || S^{pub}_r)

    // ------------------------------------------------------------
    // (Epriv_i, Epub_i) := DH-Generate()
    // msg.ephemeral := Epub_i
    // 4
    // ------------------------------------------------------------
    if (!crypto::generate_ephemeral_keypair(hs.ephemeral_private,     // Epriv_i
                                            msg.ephemeral_public)) {  // Epub_i
        return false;
    }

    // ------------------------------------------------------------
    // Ci := Kdf1(Ci, Epub_i)
    // Hi := Hash(Hi || msg.ephemeral)
    // 5-7
    // ------------------------------------------------------------
    noise::mix_ephemeral(msg.ephemeral_public, hs.chaining_key, hs.hash);

    SymmetricKey key{};

    // ------------------------------------------------------------
    // es:
    // (Ci, κ) := Kdf2(Ci, DH(Epriv_i, Spub_r))
    // 8
    // ------------------------------------------------------------
    if (!noise::mix_dh(hs.chaining_key, key,
                       hs.ephemeral_private,     // Epriv_i
                       peer.remote_static())) {  // Spub_r
        crypto::secure_zero(key);
        return false;
    }

    // ------------------------------------------------------------
    // msg.static := Aead(κ, 0, Spub_i, Hi)
    // Hi := Hash(Hi || msg.static)
    // 9-10
    // ------------------------------------------------------------
    if (!noise::encrypt_and_hash(msg.static_encrypted,
                                 local_public_,  // Spub_i
                                 key, hs.hash)) {
        crypto::secure_zero(key);
        return false;
    }

    // ------------------------------------------------------------
    // ss:
    // (Ci, κ) := Kdf2(Ci, DH(Spriv_i, Spub_r))
    // 11
    // ------------------------------------------------------------
    if (!noise::mix_precomputed_dh(hs.chaining_key, key,
                                   peer.precomputed_static_static())) {
        crypto::secure_zero(key);
        return false;
    }

    // ------------------------------------------------------------
    // msg.timestamp := Aead(κ, 0, Timestamp(), Hi)
    // Hi := Hash(Hi || msg.timestamp)
    // 12-13
    // ------------------------------------------------------------
    Timestamp timestamp = tai64n_now();

    if (!noise::encrypt_and_hash(msg.timestamp_encrypted, timestamp, key,
                                 hs.hash)) {
        crypto::secure_zero(key);
        return false;
    }

    // ------------------------------------------------------------
    // 保存握手状态
    // ------------------------------------------------------------
    hs.local_index = local_index;
    hs.state = HandshakeState::CreatedInitiation;
    crypto::secure_zero(key);
    return true;
}

Peer* NoiseProtocol::consume_initiation(const HandshakeInitiation& msg,
                                        PeerManager& peers) {
    if (!initialized_) return nullptr;

    SymmetricKey key{};
    PublicKey remote_static{};
    Timestamp t{};

    // ------------------------------------------------------------
    // 初始化临时 hash / chaining_key
    // ------------------------------------------------------------
    Hash hash = base_hash_;
    ChainingKey chaining_key = base_chaining_key_;

    // ------------------------------------------------------------
    // 1. 获取 msg.ephemeral
    // ------------------------------------------------------------
    const PublicKey& ephemeral = msg.ephemeral_public;

    // mix ephemeral
    noise::mix_ephemeral(ephemeral, chaining_key, hash);

    // ------------------------------------------------------------
    // 2. es = DH(local_static_private, msg.ephemeral)
    // ------------------------------------------------------------
    if (!noise::mix_dh(chaining_key, key, local_private_, ephemeral)) {
        crypto::secure_zero(key);
        return nullptr;
    }

    // ------------------------------------------------------------
    // 3. 解密静态公钥 msg.static
    // ------------------------------------------------------------
    if (!noise::decrypt_and_hash(remote_static, msg.static_encrypted, key,
                                 hash)) {
        crypto::secure_zero(key);
        return nullptr;
    }

    // ------------------------------------------------------------
    // 4. 查找 peer
    // ------------------------------------------------------------
    Peer* peer = peers.find_by_public_key(remote_static);
    if (!peer) {
        crypto::secure_zero(key);
        return nullptr;
    }

    Handshake& hs = peer->handshake();

    // ------------------------------------------------------------
    // 5. ss = mix_precomputed_dh(peer.precomputed_static_static)
    // ------------------------------------------------------------
    if (!noise::mix_precomputed_dh(chaining_key, key,
                                   peer->precomputed_static_static())) {
        crypto::secure_zero(key);
        return nullptr;
    }

    // ------------------------------------------------------------
    // 6. 解密 timestamp 并更新 replay/flood 防护
    // ------------------------------------------------------------
    if (!noise::decrypt_and_hash(t, msg.timestamp_encrypted, key, hash)) {
        crypto::secure_zero(key);
        return nullptr;
    }

    Timestamp now_ns = tai64n_now();

    // replay / flood 检查
    bool replay_attack = (t <= hs.latest_timestamp);
    bool flood_attack =
        (hs.last_initiation_consumption + kInitiationMinIntervalNs > now_ns);

    if (replay_attack || flood_attack) {
        crypto::secure_zero(key);
        return nullptr;
    }

    // ------------------------------------------------------------
    // 7. 更新 peer.handshake 状态
    // ------------------------------------------------------------
    hs.remote_ephemeral = ephemeral;
    hs.chaining_key = chaining_key;
    hs.hash = hash;
    hs.latest_timestamp = t;
    hs.remote_index = msg.sender_index;
    hs.last_initiation_consumption = now_ns;
    hs.state = HandshakeState::ConsumedInitiation;

    crypto::secure_zero(key);
    return peer;
}

// ================================================================
// NoiseProtocol::create_response
// ================================================================

bool NoiseProtocol::create_response(Peer& peer, KeypairIndex local_index,
                                    HandshakeResponse& msg) {
    if (!initialized_) return false;

    Handshake& hs = peer.handshake();
    hs.clear_runtime();

    // ------------------------------------------------------------
    // 初始化消息头
    // ------------------------------------------------------------
    msg.message_type = MessageType::HandshakeResponse;
    msg.sender_index = local_index;
    msg.receiver_index = peer.handshake().local_index;  // 对方 index
    msg.ephemeral_public.fill(0);
    msg.empty_encrypted.fill(0);
    msg.mac1.fill(0);
    msg.mac2.fill(0);

    // ------------------------------------------------------------
    // 初始化 hash / chaining_key
    // ------------------------------------------------------------
    ChainingKey& ck = hs.chaining_key;
    Hash& hash = hs.hash;
    ck = base_chaining_key_;
    hash = peer.base_hash();  // Hi = Hash(base || S_pub_i)

    // ------------------------------------------------------------
    // 生成 ephemeral keypair
    // ------------------------------------------------------------
    if (!crypto::generate_ephemeral_keypair(hs.ephemeral_private,
                                            msg.ephemeral_public)) {
        return false;
    }

    noise::mix_ephemeral(msg.ephemeral_public, ck, hash);

    SymmetricKey key{};

    // ------------------------------------------------------------
    // ee / se = DH(Epriv_r, Epub_i) & DH(Spriv_r, Epub_i)
    // ------------------------------------------------------------
    if (!noise::mix_dh(ck, key, hs.ephemeral_private, msg.ephemeral_public)) {
        crypto::secure_zero(key);
        return false;
    }

    if (!noise::mix_precomputed_dh(ck, key, peer.precomputed_static_static())) {
        crypto::secure_zero(key);
        return false;
    }

    // ------------------------------------------------------------
    // 更新 handshake 状态
    // ------------------------------------------------------------
    hs.local_index = local_index;
    hs.state = HandshakeState::CreatedResponse;
    crypto::secure_zero(key);
    return true;
}

Peer* NoiseProtocol::consume_response(const HandshakeResponse& msg,
                                      IndexTable& index_table) {
    if (!initialized_) return nullptr;

    SymmetricKey key{};
    PublicKey ephemeral = msg.ephemeral_public;

    Hash hash = base_hash_;
    ChainingKey ck = base_chaining_key_;

    // mix ephemeral
    noise::mix_ephemeral(ephemeral, ck, hash);

    // ee / se
    if (!noise::mix_dh(ck, key, local_private_, ephemeral)) {
        crypto::secure_zero(key);
        return nullptr;
    }

    // ss
    if (!noise::mix_precomputed_dh(
            ck, key,
            index_table.get_precomputed_static_static(msg.sender_index))) {
        crypto::secure_zero(key);
        return nullptr;
    }

    // 查找 peer
    Peer* peer = index_table.find_by_index(msg.sender_index);
    if (!peer) {
        crypto::secure_zero(key);
        return nullptr;
    }

    Handshake& hs = peer->handshake();
    hs.remote_ephemeral = ephemeral;
    hs.chaining_key = ck;
    hs.hash = hash;
    hs.remote_index = msg.sender_index;
    hs.state = HandshakeState::ConsumedResponse;

    crypto::secure_zero(key);
    return peer;
}
}  // namespace wg