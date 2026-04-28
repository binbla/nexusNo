#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

#include "crypto.hpp"
#include "endpoint.hpp"
#include "message.hpp"
#include "peer.hpp"
#include "utils.hpp"
// bytes，Noise协议的构造字符串，这里包含了\0所以使用sizeof的时候要-1
// 静态编译期计算，不操心效率问题
constexpr const uint8_t* handshake_name =
    "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";  // 37

constexpr const uint8_t* identifier_name =
    "WireGuard v1.x binbla admin@binbla.com";  // 38

/*
noise 协议的操作对象好像也就那么几个，time, ck, key, hash, ...

*/
namespace wg {
// Receiver index type used in messages
using KeypairIndex = uint32_t;

class ReplayCounter {
    // 简单的滑动窗口实现，假设乱序不会超过 64 个包
   public:
    bool check_and_update(uint64_t nonce);

    void clear() {
        max_seen_ = 0;
        window_ = 0;
    }

   private:
    uint64_t max_seen_ = 0;
    uint64_t window_ = 0;  // 简化版 64-bit 滑动窗口
};

struct DirectionalKey {
    // 密钥
    SymmetricKey key{};
    uint64_t birthdate = 0;  // 通常用 steady_clock/ns
    bool is_valid = false;
};

struct Keypair {
    /*
    Keypair 指定了一个session
    key的生命周期和状态，包含发送和接收两个方向的密钥，以及相关的计数器和索引信息。
    它是Noise协议中一个重要的抽象，用于管理会话密钥的更新和过期。
    */
    // 密钥 这是双方在本轮会话中使用的密钥，发送和接收方向不同
    DirectionalKey sending;
    DirectionalKey receiving;
    // 计数器
    uint64_t created_at = 0;  // keypair 创建时间，单位 ns
    std::atomic<uint64_t> sending_counter = 0;
    ReplayCounter replay;
    // 双端索引
    KeypairIndex local_index = 0;
    KeypairIndex remote_index = 0;
    // 是否是发起者
    bool i_am_the_initiator = false;
    bool can_send() const { return sending.is_valid; }
    bool can_receive() const { return receiving.is_valid; }

    void invalidate_sending() { sending.is_valid = false; }
    void invalidate_receiving() { receiving.is_valid = false; }

    void clear_counters() {
        sending_counter = 0;
        replay.clear();
    }
};

class KeypairManager {
    // 三个 keypair 插槽：current/previous/next
   public:
    using Ptr = std::shared_ptr<Keypair>;

    Ptr current() const { return current_; }
    Ptr previous() const { return previous_; }
    Ptr next() const { return next_; }

    void clear() {
        current_.reset();
        previous_.reset();
        next_.reset();
    }

    // - initiator: 新 keypair 直接进入 current
    // - responder: 新 keypair 先进入 next，等待首个 data 包确认
    void install_new(Ptr kp) {
        if (!kp) return;

        if (kp->i_am_the_initiator) {
            if (next_) {
                // WG 的逻辑：
                // 如果已有 next，则 next -> previous，current 被丢弃
                previous_ = next_;
                next_.reset();
                current_.reset();
            } else {
                // 没有 next，则 current -> previous
                previous_ = current_;
            }
            current_ = std::move(kp);
        } else {
            // responder: 新 key 先放 next
            next_ = std::move(kp);
            previous_.reset();
        }
    }

    // 收到用 next keypair 解密成功的首个 transport 包后调用
    // 返回 true 表示发生了 next -> current 提升
    bool confirm_if_next(const Ptr& used) {
        if (!used || !next_ || used != next_) {
            return false;
        }

        previous_ = current_;
        current_ = next_;
        next_.reset();
        return true;
    }

    // 对应 WG 的 expire_current_peer_keypairs 中的 sending invalid 语义
    void expire_current_sending() {
        if (next_) {
            next_->invalidate_sending();
        }
        if (current_) {
            current_->invalidate_sending();
        }
    }

    bool has_current() const {
        return static_cast<bool>(current_) && current_->can_send();
    }

   private:
    Ptr current_;
    Ptr previous_;
    Ptr next_;
};

enum class HandshakeState {
    Zeroed,
    CreatedInitiation,
    ConsumedInitiation,
    CreatedResponse,
    ConsumedResponse,
};

struct Handshake {
    // 当前握手状态
    HandshakeState state = HandshakeState::Zeroed;

    KeypairIndex local_index = 0;   // 本端索引
    KeypairIndex remote_index = 0;  // 对端索引：对方包里的 sender_index

    // Noise 握手中间状态
    // 初始化之后就完成固定
    PublicKey remote_static{};     // 对端长期公钥
    SymmetricKey preshared_key{};  // 可选的预共享密钥

    // 在clear_runtime的时候会被清空
    PrivateKey ephemeral_private{};  // 本地临时私钥
    PublicKey remote_ephemeral{};    // 对端临时公钥

    // Noise 协议的状态变量，跟握手消息的处理密切相关
    Hash hash{};                 // h
    ChainingKey chaining_key{};  // ck

    // 用于 initiation replay protection
    Timestamp latest_timestamp{};
    // 用于 initiation flood control
    Timestamp last_initiation_consumption{};
    // -------- helper --------

    void clear_runtime() {
        ephemeral_private.fill(0);
        remote_ephemeral.fill(0);
        hash.fill(0);
        chaining_key.fill(0);

        local_index = 0;
        remote_index = 0;
        state = HandshakeState::Zeroed;
    }

    void init_for_peer(const PublicKey& remote_pub,
                       const SymmetricKey& psk = {}) {
        clear_runtime();
        remote_static = remote_pub;
        preshared_key = psk;
    }

    bool is_zeroed() const { return state == HandshakeState::Zeroed; }

    bool can_create_response() const {
        return state == HandshakeState::ConsumedInitiation;
    }

    bool can_consume_response() const {
        return state == HandshakeState::CreatedInitiation;
    }

    bool can_begin_session() const {
        return state == HandshakeState::CreatedResponse ||
               state == HandshakeState::ConsumedResponse;
    }
};

class NoiseProtocol {
   public:
    NoiseProtocol(
        CryptoProvider& crypto, const PrivateKey& local_private,
        const PublicKey&
            local_public);  // 注意完成handshake_init_chaining_key和handshake_init_hash的初始化

    // 预先计算secret_static-static DH结果，存到peer里，减少握手时的计算量
    void wg_noise_precompute_static_static(PrivateKey local_private,
                                           PublicKey remote_static,
                                           SharedSecret& out);
    void handshake_init(Handshake& hs);
    void handshake_init(ChainingKey& ck, Hash& hash,
                        const PublicKey& remote_static);  // 重载版本

    // 握手 第一条
    bool create_initiation(Peer& peer, KeypairIndex local_index,
                           HandshakeInitiation& out);
    Peer* consume_initiation(const HandshakeInitiation& msg,
                             PeerManager& peers);

    // 握手 第二条
    bool create_response(Peer& peer, HandshakeResponse& out);
    bool consume_response(Peer& peer, const HandshakeResponse& msg);

    // 握手 第三条 带cookie的response
    bool create_cookie_response(Peer& peer, CookieReply& out);
    bool consume_cookie_response(Peer& peer, const CookieReply& msg);

    // 握手完成
    std::shared_ptr<Keypair> begin_session(Peer& peer,
                                           KeypairIndex local_index);

    // 加密和解密 transport 消息
    bool encrypt_transport(Keypair& kp, std::span<const uint8_t> plaintext,
                           TransportData& out);

    bool decrypt_transport(Keypair& kp, const TransportData& msg,
                           std::vector<uint8_t>& plaintext);

   private:
    // 密码学组件
    CryptoProvider& crypto_;
    // 自己的身份
    PrivateKey local_private_;
    PublicKey local_public_;
    // 预先计算的握手初始状态，WG协议里是全局唯一的
    static inline std::once_flag init_flag;
    static inline ChainingKey handshake_init_chaining_key{};
    static inline Hash handshake_init_hash{};

   private:
    static void init_once();
    void derive_keys(DirectionalKey& first_dst, DirectionalKey& second_dst,
                     const ChainingKey& chaining_key, uint64_t birthdate);

    void mix_hash(Hash& hash, std::span<const uint8_t> src);
    bool mix_dh(ChainingKey& ck, SymmetricKey& key, const PrivateKey& priv,
                const PublicKey& pub);
    bool mix_precomputed_dh(ChainingKey& ck, SymmetricKey& key,
                            const SharedSecret& precomputed);
    void mix_psk(ChainingKey& ck, Hash& hash, SymmetricKey& key,
                 const SymmetricKey& psk);

    void message_ephemeral(PublicKey& dst, const PublicKey& src,
                           ChainingKey& ck, Hash& hash);

    void message_encrypt(std::span<uint8_t> dst_ciphertext,
                         std::span<const uint8_t> src_plaintext,
                         SymmetricKey& key, Hash& hash);

    bool message_decrypt(std::span<uint8_t> dst_plaintext,
                         std::span<const uint8_t> src_ciphertext,
                         SymmetricKey& key, Hash& hash);
};
}  // namespace wg