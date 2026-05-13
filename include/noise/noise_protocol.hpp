#ifndef NOISE_PROTOCOL_HPP
#define NOISE_PROTOCOL_HPP

#include <array>
#include <cstdint>
#include <span>

#include "core/peer.hpp"
#include "crypto/crypto.hpp"
#include "messages.hpp"
#include "noise/noise.hpp"
#include "types.hpp"
#include "utils.hpp"

namespace wg {

/// @brief Noise / WireGuard 协议处理类
///
/// 负责本地身份管理、握手消息创建和消费、以及 session key 派生。
///
/// 注意：
/**
 * - 这个类不直接实现密码学原语，所有底层操作调用 wg::crypto 和 wg::noise。
 * - 每个握手都会复制 base_chaining_key_ 和 base_hash_ 到 Handshake 状态。
 * - ephemeral keypair 每次 handshake 都会重新生成。
 * - 支持 WireGuard IK / IKpsk2 典型握手。
 */
class NoiseProtocol {
    // NoiseProtocol 负责 Noise 协议相关的所有状态和操作，包括：
    // - 本地长期密钥对（身份）
    // - 预计算的 base_chaining_key 和 base_hash
    // - 握手消息的创建和消费逻辑
    // - 从握手完成的 chaining_key 派生 transport session keys
   public:
    NoiseProtocol() = default;
    ~NoiseProtocol();

    NoiseProtocol(const NoiseProtocol&) = delete;
    NoiseProtocol& operator=(const NoiseProtocol&) = delete;

    NoiseProtocol(NoiseProtocol&&) = delete;
    NoiseProtocol& operator=(NoiseProtocol&&) = delete;

    // ------------------------------------------------------------------------
    // Initialization
    // ------------------------------------------------------------------------

    /// @brief 使用已有本地静态密钥初始化协议实例。
    /// @param local_private 本地长期私钥
    /// @param local_public 本地长期公钥
    /// @return 是否成功初始化
    ///
    /// 成功初始化后，base_chaining_key_ 和 base_hash_ 会被预计算，可用于后续
    /// handshake。
    bool initialize(const PrivateKey& local_private,
                    const PublicKey& local_public);

    /// @brief 生成新的本地静态身份并初始化协议实例。
    /// @param out_private 输出本地长期私钥
    /// @param out_public 输出本地长期公钥
    /// @return 是否成功生成身份并初始化
    bool generate_identity(PrivateKey& out_private, PublicKey& out_public);

    /// @brief 清空本地身份和 base_chaining_key/base_hash
    void clear();

    /// @brief 返回是否已初始化
    bool initialized() const { return initialized_; }

    const PrivateKey& local_private() const { return local_private_; }
    const PublicKey& local_public() const { return local_public_; }

    // 返回预计算的 base_chaining_key 和 base_hash，供外部 handshake 初始化使用
    const ChainingKey& base_chaining_key() const { return base_chaining_key_; }
    const Hash& base_hash() const { return base_hash_; }

    // ------------------------------------------------------------------------
    // 发送消息（initiator / responder）
    // ------------------------------------------------------------------------

    /// @brief 创建 handshake initiation 消息
    /// @param peer 目标 Peer 对象
    /// @param local_index 本端索引（IndexTable 分配）
    /// @param out 输出 HandshakeInitiation 消息
    /// @return 是否成功生成
    ///
    /// 对应 Noise IK：
    ///   - e / es / s / ss / {t}
    ///
    /// 使用流程：
    ///   1. 初始化 base_ck/base_hash
    ///   2. 生成 ephemeral keypair
    ///   3. mix_ephemeral -> mix_dh -> encrypt_and_hash
    ///   peer获取handshake状态，local_index由上层分配，输出消息结构体
    bool create_initiation(Peer& peer, KeypairIndex local_index,
                           HandshakeInitiation& out);

    /// @brief 创建 handshake response 消息
    /// @param peer 目标 Peer 对象
    /// @param local_index 本端索引
    /// @param out 输出 HandshakeResponse 消息
    /// @return 是否成功生成
    ///
    /// 对应 Noise IK response:
    ///   - e / ee / se / psk
    /// 如果进入了构造消息体流程，说明已经知道是谁了。
    bool create_response(Peer& peer, KeypairIndex local_index,
                         HandshakeResponse& out);

    /// @brief 创建 Cookie Reply 消息
    /// @param peer 目标 Peer 对象
    /// @param req 收到的 CookieRequest 消息
    /// @param out 输出 CookieReply 消息
    /// @return 是否成功生成
    ///
    /// 用于防止 DoS 攻击。
    // TODO
    bool create_cookie_reply(Peer& peer, const CookieRequest& req,
                             CookieReply& out);

    /// @brief 创建 Keepalive 消息
    /// @param peer 目标 Peer 对象
    /// @param out 输出 KeepaliveMessage
    /// @return 是否成功生成
    ///
    /// 用于保持 NAT/连接活跃。
    // TODO
    bool create_keepalive(Peer& peer, KeepaliveMessage& out);

    // ------------------------------------------------------------------------
    // 消费消息（接收端）
    // ------------------------------------------------------------------------

    /// @brief 消费 handshake initiation 消息
    /// @param msg 收到的 HandshakeInitiation
    /// @param peers PeerManager 对象
    /// @return 成功返回匹配的 Peer*，失败返回 nullptr
    ///
    /// 注意：
    ///   - 消费 initiation 时，先在栈上创建临时
    ///   handshake 状态
    ///   - 解密静态公钥后查找 peer
    ///   - 处理 replay/flood attack 检测
    /// 收到初始化消息，不知道对方是谁，先解密出对方的静态公钥，然后根据静态公钥查找对应的
    /// Peer。
    Peer* consume_initiation(const HandshakeInitiation& msg,
                             PeerManager& peers);

    /// @brief 消费 handshake response 消息
    /// @param msg 收到的 HandshakeResponse
    /// @param index_table IndexTable
    /// 对象，用于查找本端 handshake 状态
    /// @return 成功返回匹配的 Peer*，失败返回 nullptr
    /// 处理对方回复的消息，如果是合法的消息，那么就可以通过indextable找到之前发起握手时保存的handshake状态，继续处理消息。
    Peer* consume_response(const HandshakeResponse& msg,
                           IndexTable& index_table);

    /// @brief 消费 CookieRequest 消息
    /// @param msg 收到的 CookieRequest
    /// @param index_table IndexTable 对象
    /// @return 成功返回匹配的 Peer*，失败返回 nullptr
    /// 同理
    Peer* consume_cookie_request(const CookieRequest& msg,
                                 IndexTable& index_table);

    /// @brief 消费 Keepalive 消息
    /// @param msg 收到的 KeepaliveMessage
    /// @param peers PeerManager 对象
    /// @return 成功返回匹配的 Peer*，失败返回 nullptr
    /// 这个还没有定义
    Peer* consume_keepalive(const KeepaliveMessage& msg, PeerManager& peers);

    // ------------------------------------------------------------------------
    // 派生 Transport session keys
    // ------------------------------------------------------------------------

    /// @brief 从握手完成的 chaining_key 派生发送/接收
    /// session key
    /// @param peer Peer 对象
    /// @param am_initiator 是否为 initiator 方向
    /// @return 是否成功派生
    bool derive_transport_keys(Peer& peer, bool am_initiator);

   private:
    bool initialized_ = false;

    PrivateKey local_private_{};
    PublicKey local_public_{};

    ChainingKey base_chaining_key_{};
    Hash base_hash_{};

   private:
    // ------------------------------------------------------------------------
    // 内部辅助函数
    // ------------------------------------------------------------------------

    /// @brief 初始化 initiator 侧 handshake
    /// @param peer 目标 Peer
    /// @param hs Handshake 状态
    /// @return 是否成功
    bool initialize_initiator_handshake(Peer& peer, Handshake& hs) const;

    /// @brief 初始化 responder 侧 handshake 临时状态
    /// @param ck 临时 chaining key
    /// @param h 临时 hash
    /// @return 是否成功
    bool initialize_responder_handshake(ChainingKey& ck, Hash& h) const;

    /// @brief 检查 NoiseProtocol 是否准备好
    bool ready() const { return initialized_; }
};

}  // namespace wg

#endif  // NOISE_PROTOCOL_HPP