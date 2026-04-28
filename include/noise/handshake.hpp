#ifndef HANDSHAKE_HPP
#define HANDSHAKE_HPP

#include <memory>

#include "keypair.hpp"

namespace wg {
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
}  // namespace wg

#endif  // HANDSHAKE_HPP