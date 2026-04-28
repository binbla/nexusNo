#ifndef KEYPAIR_HPP
#define KEYPAIR_HPP

#include <atomic>
#include <memory>

#include "../include/types.hpp"
#include "replay_counter.hpp"

namespace wg {

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
}  // namespace wg
#endif