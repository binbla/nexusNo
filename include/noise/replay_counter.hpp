#ifndef REPLAY_COUNTER_HPP
#define REPLAY_COUNTER_HPP

#include <cstdint>

namespace wg {

class ReplayCounter {
   public:
    static constexpr uint64_t kWindowSize = 64;

    ReplayCounter() = default;

    /// 只检查 nonce 是否可能被接受，不更新窗口状态。
    ///
    /// 用途：
    ///   可以在 AEAD 解密前做快速过滤，丢弃明显太旧或明显重复的包。
    ///
    /// 注意：
    ///   may_accept() 不能替代 check_and_update()。
    ///   真正更新 replay window 必须发生在 AEAD 认证成功之后。
    bool may_accept(uint64_t nonce) const {
        if (!initialized_) {
            return true;
        }

        if (nonce > max_seen_) {
            return true;
        }

        const uint64_t diff = max_seen_ - nonce;

        if (diff >= kWindowSize) {
            return false;
        }

        const uint64_t mask = 1ULL << diff;
        return (window_ & mask) == 0;
    }

    /// 检查并更新 replay window。
    ///
    /// 返回：
    ///   true  表示 nonce 未重放，可以接受，并且已经更新窗口。
    ///   false 表示 nonce 太旧或已经见过，应丢弃。
    ///
    /// 重要：
    ///   这个函数应该在 AEAD 解密认证成功后调用。
    ///   不要在认证前调用，否则攻击者可以用伪造的大 nonce 推进窗口，
    ///   导致后续真实包被误判为太旧。
    bool check_and_update(uint64_t nonce) {
        if (!initialized_) {
            initialized_ = true;
            max_seen_ = nonce;
            window_ = 1ULL;
            return true;
        }

        if (nonce > max_seen_) {
            const uint64_t shift = nonce - max_seen_;

            if (shift >= kWindowSize) {
                window_ = 1ULL;
            } else {
                window_ <<= shift;
                window_ |= 1ULL;
            }

            max_seen_ = nonce;
            return true;
        }

        const uint64_t diff = max_seen_ - nonce;

        if (diff >= kWindowSize) {
            return false;
        }

        const uint64_t mask = 1ULL << diff;

        if ((window_ & mask) != 0) {
            return false;
        }

        window_ |= mask;
        return true;
    }

    /// 清空 replay 状态。
    ///
    /// 应在 session/keypair 更换、重新握手、连接重置时调用。
    void clear() {
        initialized_ = false;
        max_seen_ = 0;
        window_ = 0;
    }

    /// 当前是否已经见过至少一个 nonce。
    bool initialized() const { return initialized_; }

    /// 当前见过的最大 nonce。
    ///
    /// 只有 initialized() 为 true 时才有实际意义。
    uint64_t max_seen() const { return max_seen_; }

    /// 当前窗口 bitmap。
    ///
    /// 调试用：
    ///   bit 0  表示 max_seen_
    ///   bit 1  表示 max_seen_ - 1
    ///   ...
    ///   bit 63 表示 max_seen_ - 63
    uint64_t window() const { return window_; }

   private:
    bool initialized_ = false;
    uint64_t max_seen_ = 0;
    uint64_t window_ = 0;
};

}  // namespace wg

#endif  // REPLAY_COUNTER_HPP