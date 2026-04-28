#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>

#include "noise.hpp"

namespace wg {

struct PeerConfig {
    PublicKey remote_static;
    PreSharedKey preshared_key{};
    std::optional<Endpoint> endpoint;
};
class Peer {
    // 单个peer下面挂一个handshake和一套keypair manager
    // handshake里面放静态身份和
   public:
    explicit Peer(const PeerConfig& config)
        : remote_static_(config.remote_static),
          preshared_key_(config.preshared_key),
          endpoint_(config.endpoint) {}

    // -------- identity / config --------

    const PublicKey& remote_static() const { return remote_static_; }
    const PreSharedKey& preshared_key() const { return preshared_key_; }
    void set_preshared_key(const PreSharedKey& psk) { preshared_key_ = psk; }

    // -------- endpoint --------

    const std::optional<Endpoint>& endpoint() const { return endpoint_; }
    void set_endpoint(const Endpoint& ep) { endpoint_ = ep; }
    void clear_endpoint() { endpoint_.reset(); }

    // -------- handshake / keypairs --------

    const SharedSecret precomputed_static_static() const {
        return precomputed_static_static_;
    }
    void set_precomputed_static_static(const SharedSecret&);
    Handshake& handshake() { return handshake_; }  // 返回的是引用，方便外部修改
    KeypairManager& keypairs() { return keypairs_; }

   private:
    // peer 的长期身份信息 自己存一个，hs还要存一个。
    PublicKey remote_static_{};     // 跟Handshake重复了
    PreSharedKey preshared_key_{};  // 跟Handshake重复了
    std::optional<Endpoint> endpoint_;

    // 与 peer 绑定的长期预计算缓存
    // 提前计算
    SharedSecret precomputed_static_static_{};

    // 运行时状态 Handshake 和 KeypairManager
    Handshake handshake_;  // 静态分配空间，避免后续频繁new/delete
    KeypairManager keypairs_;

    // ===== state =====
    std::atomic<uint64_t> last_handshake_time{0};  // ns

    // ===== keepalive =====
    uint16_t keepalive_interval = 0;

    // ===== stats =====
    uint64_t tx_bytes = 0;
    uint64_t rx_bytes = 0;

    // ===== runtime =====

    bool is_alive = true;
};

class PeerManager {
   public:
    // 提供查找、添加、删除peer的接口
    Peer* find_by_public_key(const PublicKey& key);
    void add_peer(std::unique_ptr<Peer> peer);  // 同时具备update
    void remove_peer(const PublicKey& key);

   private:
    std::map<PublicKey, std::unique_ptr<Peer>> peers_;
};
}  // namespace wg