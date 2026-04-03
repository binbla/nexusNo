#pragma once

#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "network.hpp"
#include "types.hpp"

namespace wg {

struct CoreConfig {
    SelfIdentity identity{};
    std::string listen_address;
    uint16_t listen_port = 0;
};

struct CoreCallbacks {
    std::function<void(const Peer&)> on_peer_added;
    std::function<void(const Peer&)> on_peer_removed;
    std::function<void(const Peer&)> on_peer_updated;
    std::function<void(const Peer&, const Session&)> on_session_installed;
    std::function<void(const Peer&, const Session&)> on_session_removed;
    std::function<void(const Peer&, const Endpoint&)> on_endpoint_updated;
    std::function<void(const Peer&, const Endpoint&,
                       const std::vector<uint8_t>&)>
        on_transport_packet;
};

class Core {
   public:
    explicit Core(std::unique_ptr<CryptoProvider> crypto_provider);
    ~Core();

    Core(const Core&) = delete;
    Core& operator=(const Core&) = delete;
    Core(Core&&) = delete;
    Core& operator=(Core&&) = delete;

    bool initialize(const CoreConfig& config);
    void shutdown();

    [[nodiscard]] bool is_initialized() const;

    void set_callbacks(CoreCallbacks callbacks);

    PeerId add_peer(const PublicKey& remote_static_public_key,
                    std::optional<Endpoint> endpoint = std::nullopt);
    bool update_peer_endpoint(PeerId peer_id,
                              const std::optional<Endpoint>& endpoint);
    bool remove_peer(PeerId peer_id);

    Peer* find_peer(PeerId peer_id);
    const Peer* find_peer(PeerId peer_id) const;
    Peer* find_peer(const PublicKey& remote_static_public_key);
    const Peer* find_peer(const PublicKey& remote_static_public_key) const;

    std::vector<PeerId> list_peer_ids() const;

    SessionInstallResult install_session(PeerId peer_id, SessionPtr session);
    bool remove_session(SessionIndex local_index);

    Session* find_session(SessionIndex local_index);
    const Session* find_session(SessionIndex local_index) const;

    bool on_udp_packet(const std::vector<uint8_t>& packet,
                       const Endpoint& source);
    void poll(uint64_t now_ms);

    UdpSocket& socket();
    const UdpSocket& socket() const;

    const SelfIdentity& local_identity() const;

   private:
    std::unique_ptr<CryptoProvider> crypto_provider_;
    UdpSocket socket_;
    CoreConfig config_{};
    CoreCallbacks callbacks_{};
    bool initialized_ = false;
    PeerId next_peer_id_ = 1;

    std::unordered_map<PeerId, std::shared_ptr<Peer>> peers_by_id_;
    std::map<PublicKey, PeerId> peer_ids_by_public_key_;
    std::unordered_map<SessionIndex, SessionPtr> sessions_by_index_;

    PeerId allocate_peer_id();
    SessionIndex allocate_session_index();
    bool store_session_index(const SessionPtr& session);
    void remove_peer_sessions(const Peer& peer);
    static uint64_t current_time_ms();
};

}  // namespace wg
