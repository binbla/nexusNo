#include "../../include/core.hpp"

#include <chrono>
#include <utility>

#include "../../include/utils.hpp"

namespace wg {

namespace {

constexpr uint32_t kSessionIndexMask = 0x7fffffffU;

bool endpoint_equals(const std::optional<Endpoint>& lhs,
                     const std::optional<Endpoint>& rhs) {
    if (!lhs.has_value() && !rhs.has_value()) {
        return true;
    }
    if (lhs.has_value() != rhs.has_value()) {
        return false;
    }
    return *lhs == *rhs;
}

}  // namespace

Core::Core(std::unique_ptr<CryptoProvider> crypto_provider)
    : crypto_provider_(std::move(crypto_provider)), socket_() {}

Core::~Core() { shutdown(); }

bool Core::initialize(const CoreConfig& config) {
    if (!crypto_provider_) {
        return false;
    }
    if (initialized_) {
        return true;
    }

    config_ = config;
    if (!socket_.bind(config.listen_address, config.listen_port)) {
        return false;
    }
    socket_.set_non_blocking(true);
    initialized_ = true;
    return true;
}

void Core::shutdown() {
    if (!initialized_) {
        return;
    }

    for (auto& [peer_id, peer] : peers_by_id_) {
        (void)peer_id;
        if (peer) {
            remove_peer_sessions(*peer);
        }
    }

    sessions_by_index_.clear();
    peers_by_id_.clear();
    peer_ids_by_public_key_.clear();
    socket_.close();
    initialized_ = false;
}

bool Core::is_initialized() const { return initialized_; }

void Core::set_callbacks(CoreCallbacks callbacks) {
    callbacks_ = std::move(callbacks);
}

PeerId Core::allocate_peer_id() { return next_peer_id_++; }

SessionIndex Core::allocate_session_index() {
    while (true) {
        auto random_bytes =
            crypto_provider_->random_bytes(sizeof(SessionIndex));
        if (random_bytes.size() < sizeof(SessionIndex)) {
            continue;
        }
        SessionIndex index =
            read_u32_le(random_bytes.data()) & kSessionIndexMask;
        if (index == 0 ||
            sessions_by_index_.find(index) != sessions_by_index_.end()) {
            continue;
        }
        return index;
    }
}

PeerId Core::add_peer(const PublicKey& remote_static_public_key,
                      std::optional<Endpoint> endpoint) {
    auto existing = peer_ids_by_public_key_.find(remote_static_public_key);
    if (existing != peer_ids_by_public_key_.end()) {
        if (endpoint.has_value()) {
            update_peer_endpoint(existing->second, endpoint);
        }
        return existing->second;
    }

    auto peer = std::make_shared<Peer>();
    peer->peer_id = allocate_peer_id();
    peer->remote_static_public_key = remote_static_public_key;
    peer->endpoint = std::move(endpoint);

    peers_by_id_[peer->peer_id] = peer;
    peer_ids_by_public_key_[peer->remote_static_public_key] = peer->peer_id;

    if (callbacks_.on_peer_added) {
        callbacks_.on_peer_added(*peer);
    }

    return peer->peer_id;
}

bool Core::update_peer_endpoint(PeerId peer_id,
                                const std::optional<Endpoint>& endpoint) {
    auto* peer = find_peer(peer_id);
    if (peer == nullptr) {
        return false;
    }

    if (endpoint_equals(peer->endpoint, endpoint)) {
        return true;
    }

    peer->endpoint = endpoint;
    if (callbacks_.on_peer_updated) {
        callbacks_.on_peer_updated(*peer);
    }
    if (endpoint.has_value() && callbacks_.on_endpoint_updated) {
        callbacks_.on_endpoint_updated(*peer, *endpoint);
    }
    return true;
}

void Core::remove_peer_sessions(const Peer& peer) {
    if (peer.keypairs.current) {
        sessions_by_index_.erase(peer.keypairs.current->local_index);
    }
    if (peer.keypairs.previous) {
        sessions_by_index_.erase(peer.keypairs.previous->local_index);
    }
}

bool Core::remove_peer(PeerId peer_id) {
    auto peer_it = peers_by_id_.find(peer_id);
    if (peer_it == peers_by_id_.end()) {
        return false;
    }

    auto peer = peer_it->second;
    if (peer) {
        remove_peer_sessions(*peer);
        peer_ids_by_public_key_.erase(peer->remote_static_public_key);
        if (callbacks_.on_peer_removed) {
            callbacks_.on_peer_removed(*peer);
        }
    }

    peers_by_id_.erase(peer_it);
    return true;
}

Peer* Core::find_peer(PeerId peer_id) {
    auto it = peers_by_id_.find(peer_id);
    if (it == peers_by_id_.end()) {
        return nullptr;
    }
    return it->second.get();
}

const Peer* Core::find_peer(PeerId peer_id) const {
    auto it = peers_by_id_.find(peer_id);
    if (it == peers_by_id_.end()) {
        return nullptr;
    }
    return it->second.get();
}

Peer* Core::find_peer(const PublicKey& remote_static_public_key) {
    auto it = peer_ids_by_public_key_.find(remote_static_public_key);
    if (it == peer_ids_by_public_key_.end()) {
        return nullptr;
    }
    return find_peer(it->second);
}

const Peer* Core::find_peer(const PublicKey& remote_static_public_key) const {
    auto it = peer_ids_by_public_key_.find(remote_static_public_key);
    if (it == peer_ids_by_public_key_.end()) {
        return nullptr;
    }
    return find_peer(it->second);
}

std::vector<PeerId> Core::list_peer_ids() const {
    std::vector<PeerId> peer_ids;
    peer_ids.reserve(peers_by_id_.size());
    for (const auto& [peer_id, peer] : peers_by_id_) {
        (void)peer;
        peer_ids.push_back(peer_id);
    }
    return peer_ids;
}

bool Core::store_session_index(const SessionPtr& session) {
    if (!session || session->local_index == 0) {
        return false;
    }

    auto [it, inserted] =
        sessions_by_index_.emplace(session->local_index, session);
    if (!inserted) {
        return it->second == session;
    }
    return true;
}

SessionInstallResult Core::install_session(PeerId peer_id, SessionPtr session) {
    auto* peer = find_peer(peer_id);
    if (peer == nullptr || !session) {
        return SessionInstallResult::Failed;
    }

    if (session->local_index == 0) {
        session->local_index = allocate_session_index();
    }
    if (!store_session_index(session)) {
        return SessionInstallResult::Failed;
    }

    session->peer_id = peer_id;
    session->created_at_ms = current_time_ms();
    if (session->rekey_after_time_at_ms == 0) {
        session->rekey_after_time_at_ms =
            session->created_at_ms +
            static_cast<uint64_t>(REKEY_TIMEOUT.count()) * 1000ULL;
    }
    if (session->reject_after_time_at_ms == 0) {
        session->reject_after_time_at_ms =
            session->created_at_ms +
            static_cast<uint64_t>(REJECT_AFTER_TIME.count()) * 1000ULL;
    }

    SessionInstallResult result = SessionInstallResult::Installed;
    if (peer->keypairs.current) {
        if (peer->keypairs.previous) {
            sessions_by_index_.erase(peer->keypairs.previous->local_index);
        }
        peer->keypairs.previous = peer->keypairs.current;
        result = SessionInstallResult::ReplacedCurrent;
    }

    peer->keypairs.current = session;

    if (callbacks_.on_session_installed) {
        callbacks_.on_session_installed(*peer, *session);
    }

    return result;
}

bool Core::remove_session(SessionIndex local_index) {
    auto session_it = sessions_by_index_.find(local_index);
    if (session_it == sessions_by_index_.end()) {
        return false;
    }

    auto session = session_it->second;
    if (session) {
        auto peer_it = peers_by_id_.find(session->peer_id);
        if (peer_it != peers_by_id_.end() && peer_it->second) {
            auto& peer = *peer_it->second;
            if (callbacks_.on_session_removed) {
                callbacks_.on_session_removed(peer, *session);
            }
            if (peer.keypairs.current == session) {
                peer.keypairs.current = peer.keypairs.previous;
                peer.keypairs.previous.reset();
            } else if (peer.keypairs.previous == session) {
                peer.keypairs.previous.reset();
            }
        }
    }

    sessions_by_index_.erase(session_it);
    return true;
}

Session* Core::find_session(SessionIndex local_index) {
    auto it = sessions_by_index_.find(local_index);
    if (it == sessions_by_index_.end()) {
        return nullptr;
    }
    return it->second.get();
}

const Session* Core::find_session(SessionIndex local_index) const {
    auto it = sessions_by_index_.find(local_index);
    if (it == sessions_by_index_.end()) {
        return nullptr;
    }
    return it->second.get();
}

bool Core::on_udp_packet(const std::vector<uint8_t>& packet,
                         const Endpoint& source) {
    if (!initialized_ || packet.size() < sizeof(TransportDataHeader)) {
        return false;
    }

    auto message_type = static_cast<MessageType>(packet[0]);
    if (message_type != MessageType::TransportData) {
        return false;
    }

    SessionIndex receiver_index = read_u32_le(packet.data() + 4);
    auto* session = find_session(receiver_index);
    if (session == nullptr) {
        return false;
    }

    auto* peer = find_peer(session->peer_id);
    if (peer == nullptr) {
        return false;
    }

    update_peer_endpoint(peer->peer_id, source);
    const uint64_t now_ms = current_time_ms();
    peer->last_recv_time_ms = now_ms;
    session->last_recv_at_ms = now_ms;
    if (session->role == SessionRole::Responder && !session->confirmed) {
        session->confirmed = true;
    }

    if (callbacks_.on_transport_packet) {
        callbacks_.on_transport_packet(*peer, source, packet);
    }

    return true;
}

void Core::poll(uint64_t now_ms) {
    for (auto& [peer_id, peer] : peers_by_id_) {
        (void)peer_id;
        if (!peer) {
            continue;
        }

        if (peer->keypairs.previous &&
            peer->keypairs.previous->reject_after_time_at_ms != 0 &&
            now_ms >= peer->keypairs.previous->reject_after_time_at_ms) {
            sessions_by_index_.erase(peer->keypairs.previous->local_index);
            peer->keypairs.previous.reset();
        }

        if (peer->keypairs.current &&
            peer->keypairs.current->rekey_after_time_at_ms != 0 &&
            now_ms >= peer->keypairs.current->rekey_after_time_at_ms) {
            peer->timers.next_rekey_at_ms = now_ms;
        }
    }
}

UdpSocket& Core::socket() { return socket_; }

const UdpSocket& Core::socket() const { return socket_; }

const SelfIdentity& Core::local_identity() const { return config_.identity; }

uint64_t Core::current_time_ms() {
    using clock = std::chrono::system_clock;
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            clock::now().time_since_epoch())
            .count());
}

}  // namespace wg
