#pragma once

#include <map>
#include <memory>
#include <vector>

#include "crypto_provider.hpp"
#include "types.hpp"

namespace wg {

// ============================================================================
// Initiator - Handles Handshake Initiation (msg 1 & 3)
// ============================================================================

class Initiator {
   public:
    /// Constructor
    /// @param local_private_key Our static private key
    /// @param local_public_key Our static public key
    /// @param crypto_provider Crypto operations
    Initiator(const PrivateKey& local_private_key,
              const PublicKey& local_public_key,
              CryptoProvider* crypto_provider);

    /// Create a handshake initiation message (msg 1)
    /// @param peer_public_key Peer's static public key
    /// @param session_index Our new session index
    /// @return Serialized handshake_initiation message, empty if fails
    std::vector<uint8_t> create_initiation(const PublicKey& peer_public_key,
                                           SessionIndex session_index);

    /// Process a handshake response message (msg 2)
    /// @param message Serialized response message
    /// @param peer_public_key Output: extracted peer public key
    /// @param send_key Output: derived send key
    /// @param recv_key Output: derived receive key
    /// @return true if response valid and keys derived
    bool process_response(const std::vector<uint8_t>& message,
                          PublicKey& peer_public_key, SymmetricKey& send_key,
                          SymmetricKey& recv_key);

    /// Create a transport data keepalive message
    /// @param receiver_index Session index for receiver
    /// @param counter Packet counter
    /// @return Serialized transport_data message with empty payload
    std::vector<uint8_t> create_keepalive(SessionIndex receiver_index,
                                          uint64_t counter);

   private:
    PrivateKey local_private_key_;
    PublicKey local_public_key_;
    CryptoProvider* crypto_;

    // State during handshake
    struct HandshakeState {
        PrivateKey ephemeral_private;
        PublicKey ephemeral_public;
        SessionIndex our_session_index;
    };
    std::map<PublicKey, HandshakeState> pending_handshakes_;
};

// ============================================================================
// Responder - Handles Handshake Response (msg 2)
// ============================================================================

class Responder {
   public:
    /// Constructor
    /// @param local_private_key Our static private key
    /// @param local_public_key Our static public key
    /// @param crypto_provider Crypto operations
    Responder(const PrivateKey& local_private_key,
              const PublicKey& local_public_key,
              CryptoProvider* crypto_provider);

    /// Process a handshake initiation message (msg 1)
    /// @param message Serialized initiation message
    /// @param peer_public_key Output: extracted peer public key
    /// @param timestamp Output: extracted timestamp
    /// @return Serialized handshake_response message, empty if invalid
    std::vector<uint8_t> process_initiation(const std::vector<uint8_t>& message,
                                            PublicKey& peer_public_key,
                                            Timestamp& timestamp);

    /// Get derived keys for a completed response
    /// @param peer_public_key Peer public key
    /// @param send_key Output: send key (responder sends with recv key)
    /// @param recv_key Output: receive key (responder receives with send key)
    /// @return true if keys available
    bool get_derived_keys(const PublicKey& peer_public_key,
                          SymmetricKey& send_key, SymmetricKey& recv_key);

    /// Get responder's session index for transport data
    /// @param peer_public_key Peer public key
    /// @return Session index, 0 if not available
    SessionIndex get_response_index(const PublicKey& peer_public_key);

    /// Confirm handshake completion after receiving first transport data
    /// This ensures the initiator actually received our response
    /// @param peer_public_key Peer public key
    /// @return true if confirmation successful
    bool confirm_handshake(const PublicKey& peer_public_key);

   private:
    PrivateKey local_private_key_;
    PublicKey local_public_key_;
    CryptoProvider* crypto_;

    // State during handshake
    struct ResponseState {
        PrivateKey ephemeral_private;
        PublicKey ephemeral_public;
        SessionIndex our_session_index;
        SessionIndex their_session_index;
        SymmetricKey send_key;   // For responses (sends with their recv key)
        SymmetricKey recv_key;   // For data (receives with their send key)
        bool confirmed = false;  // Confirmed after first data packet
    };
    std::map<PublicKey, ResponseState> pending_responses_;
};

}  // namespace wg
