#pragma once

#include <sys/types.h>

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "crypto_provider.hpp"
#include "types.hpp"

namespace wg {

// ============================================================================
// TransportDataHandler - Encrypts and Decrypts Transport Packets
// ============================================================================

class TransportDataHandler {
   public:
    /// Constructor
    /// @param crypto_provider Crypto operations
    /// @param session_manager Session manager for keys
    TransportDataHandler(CryptoProvider* crypto_provider);

    /// Encrypt plaintext and create transport data packet
    /// @param peer_public_key Peer's public key
    /// @param plaintext Data to encrypt
    /// @return Serialized transport_data packet, empty if fails
    std::vector<uint8_t> encrypt_and_send(
        const PublicKey& peer_public_key,
        const std::vector<uint8_t>& plaintext);

    /// Decrypt a transport data packet
    /// @param message Serialized transport_data packet
    /// @param peer_public_key Output: peer public key
    /// @param plaintext Output: decrypted data
    /// @return true if decryption successful and replay check passes
    bool decrypt_and_receive(const std::vector<uint8_t>& message,
                             PublicKey& peer_public_key,
                             std::vector<uint8_t>& plaintext);

    /// Check if this is a keepalive packet (empty transport data)
    /// @param message Serialized packet
    /// @return true if keepalive
    bool is_keepalive(const std::vector<uint8_t>& message) const;

   private:
    CryptoProvider* crypto_;

    // Anti-replay: track highest seen counter for each session
    std::map<SessionIndex, uint64_t> highest_counter_;

    /// Derive nonce from counter
    Nonce counter_to_nonce(uint64_t counter) const;

    /// Check and update replay window
    bool check_replay_and_update(SessionIndex session_index, uint64_t counter);
};

// ============================================================================
// UdpSocket - Network I/O (Non-blocking UDP)
// ============================================================================

class UdpSocket {
   public:
    /// Constructor
    /// @param local_port Port to bind (0 for automatic)
    explicit UdpSocket(uint16_t local_port = 0);

    virtual ~UdpSocket();

    /// Bind socket locally
    /// @param address Local address to bind (empty = any)
    /// @param port Local port to bind
    /// @return true if successful
    bool bind(const std::string& address = "", uint16_t port = 0);

    /// Send data to an endpoint
    /// @param endpoint Destination endpoint
    /// @param data Data to send
    /// @return Number of bytes sent, -1 if error
    ssize_t send_to(const Endpoint& endpoint, const std::vector<uint8_t>& data);

    /// Receive data from any endpoint
    /// @param endpoint Output: source endpoint
    /// @param data Output: received data
    /// @param max_size Maximum bytes to receive
    /// @return Number of bytes received, 0 if would block, -1 if error
    ssize_t recv_from(Endpoint& endpoint, std::vector<uint8_t>& data,
                      size_t max_size = 4096);

    /// Set socket to non-blocking mode
    /// @return true if successful
    bool set_non_blocking(bool non_blocking);

    /// Check if socket is ready to read
    /// @param timeout_ms Timeout in milliseconds
    /// @return true if readable, false if timeout or error
    bool is_readable(int timeout_ms = 0);

    /// Get local endpoint
    /// @return Local endpoint
    Endpoint get_local_endpoint() const;

    /// Close socket
    void close();

    /// Check if socket is valid
    bool is_valid() const;

   private:
    int socket_fd_;
    Endpoint local_endpoint_;
    bool is_non_blocking_;

    // Platform-specific helper methods
    bool create_socket();
};

}  // namespace wg
