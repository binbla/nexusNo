#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace wg {

// The UTF-8 string
constexpr const char* CONSTRUCTION =
    "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";  // 37bytes
constexpr const char* PROTOCOL_NAME =
    "wg v1 mod admin@binbla.com";                 // 29bytes 自协议
constexpr const char* label_mac1 = "mac1----";    // 8 bytes
constexpr const char* label_cookie = "cookie--";  // 8 bytes
// ============================================================================
// TLS Constants & Type Aliases
// ============================================================================

constexpr size_t KEY_SIZE = 32;            // For both public and private keys
constexpr size_t PUBLIC_KEY_SIZE = 32;     // X25519 public key size
constexpr size_t PRIVATE_KEY_SIZE = 32;    // X25519 private key size
constexpr size_t SYMMETRIC_KEY_SIZE = 32;  // ChaCha20-Poly1305 key size
constexpr size_t TIMESTAMP_SIZE = 12;      // 8 bytes timestamp + 4 bytes noise
constexpr size_t COUNTER_SIZE = 8;         // 64-bit packet counter
constexpr size_t TAG_SIZE = 16;            // Poly1305 authentication tag
constexpr size_t XNONCE_SIZE = 24;         // XChaCha20 nonce size
constexpr size_t HASH_SIZE = 32;           // BLAKE2s hash output size
constexpr size_t MAC_SIZE = 16;   // BLAKE2s MAC size (16 bytes for keyed MAC)
constexpr size_t HMAC_SIZE = 32;  // HMAC-BLAKE2s output size (32 bytes)

// 网络重试
constexpr std::chrono::seconds HANDSHAKE_RETRY{5};
constexpr int MAX_HANDSHAKE_ATTEMPTS = 10;

// 会话管理
constexpr std::chrono::seconds REKEY_TIMEOUT{120};  // 会话重键时间（120秒）
constexpr std::chrono::seconds INITIATOR_REKEY_TIMEOUT{
    135};  // 发起者重键时间（135秒，稍长于重键时间以允许响应者先重键）
constexpr std::chrono::seconds REJECT_AFTER_TIME{
    180};  // 会话过期时间（180秒，超过这个时间未重键则拒绝继续使用）
constexpr std::chrono::seconds KEEPALIVE_TIMEOUT{
    10};  // 保持连接超时时间（10秒，超过这个时间未收到数据则发送保持连接消息）

// Replay window (anti-replay for transport packets)
constexpr uint64_t REPLAY_WINDOW_SIZE = 64;  // 先跑通再说

// ============================================================================
// Type Definitions For Cryptography and Protocol
// ============================================================================

using PublicKey = std::array<uint8_t, PUBLIC_KEY_SIZE>;
using PrivateKey = std::array<uint8_t, PRIVATE_KEY_SIZE>;
using SymmetricKey = std::array<uint8_t, SYMMETRIC_KEY_SIZE>;
using Timestamp = std::array<uint8_t, TIMESTAMP_SIZE>;
using Tag = std::array<uint8_t, TAG_SIZE>;
using Nonce = std::array<uint8_t, 12>;
using XNonce = std::array<uint8_t, XNONCE_SIZE>;
using Mac = std::array<uint8_t, MAC_SIZE>;
using Hmac = std::array<uint8_t, HMAC_SIZE>;
using Hash = std::array<uint8_t, HASH_SIZE>;

// Session index type used in messages
using SessionIndex = uint32_t;
using PeerId = uint64_t;
struct Session;  // Forward declaration for session struct
using SessionPtr = std::shared_ptr<Session>;

// ============================================================================
// Endpoint Information
// ============================================================================

struct Endpoint {
    std::string address;  // IP address (IPv4/IPv6)
    uint16_t port;        // UDP port

    bool operator==(const Endpoint& other) const {
        return address == other.address && port == other.port;
    }

    bool operator!=(const Endpoint& other) const { return !(*this == other); }
};

// ============================================================================
// Message Types
// ============================================================================
enum class MessageType : uint8_t {
    HandshakeInitiation = 1,
    HandshakeResponse = 2,
    CookieReply = 3,
    TransportData = 4,
};

// ============================================================================
// Handshake Message Types
// ============================================================================

// 格式跟WireGuard的消息格式一样
// 第一条消息：发起者至响应者
#pragma pack(push, 1)
struct HandshakeInitiation {
    uint8_t message_type;        // Always 1, 1 byte
    uint8_t reserved[3];         // Reserved for alignment 3
    SessionIndex sender_index;   // Session index from initiator 4
    PublicKey ephemeral_public;  // Ephemeral public key 32
    std::array<uint8_t, 48>
        static_encrypted;  // Encrypted static key 32 + 16 (tag)
    std::array<uint8_t, 28>
        timestamp_encrypted;  // Encrypted timestamp 12 + 16 (tag)
    Mac mac1;                 // 16
    Mac mac2;                 // 16
};
#pragma pack(pop)
static_assert(sizeof(HandshakeInitiation) == 148);

// 第二条消息：响应者至发起者
#pragma pack(push, 1)
struct HandshakeResponse {
    uint8_t message_type;         // Always 2, 1 byte
    uint8_t reserved[3];          // Reserved for alignment 3
    SessionIndex sender_index;    // Session index from responder 4
    SessionIndex receiver_index;  // Sender index from initiation 4
    PublicKey ephemeral_public;   // Ephemeral public key 32
    std::array<uint8_t, 16>
        empty_encrypted;  // Encrypted static key 0 + 16 (tag)
    Mac mac1;             // 16
    Mac mac2;             // 16
};
#pragma pack(pop)
static_assert(sizeof(HandshakeResponse) == 92);

// Under load: Cookie Reply Message
#pragma pack(push, 1)
struct CookieReply {
    uint8_t message_type;                      // 3
    uint8_t reserved[3];                       // Reserved for alignment 3
    SessionIndex receiver_index;               // Session index from initiator 4
    XNonce nonce;                              // 24 bytes
    std::array<uint8_t, 32> encrypted_cookie;  // 16-byte cookie + 16-byte tag
};
#pragma pack(pop)
static_assert(sizeof(CookieReply) == 64);

// ============================================================================
// Transport Data Packet
// ============================================================================

// 后续消息：双方至对方
#pragma pack(push, 1)
struct TransportDataHeader {
    uint8_t message_type;         // Always 4, 1 byte
    uint8_t reserved[3];          // Reserved for alignment 3
    SessionIndex receiver_index;  // Session index receiver should use 4
    uint64_t counter;             // Packet counter 8
};
#pragma pack(pop)
// payload不参与layout
struct TransportData {
    TransportDataHeader header;
    std::vector<uint8_t> encrypted_data;  // Encrypted + authenticated payload
};

// ============================================================================
// Replay Window
// ============================================================================

struct ReplayWindow {
    uint64_t max_counter = 0;
    uint64_t bitmap = 0;  // minimal version; can be widened later
};

// ============================================================================
// Session
// 握手建立的会话状态，包含会话索引、密钥、计数器等信息
// ============================================================================
// Session role
enum class SessionRole : uint8_t {
    Initiator = 0,
    Responder = 1,
};

struct Session {                                // 会话状态
    PeerId peer_id = 0;                         // 所属peer ID，非协议字段
    SessionRole role = SessionRole::Initiator;  // 会话角色：发起者或响应者

    // Indices used in transport messages:
    // - local_index: index remote peer uses to send packets to us
    // - remote_index: index we use to send packets to remote
    SessionIndex local_index = 0;   // 本peer的索引
    SessionIndex remote_index = 0;  // 远端用于索引的会话索引，协议字段

    SymmetricKey send_key{};  // 完成握手后商量出的发送密钥，协议字段
    SymmetricKey recv_key{};  // 接收密钥，协议字段

    uint64_t send_nonce = 0;
    ReplayWindow replay{};

    // 统计和计时信息
    uint64_t created_at_ms = 0;
    uint64_t last_send_at_ms = 0;
    uint64_t last_recv_at_ms = 0;

    // 重键和过期处理时间点（协议字段）
    uint64_t rekey_after_time_at_ms = 0;
    uint64_t reject_after_time_at_ms = 0;

    // WireGuard-aligned session confirmation semantics:
    // - initiator-created session: true immediately after valid response
    // - responder-created session: false until first valid transport packet
    bool confirmed = false;

    [[nodiscard]] bool can_send() const {
        if (role == SessionRole::Initiator) {
            return true;
        }
        return confirmed;
    }
};

// ============================================================================
// Handshake
// 通过mac1验证的握手状态，包含当前握手阶段、索引、临时密钥等信息
// ============================================================================

enum class HandshakeStateType : uint8_t {
    Idle = 0,
    InitSent,
    InitReceived,
    ResponseSent,
};

struct HandshakeState {
    // 存中间信息以完成握手的状态机
    // 完成握手之后就丢弃
    HandshakeStateType state = HandshakeStateType::Idle;

    SessionIndex local_index = 0;
    SessionIndex remote_index = 0;

    std::optional<PrivateKey> local_ephemeral_private;
    std::optional<PublicKey> local_ephemeral_public;
    std::optional<PublicKey> remote_ephemeral_public;

    Hash chaining_key{};
    Hash handshake_hash{};

    bool is_initiator = false;
    uint64_t created_at_ms = 0;

    // for handshake retry / replay protection bookkeeping
    std::optional<Timestamp> last_sent_timestamp;
    std::optional<Timestamp> last_received_timestamp;
    uint32_t retry_count = 0;
};

// ============================================================================
// PeerTimers
// Logical timer points, driven externally by poll(now)
// ============================================================================
// 计时器
struct PeerTimers {
    uint64_t next_handshake_retry_at_ms = 0;
    uint64_t next_rekey_at_ms = 0;
    uint64_t next_keepalive_at_ms = 0;
    uint64_t next_stale_cleanup_at_ms = 0;
};

// ============================================================================
// PeerKeypairs
// WireGuard-aligned: current + previous
// ============================================================================
// 维护当前和上一个会话状态
struct PeerKeypairs {
    SessionPtr current;
    SessionPtr previous;
};

// ============================================================================
// Peer
// Session ownership belongs here
// ============================================================================

struct Peer {
    PeerId peer_id = 0;                    // 用于内部管理的peer ID，非协议字段
    PublicKey remote_static_public_key{};  // 对端的静态公钥，协议字段

    std::optional<Endpoint> endpoint;  // 对端地址，协议字段（可变）

    HandshakeState handshake_state{};  // 当前握手状态
    PeerKeypairs keypairs{};           // 当前和上一个会话状态

    // 统计和计时信息
    uint64_t last_handshake_time_ms = 0;
    uint64_t last_send_time_ms = 0;
    uint64_t last_recv_time_ms = 0;

    PeerTimers timers{};  // 计时器
};

// ============================================================================
// Crypto Parameters
// ============================================================================
// self
struct SelfIdentity {
    PublicKey static_public;
    PrivateKey static_private;
    PublicKey static_peer_public;  // For responder
};

// ============================================================================
// Event Types (for event loop)
// ============================================================================

enum class EventType {
    HANDSHAKE_TIMEOUT,
    REKEY_TIMEOUT,
    EXPIRY_TIMEOUT,
    SOCKET_READABLE,
    USER_SEND_DATA,
};

enum class SessionInstallResult : uint8_t {
    Installed,
    ReplacedCurrent,
    Failed,
};

}  // namespace wg
