#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "crypto.hpp"
#include "peer.hpp"

// ============================================================================
// Protocol Message Structures
// These structures represent the on-the-wire format of WireGuard messages.
// ============================================================================

namespace wg {

enum class MessageType : uint8_t {
    HandshakeInitiation = 1,
    HandshakeResponse = 2,
    CookieReply = 3,
    TransportData = 4,
};

// 第一条消息：发起者至响应者
#pragma pack(push, 1)
struct HandshakeInitiation {
    uint8_t message_type;
    uint8_t reserved[3];
    KeypairIndex sender_index;
    PublicKey ephemeral_public;
    std::array<uint8_t, 48> static_encrypted;
    std::array<uint8_t, 28> timestamp_encrypted;
    Mac mac1;
    Mac mac2;
};
#pragma pack(pop)
static_assert(sizeof(HandshakeInitiation) == 148);

// 第二条消息：响应者至发起者
#pragma pack(push, 1)
struct HandshakeResponse {
    uint8_t message_type;
    uint8_t reserved[3];
    KeypairIndex sender_index;
    KeypairIndex receiver_index;
    PublicKey ephemeral_public;
    std::array<uint8_t, 16> empty_encrypted;
    Mac mac1;
    Mac mac2;
};
#pragma pack(pop)
static_assert(sizeof(HandshakeResponse) == 92);

// Under load: Cookie Reply Message
#pragma pack(push, 1)
struct CookieReply {
    uint8_t message_type;
    uint8_t reserved[3];
    KeypairIndex receiver_index;
    XNonce nonce;
    std::array<uint8_t, 32> encrypted_cookie;
};
#pragma pack(pop)
static_assert(sizeof(CookieReply) == 64);

// 后续消息：双方至对方
#pragma pack(push, 1)
struct TransportDataHeader {
    uint8_t message_type;
    uint8_t reserved[3];
    KeypairIndex receiver_index;
    uint64_t counter;
};
#pragma pack(pop)

struct TransportData {
    TransportDataHeader header;
    std::vector<uint8_t> encrypted_data;
};

}  // namespace wg