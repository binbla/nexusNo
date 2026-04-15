#pragma once

#include <array>
#include <cstdint>
#include <vector>

#include "crypto.hpp"
using KeypairIndex = uint32_t;
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
    MessageType message_type;    // 1
    uint8_t reserved[3];         // 3
    KeypairIndex sender_index;   // 4 - 发起者的索引
    PublicKey ephemeral_public;  // 32 - 发起者的临时公钥
    std::array<uint8_t, 48>
        static_encrypted;  // 48 - 加密的发起者静态公钥（32）+预共享密钥（16）
    std::array<uint8_t, 28>
        timestamp_encrypted;  // 28 - 加密的时间戳（12）+噪声（16）
    Mac mac1;
    Mac mac2;
};
#pragma pack(pop)
static_assert(sizeof(HandshakeInitiation) == 148);

// 第二条消息：响应者至发起者
#pragma pack(push, 1)
struct HandshakeResponse {
    MessageType message_type;                 // 1
    uint8_t reserved[3];                      // 3
    KeypairIndex sender_index;                // 4
    KeypairIndex receiver_index;              // 4
    PublicKey ephemeral_public;               // 32
    std::array<uint8_t, 16> empty_encrypted;  // 16
    Mac mac1;                                 // 16
    Mac mac2;                                 // 16
};
#pragma pack(pop)
static_assert(sizeof(HandshakeResponse) == 92);

// Under load: Cookie Reply Message
#pragma pack(push, 1)
struct CookieReply {
    MessageType message_type;
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
    MessageType message_type;
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