#pragma once

#include <sys/types.h>

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "crypto.hpp"
#include "endpoint.hpp"
#include "peer.hpp"

// ============================================================================
// Network I/O and Transport Data Handling
// ============================================================================

namespace wg {
// ============================================================================
// UdpSocket - Network I/O (Non-blocking UDP)
// ============================================================================
class UdpSocket {
   public:
    using RecvCallback =
        std::function<void(std::span<const uint8_t> data, const Endpoint& src)>;

    explicit UdpSocket(uint16_t port);  // 默认就所有地址
    ~UdpSocket();

    int fd() const;

    void send(std::span<const uint8_t> data, const Endpoint& dst);

    void set_recv_callback(RecvCallback cb);

    // epoll 触发
    void handle_read();

   private:
    int fd_;
    RecvCallback recv_cb_;

    void set_non_blocking();
};

}  // namespace wg
