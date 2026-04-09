#include "../include/socket.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <stdexcept>

#include "../include/endpoint.hpp"
#include "../include/utils.hpp"

namespace wg {
UdpSocket::UdpSocket(uint16_t port) {
    fd_ = socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd_ < 0) {
        throw std::runtime_error("socket create failed");
    }

    // 允许 IPv4 映射 默认就双栈 反正协议后面能力要求很高
    int off = 0;
    setsockopt(fd_, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));

    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    addr.sin6_addr = in6addr_any;

    if (bind(fd_, (sockaddr*)&addr, sizeof(addr)) < 0) {
        close(fd_);
        throw std::runtime_error("bind failed");
    }

    set_non_blocking();
}
int UdpSocket::fd() const { return fd_; }
void UdpSocket::set_non_blocking() {
    int flags = fcntl(fd_, F_GETFL, 0);
    fcntl(fd_, F_SETFL, flags | O_NONBLOCK);
}
void UdpSocket::send(std::span<const uint8_t> data, const Endpoint& dst) {
    sendto(fd_, data.data(), data.size(), 0, dst.addr(), dst.size());
}

void UdpSocket::set_recv_callback(RecvCallback cb) { recv_cb_ = std::move(cb); }
void UdpSocket::handle_read() {
    uint8_t buf[2048];

    while (true) {
        sockaddr_storage src{};
        socklen_t len = sizeof(src);

        ssize_t n = recvfrom(fd_, buf, sizeof(buf), 0, (sockaddr*)&src, &len);

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            continue;
        }

        if (n == 0) continue;

        Endpoint ep = Endpoint::from_sockaddr((sockaddr*)&src, len);

        if (recv_cb_) {
            recv_cb_(std::span<const uint8_t>(buf, n), ep);
        }
    }
}

}  // namespace wg
