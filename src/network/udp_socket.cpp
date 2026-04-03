#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

#include "../include/network.hpp"
#include "../include/utils.hpp"

namespace wg {

// ============================================================================
// UdpSocket Implementation
// ============================================================================

UdpSocket::UdpSocket(uint16_t local_port)
    : socket_fd_(-1), is_non_blocking_(false) {
    if (!create_socket()) {
        Logger::error("Failed to create UDP socket");
    }
}

UdpSocket::~UdpSocket() { close(); }

bool UdpSocket::create_socket() {
    socket_fd_ = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd_ < 0) {
        Logger::error("Failed to create socket: " +
                      std::string(strerror(errno)));
        return false;
    }

    // Set socket options
    int reuse = 1;
    if (::setsockopt(socket_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse,
                     sizeof(reuse)) < 0) {
        Logger::warn("Failed to set SO_REUSEADDR");
    }

    return true;
}

bool UdpSocket::bind(const std::string& address, uint16_t port) {
    if (socket_fd_ < 0) {
        Logger::error("Socket not created");
        return false;
    }

    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (address.empty()) {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        if (::inet_pton(AF_INET, address.c_str(), &addr.sin_addr) <= 0) {
            Logger::error("Invalid IP address: " + address);
            return false;
        }
    }

    if (::bind(socket_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        Logger::error("Failed to bind socket: " + std::string(strerror(errno)));
        return false;
    }

    // Get actual bound address
    socklen_t len = sizeof(addr);
    if (::getsockname(socket_fd_, (struct sockaddr*)&addr, &len) == 0) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ip_str, INET_ADDRSTRLEN);
        local_endpoint_.address = ip_str;
        local_endpoint_.port = ntohs(addr.sin_port);
        Logger::info("Socket bound to " + local_endpoint_.address + ":" +
                     std::to_string(local_endpoint_.port));
    }

    return true;
}

ssize_t UdpSocket::send_to(const Endpoint& endpoint,
                           const std::vector<uint8_t>& data) {
    if (socket_fd_ < 0) {
        Logger::error("Socket not valid");
        return -1;
    }

    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(endpoint.port);

    if (::inet_pton(AF_INET, endpoint.address.c_str(), &addr.sin_addr) <= 0) {
        Logger::error("Invalid destination address");
        return -1;
    }

    ssize_t sent = ::sendto(socket_fd_, data.data(), data.size(), 0,
                            (struct sockaddr*)&addr, sizeof(addr));

    if (sent < 0) {
        Logger::warn("sendto failed: " + std::string(strerror(errno)));
        return -1;
    }

    return sent;
}

ssize_t UdpSocket::recv_from(Endpoint& endpoint, std::vector<uint8_t>& data,
                             size_t max_size) {
    if (socket_fd_ < 0) {
        Logger::error("Socket not valid");
        return -1;
    }

    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    data.resize(max_size);
    ssize_t received =
        ::recvfrom(socket_fd_, data.data(), max_size, MSG_DONTWAIT,
                   (struct sockaddr*)&addr, &addr_len);

    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            data.clear();
            return 0;  // No data available (would block)
        }
        Logger::warn("recvfrom failed: " + std::string(strerror(errno)));
        return -1;
    }

    // Fill in endpoint
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr.sin_addr, ip_str, INET_ADDRSTRLEN);
    endpoint.address = ip_str;
    endpoint.port = ntohs(addr.sin_port);

    data.resize(received);
    return received;
}

bool UdpSocket::set_non_blocking(bool non_blocking) {
    if (socket_fd_ < 0) {
        return false;
    }

    int flags = ::fcntl(socket_fd_, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }

    if (non_blocking) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }

    if (::fcntl(socket_fd_, F_SETFL, flags) < 0) {
        return false;
    }

    is_non_blocking_ = non_blocking;
    return true;
}

bool UdpSocket::is_readable(int timeout_ms) {
    if (socket_fd_ < 0) {
        return false;
    }

    struct pollfd pfd;
    pfd.fd = socket_fd_;
    pfd.events = POLLIN;
    pfd.revents = 0;

    int result = ::poll(&pfd, 1, timeout_ms);
    return result > 0 && (pfd.revents & POLLIN);
}

Endpoint UdpSocket::get_local_endpoint() const { return local_endpoint_; }

void UdpSocket::close() {
    if (socket_fd_ >= 0) {
        ::close(socket_fd_);
        socket_fd_ = -1;
    }
}

bool UdpSocket::is_valid() const { return socket_fd_ >= 0; }

}  // namespace wg
