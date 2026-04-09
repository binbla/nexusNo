#include "../include/endpoint.hpp"

#include <arpa/inet.h>
namespace wg {
Endpoint::Endpoint() {
    std::memset(&storage_, 0, sizeof(storage_));
    len_ = 0;
}

Endpoint Endpoint::from_ipv4(const char* ip, uint16_t port) {
    Endpoint ep;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &addr.sin_addr);

    std::memcpy(&ep.storage_, &addr, sizeof(addr));
    ep.len_ = sizeof(addr);

    return ep;
}

Endpoint Endpoint::from_ipv6(const char* ip, uint16_t port) {
    Endpoint ep;

    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(port);
    inet_pton(AF_INET6, ip, &addr.sin6_addr);

    std::memcpy(&ep.storage_, &addr, sizeof(addr));
    ep.len_ = sizeof(addr);

    return ep;
}

sa_family_t Endpoint::family() const {
    return ((sockaddr*)&storage_)->sa_family;
}

const sockaddr* Endpoint::addr() const { return (const sockaddr*)&storage_; }

socklen_t Endpoint::size() const { return len_; }

uint16_t Endpoint::port() const {
    if (family() == AF_INET) {
        return ntohs(((sockaddr_in*)&storage_)->sin_port);
    } else {
        return ntohs(((sockaddr_in6*)&storage_)->sin6_port);
    }
}

bool Endpoint::operator==(const Endpoint& other) const {
    if (family() != other.family()) return false;
    if (len_ != other.len_) return false;

    return std::memcmp(&storage_, &other.storage_, len_) == 0;
}

Endpoint Endpoint::from_sockaddr(const sockaddr* addr, socklen_t len) {
    Endpoint ep;
    std::memcpy(&ep.storage_, addr, len);
    ep.len_ = len;
    return ep;
}
}  // namespace wg