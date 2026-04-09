#pragma once
#include <netinet/in.h>

#include <cstring>
#include <string>
namespace wg {
class Endpoint {
   public:
    Endpoint();

    static Endpoint from_ipv4(const char* ip, uint16_t port);
    static Endpoint from_ipv6(const char* ip, uint16_t port);

    sa_family_t family() const;

    const sockaddr* addr() const;
    socklen_t size() const;

    uint16_t port() const;

    bool operator==(const Endpoint& other) const;
    static Endpoint from_sockaddr(const sockaddr* addr, socklen_t len);

   private:
    sockaddr_storage storage_;
    socklen_t len_;
};
}  // namespace wg
