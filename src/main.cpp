#include <sys/epoll.h>

#include "../include/crypto.hpp"
#include "../include/crypto/crypto.hpp"
#include "../include/endpoint.hpp"
#include "../include/socket.hpp"
#include "../include/utils.hpp"

namespace wg {
int main() {
    int ep = epoll_create1(0);

    UdpSocket sock(12345);

    epoll_event ev{};
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = sock.fd();

    epoll_ctl(ep, EPOLL_CTL_ADD, sock.fd(), &ev);

    sock.set_recv_callback(
        [](const uint8_t* data, size_t len, const Endpoint& src) {
            // receive(...)
        });

    while (true) {
        epoll_event events[16];
        int n = epoll_wait(ep, events, 16, -1);

        for (int i = 0; i < n; ++i) {
            if (events[i].data.fd == sock.fd()) {
                sock.handle_read();
            }
        }
    }
}
}  // namespace wg
