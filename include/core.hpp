#include <span>
#include <variant>

#include "crypto.hpp"
#include "message.hpp"
#include "noise.hpp"
#include "peer.hpp"
#include "socket.hpp"

namespace wg {

struct Config {
    // 监听地址和端口
    std::string listen_addr;
    uint16_t listen_port;

    PrivateKey private_key;
    PublicKey public_key;
};

// 索引表应该有能力定位握手状态（Handshake）或会话密钥（Keypair），以便快速处理收到的消息
using IndexTarget = std::variant<Handshake*, Keypair*>;
struct IndexEntry {
    Peer* peer = nullptr;
    IndexTarget target;
};

class Core {
   public:
    // 初始化
    void init(Config config);
    // 注册peer
    PeerManager getPeers() const;

    // 发送消息
    bool send_to_peer(PublicKey& target, std::span<const uint8_t> plaintext);
    // 处理收到的消息
    void handle_incoming(std::span<const uint8_t> data, const Endpoint& src);
    // 注册明文回调
    using PlaintextCallback = std::function<void(
        const PublicKey& peer, std::span<const uint8_t> plaintext)>;

   private:
    UdpSocket socket_;                        // 负责网络 I/O
    std::unique_ptr<CryptoProvider> crypto_;  // 负责加密操作
    // std::map<PublicKey, std::unique_ptr<Peer>> peers_;  // 管理 peer 状态
    PeerManager peers_;
    std::unordered_map<KeypairIndex, IndexEntry> index_table_;  // 定位
    /*
    index_table_ --> (index, sessionEntry) // index
    是session的索引，Entry是Keypair的入口

    sessionEntry --> (peer, sessionItem) //
    单个sessionEntry必须标识清楚归属Peer, 然后才是整个session的入口
    session 自己有能力标识自己是握手还是已经完成建联

    session的创建由core完成，初始化则交给noise完成


    */
};
}  // namespace wg