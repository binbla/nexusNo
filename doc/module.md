## **1. 核心层 `core.hpp`**

**职责：**

- 协议的入口、生命周期管理。
- 初始化网络接口、端口绑定。
- 消息监听 / 事件分发。
- 管理全局资源：`IndexTable`、`PeerManager`、`NoiseProtocol`。
- 分配 Session Index。
- 计时、维护握手频率、定时发送 Keepalive。
- 接收到消息后，将其派发给 `receive.hpp` 处理；发送消息调用 `send.hpp`。

**核心成员：**

```text
- IndexTable index_table   // index -> session 映射
- PeerManager peer_manager // peer 查找、管理
- NoiseProtocol protocol   // 协议逻辑
```

**职责说明：**

| 功能     | 说明                                                      |
| -------- | --------------------------------------------------------- |
| 初始化   | 初始化 crypto、noise、peer_manager、index_table、网络端口 |
| 消息监听 | 阻塞/非阻塞接收 UDP 消息，并交给 `receive.hpp` 解析       |
| 分配任务 | 为握手或数据传输分配 session / index / peer               |
| 时间管理 | 控制握手重试、keepalive 定时发送                          |
| 上层调用 | 提供发送接口给应用层调用                                  |

---

## **2. `IndexTable`**

**职责：**

- 用于从 peer 的 session index 找到对应的 Session 或 Peer。
- 每个 Peer 维护三槽 Session（最近使用 / 按 index）。
- Core 或 NoiseProtocol 在分配新的 handshake 时，会向 IndexTable 请求可用 index。

**数据结构：**

```text
index -> Session*
```

---

## **3. `PeerManager`**

**职责：**

- 管理所有 peer 对象。
- 支持根据 peer 公钥 / hashed 公钥查找 Peer。
- 初始化时计算 peer 静态资源：
  - `precomputed_static_static`（static-static DH）
  - 该 peer 的 public key hash（用于 handshake）

- 提供接口：
  - `find_by_public_key(pub)`
  - `find_by_hash(hash)`

**Peer 的内容：**

```text
- PublicKey remote_public
- Hash      remote_hash = Hash(remote_public)
- ChainingKey base_ck (precomputed)
- Hash      base_hash (precomputed)
- Session[3] sessions
- Handshake handshake_state
```

**特点：**

- 公钥和 hash 是只读的，初始化时生成后不会变（除非 peer 改 key）。
- 每个 peer 拥有独立的 handshake 状态，用于维护临时 ck/hash/ephemeral。

---

## **4. `NoiseProtocol`**

**职责：**

- 管理本地身份（Public/Private Key）。
- 保存 base_chaining_key 和 base_hash。
- 创建和消费 handshake 消息（initiation / response / cookie / keepalive）。
- 派生 transport session key。
- 调用底层工具：`wg::noise` + `wg::crypto`。

**状态：**

```text
- PrivateKey local_private
- PublicKey  local_public
- ChainingKey base_chaining_key
- Hash        base_hash
```

**注意：**

- 不维护 ephemeral key 或握手临时状态，这些存储在 `Peer` 的 Handshake 内。

---

## **5. 消息收发**

- **`send.hpp`**：
  - 封装 UDP / NAT traversal 发送。
  - 将 NoiseProtocol 输出的 handshake/data 消息封装成二进制。

- **`receive.hpp`**：
  - 解析 UDP /消息缓冲区。
  - 根据消息类型调用 NoiseProtocol 消费函数：
    - initiation → `consume_initiation()`
    - response → `consume_response()`
    - cookie → `consume_cookie_request()`
    - keepalive → `consume_keepalive()`

  - 校验顺序 / replay / flood。
  - 交给 Core / PeerManager 更新 handshake 或 session。

---

## **6. Peer 内部结构**

```text
Peer {
    // 静态资源 (初始化就固定)
    PublicKey remote_public
    Hash      remote_public_hash
    ChainingKey precomputed_static_static
    Hash      precomputed_hash_for_handshake

    // 握手状态
    Handshake handshake_state

    // 三槽 Session（发送/接收 key）
    Session sessions[3]

    // replay counter
    ReplayCounter replay_counter
}
```

**说明：**

- Peer 静态资源只读。
- Session 是活跃握手 / transport key 存储。
- replay_counter 用于检测重放攻击。
- Handshake 状态仅用于 handshake 期间。

---

## **7. NoiseProtocol + wg::noise / wg::crypto**

- NoiseProtocol **有状态**：local identity + base ck/hash。
- wg::noise **无状态**：
  - mix_dh, mix_precomputed_dh, encrypt_and_hash, decrypt_and_hash, mix_ephemeral
  - 只负责协议组合逻辑

- wg::crypto **无状态**：
  - dh, kdf, aead, hash, hmac, random_bytes
  - 低层原语

调用关系：

```text
Core
 ├─ IndexTable
 ├─ PeerManager
 │    └─ Peer
 ├─ NoiseProtocol
 │     └─ wg::noise
 │          └─ wg::crypto
 ├─ send.hpp
 └─ receive.hpp
```

---

## **8. 数据流总结**

1. **消息发送**：

```text
Core → NoiseProtocol.create_initiation() → wg::noise → wg::crypto → send.hpp → UDP
```

2. **消息接收**：

```text
Core / receive.hpp → wg::noise consume_xxx() → PeerManager → Peer handshake/session
```

3. **Session Key 派生**：

```text
NoiseProtocol.derive_transport_keys() → wg::noise.derive_transport_keys() → Peer.sessions
```

---

## **9. 资源管理总结**

| 组件          | 主要资源                               | 生命周期              | 可变性                      |
| ------------- | -------------------------------------- | --------------------- | --------------------------- |
| Core          | index_table, peer_manager, protocol    | 全局                  | 可变（管理 peer / session） |
| PeerManager   | peer 静态公钥、precomputed DH          | 初始化完成后固定      | 不变（除非 pub key 变）     |
| Peer          | 三槽 Session、Handshake、ReplayCounter | handshake + transport | session / handshake 可变    |
| NoiseProtocol | local_private/public, base_ck/hash     | 协议实例周期          | 可变初始化一次              |
| wg::noise     | 无状态函数                             | 无                    | 不变                        |
| wg::crypto    | 无状态函数                             | 无                    | 不变                        |
| send/receive  | 消息缓冲                               | 消息生命周期          | 临时                        |

---

如果你希望，我可以帮你画一张 **清晰的组件关系图**，用 UML 类图 + 数据流箭头，标注每个对象的可变性和生命周期。

你希望我画吗？
