# NexusNo 通信 Core 架构设计（协议层）

## 1. 目标与边界

本项目的 `core` 是一个纯协议层通信内核，采用 WireGuard 风格密码学与握手语义，但不实现 VPN 与路由能力。

### 1.1 负责范围

- 本地私钥初始化、派生本地公钥、UDP 端口监听
- Peer 白名单管理（静态公钥为身份）
- 会话建立、会话状态管理、会话轮换触发
- 加密发送与解密接收（payload 不透明）
- 必要的上行回调（事件与明文消息）

### 1.2 不负责范围

- 不实现 TUN/TAP、IP 转发、路由策略
- 不实现可靠传输、重传、顺序保证、分片重组
- 不解析业务 payload 语义

## 2. 核心原则

### 2.1 身份原则

- `Peer Identity = X25519 PublicKey`
- 只有已注册公钥可进入握手与数据通道

### 2.2 安全原则

- 默认拒绝未知 peer
- 未建立会话前禁止发送业务数据
- endpoint 学习仅在白名单身份可确认后进行

### 2.3 协议兼容原则

- 消息结构延续当前 `protocol_messages.hpp`
- 密码学实现依赖 `CryptoProvider`
- 网络 I/O 复用 `UdpSocket`

## 3. 模块分层

## 3.1 对外层（API）

文件：`include/core.hpp`

- `Core::initialize(config)`：私钥与监听端口初始化
- `Core::add_or_update_peer(pubkey, options)`：注册/更新 peer
- `Core::set_peer_endpoint(pubkey, endpoint)`：显式更新 endpoint
- `Core::send_to_peer(pubkey, plaintext)`：向指定 peer 发送明文（内部加密）
- `Core::poll_once(timeout)`：单步轮询收包与处理
- `register_receive_callback(...)`：上行明文回调
- `register_peer_event_callback(...)`：上行事件回调

## 3.2 编排层（Core Orchestrator）

文件：`src/core/core.cpp`

职责：

- 维护 peer 状态表
- 收包后按消息类型分发到握手/传输管线
- 触发事件上报（握手开始、会话建立、丢包原因等）

当前仓库中该层已经具备：

- 初始化/销毁
- peer 白名单管理
- 基础事件模型与回调注册
- 消息入口分流框架

## 3.3 密码与网络依赖层

- `CryptoProvider`：X25519、AEAD、HKDF、Hash/MAC
- `UdpSocket`：非阻塞 UDP 收发

`Core` 不直接绑定具体库，默认通过 `create_libsodium_provider()` 注入。

## 4. 关键数据模型

## 4.1 CoreConfig

- `local_private_key`
- `bind_endpoint`
- `default_poll_timeout_ms`
- `max_packet_size`

## 4.2 PeerOptions

- `endpoint`（可选）
- `allow_endpoint_update`（是否允许被动学习更新）

## 4.3 PeerState（内部）

- `public_key`
- `endpoint`（可为空）
- `allow_endpoint_update`
- `session`（会话索引、计数器、建立状态）

## 4.4 PeerEvent

- `PeerAdded / PeerUpdated / PeerRemoved`
- `EndpointLearned`
- `HandshakeStarted / HandshakeCompleted`
- `TransportDropped`

## 5. 状态机设计

## 5.1 Peer 状态

- `RegisteredNoEndpoint`：仅注册公钥，无 endpoint
- `RegisteredWithEndpoint`：已知 endpoint，可主动发起握手
- `Handshaking`：握手进行中
- `Established`：会话已建立，可收发业务数据
- `Stale`：会话过期，等待重握手

状态迁移触发：

- 上层 `add_or_update_peer`
- 收到合法握手包
- 会话超时/计数器阈值
- 上层移除 peer

## 5.2 Endpoint 更新策略

- 若 peer 配置了固定 endpoint 且 `allow_endpoint_update=false`：只接受该地址端口
- 若 `allow_endpoint_update=true`：在身份验证通过后允许迁移 endpoint
- 未注册公钥来源的数据包一律丢弃

## 6. 握手与数据通路

## 6.1 主动建联（有 endpoint）

1. 上层调用 `send_to_peer`
2. 若无已建立会话，触发 `HandshakeStarted`
3. 完成 IK 握手后，进入 `Established`
4. 发送 `TransportData`

## 6.2 被动建联（无 endpoint）

1. 收到握手发起包
2. 在白名单中定位 peer 并完成身份验证
3. 写入/更新 endpoint
4. 回复握手并建立会话

## 6.3 传输数据

- 出站：按会话发送计数器构造 nonce，AEAD 加密后发包
- 入站：按会话索引定位 peer，反解并做 replay 检查
- 成功后触发 `receive_callback(peer_pubkey, plaintext)`

## 7. 线程与并发建议

当前建议先使用单线程事件循环：

- 上层线程周期调用 `poll_once()`
- 所有 `Core` API 与 `poll_once` 在同一线程调用

后续若扩展到多线程：

- peer 表加读写锁
- 回调改为异步队列派发

## 8. 失败处理与可观测性

- `send_to_peer` 返回 `false` 表示未发送（常见：peer 不存在、无 endpoint、会话未建立）
- 细分原因通过 `PeerEvent.reason` 上报
- 推荐上层记录以下指标：
  - 握手成功率
  - `TransportDropped` 分类计数
  - endpoint 迁移次数
