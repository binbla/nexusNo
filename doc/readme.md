你现在扮演一名资深安全协议工程师与系统架构师，负责帮助我设计并实现一个**基于 WireGuard 核心语义的点对点安全通信内核**。

你的任务不是发散讨论，而是**严格按照以下需求生成一个可实现、可迭代的协议内核框架设计与代码骨架方案**。

---

## 一、项目目标

我要实现一个**基于 UDP 的点对点安全通信内核**。

该内核：

- 使用静态 **X25519 公钥** 作为身份
- 采用 **WireGuard 风格握手** 建立会话
- 使用 **ChaCha20-Poly1305** 加密数据报
- 仅对**预注册 peer** 提供认证后的收发能力
- 只负责：
  1. peer 管理
  2. 会话建立 / 轮换
  3. 加密发送 / 解密接收数据报

---

## 二、必须严格遵守的前提

### 1. 完整继承 WireGuard 的核心语义

必须完整继承以下语义，不允许擅自改造为别的协议模型：

- WireGuard 风格的 initiation / response / cookie reply / transport data 四类消息
- WireGuard 风格的静态公钥身份模型
- WireGuard 风格的 handshake / session / rekey / roaming / anti-replay / session confirmation 语义
- current / previous / next 三槽会话模型
- responder 必须在收到 initiator 的第一条 transport data 后才确认 session 可用于发送
- endpoint roaming 语义：仅在收到合法认证/解密通过的包后更新 endpoint
- handshake anti-replay 使用 timestamp
- transport anti-replay 使用 counter + sliding window
- 非法包默认静默丢弃，不向对端泄露额外行为

### 2. 明确不负责的事情

这个内核**不负责**：

- 不保证可靠性
- 不保证顺序
- 不做分片 / 重组
- 不定义上层协议结构
- 不解释 payload 内容
- 不做 VPN / 路由 / IP 封装
- 不做 TUN/TAP / netdevice / 内核网卡集成

### 3. payload 语义

transport payload 是**不透明字节流**。
内核只加密、发送、接收、解密，不解释其中内容。

---

## 三、总体架构

系统划分为以下 5 个核心模块：

1. Core API
2. Peer Manager
3. Handshake Engine
4. Session Engine
5. Transport Engine
6. UDP Socket / IO

请围绕这几个模块组织代码和类型边界。

---

## 四、核心数据结构约束

### 4.1 Core

Core 至少应包含：

- local_identity
- udp_socket
- peer_table // pubkey -> Peer
- index_table // receiver_index -> Session
- config
- callbacks
- runtime_state

### 4.2 LocalIdentity

- static_private_key [32]
- static_public_key [32]

### 4.3 Peer

Peer 至少包含：

- peer_id
- remote_static_public_key
- endpoint // 当前通信地址，可动态更新
- handshake_state // 临时握手状态
- current_session
- previous_session
- next_session
- last_handshake_time
- last_send_time
- last_recv_time
- timers

约束：

- peer 必须预注册
- endpoint 继承 WireGuard roaming 行为
- endpoint 仅可在收到合法握手 / 合法 transport data 后更新

### 4.4 HandshakeState

至少包含：

- state // Idle | InitSent | InitReceived | ResponseSent
- local_index
- remote_index
- local_ephemeral_private
- local_ephemeral_public
- remote_ephemeral_public
- chaining_key
- handshake_hash
- is_initiator
- created_at

### 4.5 Session

至少包含：

- session_id
- role // Initiator | Responder
- status // Next | Current | Previous
- local_index
- remote_index
- send_key
- recv_key
- send_nonce
- recv_replay_window
- created_at
- confirmed // responder 是否已确认

### 4.6 IndexTable

- map: receiver_index -> Session

约束：

- 每个 active session index 全局唯一
- session 删除时必须从表中移除

---

## 五、协议消息类型

沿用 WireGuard 四类消息：

### 5.1 Handshake Initiation

- type = 1
- sender_index
- ephemeral
- encrypted_static
- encrypted_timestamp
- mac1
- mac2

### 5.2 Handshake Response

- type = 2
- sender_index
- receiver_index
- ephemeral
- encrypted_empty
- mac1
- mac2

### 5.3 Cookie Reply

- type = 3
- receiver_index
- nonce
- encrypted_cookie

### 5.4 Transport Data

- type = 4
- receiver_index
- counter
- encrypted_payload

约束：

- payload 为不透明字节流
- 每个 packet 承载一个 payload
- 不定义更高层 frame 结构

---

## 六、核心行为定义

### 6.1 Peer 注册

提供接口：

- add_peer(pubkey, endpoint?)
- remove_peer(peer_id)

规则：

- 未注册 peer 的所有包直接丢弃
- peer 是唯一信任边界

### 6.2 发送数据

提供接口：

- send_to_peer(peer_id, payload)

行为：

#### 情况 A：存在可用 session

- 使用 current session 加密发送

#### 情况 B：无 session

- 触发 handshake initiation
- 本次发送返回失败
- 不排队

#### 情况 C：current session 已经过 rekey_after_time 但未过 reject_after_time

- 允许本次发送
- 同时 opportunistic 发起 rekey

#### 情况 D：current session 已过 reject_after_time

- 不允许发送
- 触发 handshake
- 返回失败 / NoSession

### 6.3 接收数据

所有 UDP 包统一入口：

- on_udp_packet(packet, src_addr)

按 type 分发：

#### 6.3.1 收到 Initiation

- 不允许直接按 index 找 peer
- 必须按 WireGuard 语义通过解密 `encrypted_static` 识别 peer
- 验证合法性
- 若识别到已注册 peer，则更新 endpoint = src_addr
- 创建 / 更新 handshake state
- 发送 response

#### 6.3.2 收到 Response

- 匹配已有 pending handshake
- 更新 endpoint
- 建立 session（Next / Current）
- initiator 侧 session 可立即用于发送

#### 6.3.3 收到 Cookie Reply

- 更新 cookie
- 重发 initiation

#### 6.3.4 收到 Transport Data

- 根据 receiver_index 查 session
- 验证 counter / replay
- 解密 payload
- 更新 endpoint
- 若 responder 首次收到该 session 数据，则标记 confirmed
- 回调上层

### 6.4 Session 使用规则

#### Initiator

- 收到 response 后即可发送

#### Responder

- 必须等收到对端 transport data 才确认 session
- 未确认前不可发送

### 6.5 Session 轮换（Rekey）

触发条件：

- 时间到达（rekey_after_time）
- 或主动触发

行为：

- 发起新 handshake
- 新 session -> next
- 成功后提升为 current
- 原 current -> previous
- previous 超时删除

---

## 七、状态机约束

提供 peer 级抽象状态：

- Idle
- Connecting
- ConnectedUnconfirmed
- Connected
- Rekeying

说明：

- 该状态机仅用于抽象展示
- 不替代底层 current / previous / next 三槽会话结构

---

## 八、Replay Protection

### 8.1 Handshake

- 使用 timestamp 防重放

### 8.2 Transport

每个 session 维护：

- 最大 counter
- 滑动窗口 bitmap

规则：

- 小于窗口下界 -> 丢弃
- 已出现过 -> 丢弃

---

## 九、Endpoint / Roaming 语义

遵循 WireGuard 模型：

- endpoint 初始来自配置（可为空）
- 每次收到**合法握手消息**或**成功解密的合法 transport data**时更新为 src_addr
- cookie reply 不更新 endpoint
- 未完成认证 / 未成功解密的包不得更新 endpoint
- 后续发送始终使用最新合法 endpoint

---

## 十、错误处理策略

默认静默丢弃以下情况：

- 未注册 peer
- index 不存在
- replay 检测失败
- 解密失败
- 握手校验失败

约束：

- 非法包不向上层报告
- 仅可作为内部统计/日志
- 不向对端返回额外错误语义

---

## 十一、API 设计

### 初始化

- core = init(config)

### Peer 管理

- add_peer(pubkey, endpoint?)
- remove_peer(peer_id)

### 发送

- send_to_peer(peer_id, payload)

返回值至少包含：

- Success
- NoSession

### 接收回调

- on_receive(peer_id, payload)

### 主循环

支持以下两种之一，优先设计为单线程事件循环：

- poll()
  或
- start()/stop()

---

## 十二、并发模型（必须严格遵守）

第一版采用：

> **单线程事件循环 + 非阻塞 UDP socket**

约束：

- 所有 peer / handshake / session 状态仅在 Core 主循环线程内读写
- 所有网络输入统一走 `on_udp_packet(packet, src_addr)`
- 所有定时逻辑统一走 `poll(now)`
- 不引入多线程共享状态
- 不引入复杂锁
- 不引入 async runtime，除非我明确要求

---

## 十三、定时器模型

采用统一定时器调度器。

每个 peer 维护若干逻辑超时点，例如：

- handshake retry
- rekey
- session expiry
- keepalive（如果保留接口）
- stale state cleanup

由 Core 在 `poll(now)` 中统一检查并触发。

---

## 十四、握手重试策略

必须显式建模握手重试规则：

- 同一 peer 任一时刻仅允许一个本地发起的 pending handshake
- 若已有 pending handshake，则后续 rekey / connect 请求复用该状态，不重复创建
- initiation 发送后按 `Rekey-Timeout` 节奏重试
- 达到上限后进入失败状态并清理握手状态
- cookie reply 到达后，允许重发 initiation

---

## 十五、current / previous / next 三槽语义

必须严格按以下语义建模：

### current

- 当前优先发送使用的 session
- 可接收
- 可发送（若 responder 侧已 confirmed）

### previous

- 默认仅用于接收旧包
- 不用于发送
- 超时后删除

### next

- 新建但尚未完全确认的 session
- initiator 在收到 response 后可发送
- responder 在收到 initiator 首个 transport data 前不可发送

---

## 十六、WireGuard 语义对齐约束

### 16.1 身份模型

- 身份仅由静态 X25519 公钥定义
- 不引入用户名、证书、签名或额外身份字段

### 16.2 握手语义

- 保持 WireGuard initiation / response / cookie reply 语义
- responder 不为未通过最低门槛的包建立昂贵状态

### 16.3 会话语义

- 保留 current / previous / next
- responder 侧必须通过首个 transport 确认 session

### 16.4 Roaming 语义

- endpoint 仅在合法包到达后更新

### 16.5 数据报语义

- payload 不透明
- 不提供可靠性 / 重传 / 排序 / 分片

### 16.6 安全语义

- handshake anti-replay: timestamp
- transport anti-replay: counter + sliding window
- 非法包默认静默丢弃

---

## 十七、第一阶段实现范围

第一阶段必须实现：

- static identity
- peer registry
- initiation / response / transport
- current / previous / next session
- endpoint roaming
- transport replay protection
- time-based rekey
- handshake retry

第一阶段可留占位但不必完整实现：

- cookie reply 完整细节
- under-load DoS 策略
- keepalive 优化
- 统计指标
- 高性能优化

第一阶段明确不实现：

- 应用层可靠性
- 分片 / 重组
- VPN/IP encapsulation
- 多线程并发复杂度
- 上层协议解释

---

## 十八、代码生成要求

请严格按下面顺序输出，不要跳步，不要直接生成一大坨实现代码。

### 第一步：输出总体设计总结

内容应包括：

- 模块职责划分
- 数据流方向
- 状态机概览
- peer / handshake / session 生命周期关系

### 第二步：输出推荐目录结构

要求：

- 面向协议内核
- 不依赖 Linux kernel
- 不引入上层协议模块

### 第三步：输出核心数据结构定义草案

要求：

- 用清晰的类型定义表达
- 重点体现 Core / Peer / HandshakeState / Session / IndexTable / Timers

### 第四步：输出核心接口与函数签名

至少包括：

- init
- add_peer
- remove_peer
- send_to_peer
- poll
- on_udp_packet
- create_initiation
- consume_initiation
- create_response
- consume_response
- encrypt_transport
- decrypt_transport
- rotate_sessions
- maybe_rekey

### 第五步：输出关键状态流转图（文本形式即可）

至少包括：

- 建连
- 重试
- rekey
- responder session confirmation
- session rotation
- endpoint update

### 第六步：输出第一阶段最小代码骨架

要求：

- 只给出框架和占位实现
- 密码算法可以通过 trait / interface / placeholder 抽象
- 不要实现真正的密码算法细节
- 重点保证模块边界和状态机骨架正确

---

## 十九、重要限制

- 不要擅自引入可靠性层
- 不要擅自设计应用帧格式
- 不要把它改造成 TCP 风格连接协议
- 不要引入 TLS/QUIC/Noise 的额外抽象层，除非只是用于解释
- 不要偏离 WireGuard 核心会话语义
- 不要引入与 Linux 内核、TUN/TAP、路由表绑定的内容
- 不要在第一版引入复杂优化
- 不要省略状态机与生命周期设计

---

## 二十、输出风格要求

- 优先精确、结构化、工程化
- 所有关键假设必须写清楚
- 如需做实现决策，必须显式说明理由
- 先框架，后细节
- 不要一上来写完整实现
- 不要跳过模块边界和状态机

现在请严格按照“第十八节：代码生成要求”的顺序开始输出。

---

# 追加要求

```text
先不要生成代码。
只执行到第十八节中的前五步：
1. 总体设计总结
2. 推荐目录结构
3. 核心数据结构定义草案
4. 核心接口与函数签名
5. 关键状态流转图

等我确认后，再生成第一阶段代码骨架。
```
