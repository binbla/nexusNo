# 协议内核设计文档

## 1. 设计范围

本设计仅负责以下内容：

1. 维护本地身份与已注册 peer
2. 处理握手消息与 transport 数据包
3. 建立、确认、轮换和销毁会话
4. 通过会话对数据报进行加密发送与解密接收
5. 维护与 WireGuard 一致的：
   - 静态公钥身份模型
   - 握手中间状态
   - `current / previous + confirmed` 会话语义
   - transport anti-replay
   - endpoint roaming 语义

本设计不负责：

- 可靠性
- 顺序保证
- 分片 / 重组
- 上层协议解释
- VPN/IP 封装
- 网络接口设备抽象
- 底层 IO 多路复用实现细节

---

## 2. 总体设计目标

该内核是一个**基于 UDP 的点对点安全通信核心**。
每个节点使用静态 X25519 公钥作为长期身份，握手完成后导出短期 transport session。
所有数据包处理都围绕四个核心对象展开：

- `Core`
- `Peer`
- `Session`
- `HandshakeState`

整体目标是：

- 对预注册 peer 提供认证后的收发能力
- 对非法数据包静默丢弃
- 对合法握手建立最小必要状态
- 对 transport 数据包提供快速收包查找与独立 replay 防护
- 在 rekey 和 roaming 过程中保持语义与 WireGuard 对齐

---

## 3. 核心设计原则

### 3.1 Peer 是长期对象，Session 是短期对象

- `Peer` 表示一个逻辑对端，长期存在
- `Session` 表示一次握手导出的短期加密上下文，生命周期有限

### 3.2 不单独设计 PeerManager

系统不单独抽象 `PeerManager` 模块。
`Core` 直接维护 peer 集合，并提供：

- 添加 peer
- 删除 peer
- 按 peer_id 查找
- 按静态公钥查找

这更贴近 WireGuard 的工程思路。

### 3.3 Session 归属于 Peer

每个 peer 仅维护：

- `current`
- `previous`

不显式建模 `next`。
responder 新会话通过 `confirmed = false` 表达“尚未完成确认”的阶段。

### 3.4 通过 `local_index` 做全局收包查找

transport 包不带 peer 公钥，只带 `receiver_index`。
因此系统必须维护全局索引表：

- `local_index -> Session`

这是 transport 收包主路径的唯一快速入口。

### 3.5 握手状态是“已通过最低验证门槛后的最小状态”

系统并非“完全无握手状态”，而是：

- **不为未认证垃圾包建立状态**
- **仅在握手进入合法处理中时保存最小的 `HandshakeState`**

---

## 4. 核心对象模型

---

## 4.1 Core

### 定义

`Core` 是协议内核总控对象，负责：

- 管理本地身份
- 维护 peer 集合
- 维护全局 session index 表
- 驱动握手处理
- 驱动 transport 数据包处理
- 驱动 session 生命周期与 timer 检查

### 逻辑结构

```text
Core
├── local_identity
├── udp_socket
├── peers
├── index_table
├── config
├── callbacks
└── runtime state
```

### 主要职责

#### 1. 管理 peer 集合

`Core` 直接保存所有 peer，并提供：

- `add_peer`
- `remove_peer`
- `find_peer_by_id`
- `find_peer_by_static_pub`

#### 2. 维护全局 index 表

`Core` 或其内部 session 辅助逻辑必须维护：

- `local_index -> Session`

用于：

- transport 收包快速定位 session
- session 替换/销毁时同步更新索引

#### 3. 统一收包入口

所有 UDP 包统一进入：

- `on_udp_packet(packet, src_addr, now)`

然后按消息类型分发到：

- initiation 处理
- response 处理
- cookie reply 处理
- transport 处理

#### 4. 统一时间驱动入口

所有定时逻辑统一由：

- `poll(now)`

驱动，包括：

- 握手重试
- rekey
- previous 清理
- stale cleanup
- keepalive（若后续保留）

### 不负责的事情

`Core` 不解释 payload 内容，不提供可靠性，也不定义上层 frame。

---

## 4.2 Peer

### 定义

`Peer` 是一个长期存在的通信对象，表示“一个允许通信的远端身份”。

### 核心字段

当前草案中，`Peer` 已包含以下关键字段：

- `peer_id`
- `remote_static_public_key`
- `endpoint`
- `handshake_state`
- `keypairs.current`
- `keypairs.previous`
- `last_handshake_time_ms`
- `last_send_time_ms`
- `last_recv_time_ms`
- `timers`

### 语义

#### 1. 以远端静态公钥作为身份锚点

`remote_static_public_key` 是 peer 的核心身份字段。
所有握手最终都必须绑定到某个已注册 peer。

#### 2. 保存最新 endpoint

`endpoint` 是 peer 当前用于发包的目标地址。
其更新遵循 WireGuard roaming 语义：

- 收到**合法握手消息**
- 或成功解密的**合法 transport data**
- 才允许更新 `endpoint = src_addr`

#### 3. 保存握手状态

每个 peer 最多保留一个 `HandshakeState`，用于支撑当前进行中的握手。

#### 4. 保存会话状态

每个 peer 只维护两代会话：

- `current`
- `previous`

这与当前草案中的 `PeerKeypairs` 一致。

#### 5. 保存 peer 级时间信息

例如：

- 最近握手时间
- 最近发送时间
- 最近接收时间
- 各类逻辑定时点

### peer 的职责边界

peer 自身只承载状态，不承担复杂算法逻辑。
算法逻辑由 Core 内部的握手处理与 session 处理函数驱动。

---

## 4.3 Session

### 定义

`Session` 是一次合法握手导出的短期 transport keypair。
它对应 WireGuard 工程里的 keypair 概念。

### 当前核心字段

当前草案中的 `Session` 具有：

- `peer_id`
- `role`
- `local_index`
- `remote_index`
- `send_key`
- `recv_key`
- `send_nonce`
- `replay`
- `created_at_ms`
- `last_send_at_ms`
- `last_recv_at_ms`
- `rekey_after_time_at_ms`
- `reject_after_time_at_ms`
- `confirmed`

### 会话语义

#### 1. `local_index`

表示：

> 本端为该 session 分配的接收索引

即对端向本端发送 transport data 时，必须把这个值写入 `receiver_index`。
它是全局 `index_table` 的 key。

#### 2. `remote_index`

表示：

> 对端为该 session 分配的接收索引

即本端发送 transport data 时，要把它写入消息中的 `receiver_index`。

#### 3. `send_key / recv_key`

用于 transport data 的对称加解密。

#### 4. `send_nonce`

用于发送路径的计数器。
每次成功发送 transport 包后递增。

#### 5. `replay`

用于接收路径 anti-replay。
当前草案中的 `ReplayWindow` 结构是：

- `max_counter`
- `bitmap`

注意：当前 `bitmap` 仅为最小版本，实际窗口大小需要与设计常量保持一致。

#### 6. `confirmed`

这是贴近 WireGuard 的关键语义：

- initiator 创建的 session：收到合法 response 后立即 `confirmed = true`
- responder 创建的 session：发送 response 后先 `confirmed = false`
- responder 只有在收到 initiator 的第一条合法 transport data 后，才将其置为 `true`

#### 7. `role`

表示该 session 是在：

- initiator 侧创建
- 还是 responder 侧创建

它决定 `can_send()` 的行为。

---

## 4.4 HandshakeState

### 定义

`HandshakeState` 是一次进行中的握手上下文。

它的存在目的不是“为任意来包建状态”，而是：

> 为已经进入合法处理路径的握手保存最小必要中间状态。

### 当前核心字段

当前草案中的 `HandshakeState` 包含：

- `state`
- `local_index`
- `remote_index`
- `local_ephemeral_private`
- `local_ephemeral_public`
- `remote_ephemeral_public`
- `chaining_key`
- `handshake_hash`
- `is_initiator`
- `created_at_ms`
- `last_sent_timestamp`
- `retry_count`

### 语义

#### 1. 保存握手中间变量

因为握手不是单步完成，必须保存：

- 中间密钥链状态
- 握手哈希状态
- 临时密钥
- 本地 / 对端握手索引

#### 2. 连接 initiation 与 response

本端发出 initiation 后，收到 response 时必须能找到：

- 对应 peer
- 对应本地 ephemeral
- 对应本地 index
- 对应握手状态

#### 3. 支撑 KDF 连续推进

握手中 `C/H` 会持续演化，因此这些中间值必须保留到 session 导出完成。

#### 4. 生命周期短

`HandshakeState` 只在握手进行期间存在。
握手完成并导出 session 后，应尽快清理。

### 状态类型

当前草案定义了：

- `Idle`
- `InitSent`
- `InitReceived`
- `ResponseSent`

这已经足够支撑第一版协议流程。

---

## 5. Session 组织方式

---

## 5.1 不使用 `current / previous / next`

本设计不采用显式三槽 `next` 模型。
而采用更贴近 WireGuard 的：

- `current`
- `previous`
- `confirmed`

### 原因

responder 新建会话后，不需要单独放在 `next`。
直接装入 `current` 即可，但其：

- `role = Responder`
- `confirmed = false`

只有在收到 initiator 第一条合法 transport 后，才允许发送。

---

## 5.2 `current`

当前主会话。

用途：

- 默认发送使用
- 正常接收使用

发送条件：

- initiator 侧：始终可发送
- responder 侧：必须 `confirmed == true`

---

## 5.3 `previous`

上一代旧会话。

用途：

- 仅用于接收旧包
- 不用于发送

意义：

- 吸收 rekey 之后仍在网络中的延迟包或乱序包

---

## 5.4 安装新 session 的轮换规则

新 session 安装时：

1. 原 `previous` 删除
2. 原 `current` 下沉到 `previous`
3. 新 session 安装到 `current`

然后按角色决定：

- initiator：`current.confirmed = true`
- responder：`current.confirmed = false`

---

## 6. 数据包处理路径

---

## 6.1 总入口

### 函数语义

所有收到的 UDP 数据报统一进入：

```text
on_udp_packet(packet, src_addr, now)
```

处理顺序：

1. 基础长度与类型检查
2. 按 `message_type` 分发
3. 调用对应处理逻辑
4. 根据结果更新：
   - peer endpoint
   - handshake state
   - session 状态
   - 上层回调

---

## 6.2 Handshake Initiation 处理

### 输入

- 收到 `HandshakeInitiation`
- 来源地址 `src_addr`

### 处理目标

1. 识别对应 peer
2. 验证握手合法性
3. 建立 / 更新 `HandshakeState`
4. 导出 responder 侧新 session
5. 发送 response

### 处理步骤

#### 1. 基础检查

- 检查长度
- 检查 `message_type`
- 检查保留字节

#### 2. 最低门槛验证

至少要完成最小必要检查，避免为无意义数据包建立状态。

#### 3. 识别 peer

按 WireGuard 语义，initiation 不能直接靠 index 找 peer，
必须通过握手解密路径识别并匹配某个已注册 peer。

#### 4. 更新 peer.endpoint

只有当 initiation 已被成功识别为某个合法 peer 后，才允许：

```text
peer.endpoint = src_addr
```

#### 5. 更新 `HandshakeState`

保存：

- `remote_ephemeral_public`
- `local_index`
- `remote_index`
- `chaining_key`
- `handshake_hash`
- 角色信息
- 计时信息

#### 6. 创建 responder 侧 session

导出 transport keys，创建新 `Session`：

- `role = Responder`
- `confirmed = false`

安装到：

- `peer.current`

旧 current 下沉为 previous。

#### 7. 发送 response

构造 `HandshakeResponse` 并发出。

---

## 6.3 Handshake Response 处理

### 输入

- 收到 `HandshakeResponse`
- 来源地址 `src_addr`

### 处理目标

1. 匹配已有 initiation 对应的 `HandshakeState`
2. 完成握手导出
3. 创建 initiator 侧新 session
4. 安装为 current

### 处理步骤

#### 1. 基础检查

- 类型
- 长度
- receiver_index

#### 2. 匹配握手

使用 response 中的 `receiver_index` 与本地 pending handshake 匹配。

#### 3. 完成握手推导

利用 `HandshakeState` 中保存的：

- 本地 ephemeral private
- 远端 ephemeral public
- chaining key
- handshake hash

完成最终 key 导出。

#### 4. 创建 initiator 侧 session

新建 `Session`：

- `role = Initiator`
- `confirmed = true`

#### 5. 安装新 session

执行轮换：

- previous 删除
- current -> previous
- new -> current

#### 6. 更新 endpoint

response 合法时更新：

```text
peer.endpoint = src_addr
```

#### 7. 清理握手状态

成功导出 session 后，清理 `HandshakeState`。

---

## 6.4 Cookie Reply 处理

### 输入

- 收到 `CookieReply`

### 处理目标

1. 识别对应 peer / pending handshake
2. 更新临时 cookie 状态
3. 触发 initiation 重发

### 说明

第一版若不完整实现 under-load DoS 逻辑，可以保留接口与占位流程。

---

## 6.5 Transport Data 处理

### 输入

- 收到 `TransportData`
- 来源地址 `src_addr`

### 处理目标

1. 通过 `receiver_index` 命中 session
2. 校验 replay
3. 解密 payload
4. 更新 session / peer 状态
5. 若 responder current 尚未确认，则确认之
6. 回调上层

### 处理步骤

#### 1. 通过 `receiver_index` 找 session

使用全局 `index_table`：

```text
receiver_index -> Session
```

#### 2. 校验 replay

基于 session 自身的 replay window 检查：

- 是否太旧
- 是否重复
- 是否在窗口内未出现过

#### 3. 解密 payload

使用 session 的：

- `recv_key`
- `counter`

解密 transport payload。

#### 4. 更新 peer.endpoint

只有解密成功后才更新：

```text
peer.endpoint = src_addr
```

#### 5. responder 会话确认

若命中的 session 为：

- `peer.current`
- `role == Responder`
- `confirmed == false`

则：

```text
current.confirmed = true
```

从此该 current 可用于发送。

#### 6. 交付上层

payload 作为不透明字节流交给上层 receive callback。

---

## 7. 发送路径设计

---

## 7.1 发送入口

```text
send_to_peer(peer_id, payload, now)
```

### 返回语义

可返回：

- `Success`
- `NoSession`
- 其他内部错误码（如加密失败）

---

## 7.2 current 选择规则

发送时只考虑 `peer.current`。

### 可以发送的条件

1. `current` 存在
2. 未到 reject 阈值
3. `current.can_send() == true`

即：

- initiator current 直接可发
- responder current 必须 confirmed 后可发

### 不能发送的条件

- current 不存在
- current 已 reject
- responder current 未确认

---

## 7.3 send 时与 rekey 的关系

若 current 已达到 rekey 条件但未到 reject 条件：

- 本次仍允许使用 current 发送
- 同时触发新握手

这与 WireGuard 的 opportunistic rekey 思路一致。

---

## 8. 会话生命周期与轮换

---

## 8.1 新会话创建时机

新 session 只能来自合法握手：

- initiator 在 `consume_response()` 后创建
- responder 在 `consume_initiation()` / `create_response()` 路径中创建

---

## 8.2 previous 的存在意义

previous 只用于接收，不参与发送。
它用来承接：

- rekey 之后飞行中的旧包
- 延迟包
- 少量乱序包

---

## 8.3 previous 清理时机

previous 在以下情况下删除：

- 被新一轮 current 下沉覆盖
- 到达过期时间
- peer 被移除
- 系统做 stale cleanup

删除时必须：

- 从 index_table 移除
- 清理敏感状态

---

## 8.4 reject 行为

当 current 达到 reject 条件后：

- 不允许继续发送
- 不应继续作为正常可用会话使用
- 等待新握手建立替代 current

---

## 9. 握手状态生命周期

---

## 9.1 创建时机

`HandshakeState` 只在以下情况下创建或覆盖：

- 本端主动发送 initiation
- 收到已进入合法处理路径的 initiation

不会因为任意垃圾包创建状态。

---

## 9.2 生命周期

握手状态是短生命周期对象，用于：

- 保存中间密钥链状态
- 保存 ephemeral key
- 保存索引与计数信息
- 支撑 response 到来后的 session 导出

---

## 9.3 销毁时机

以下情况应清理握手状态：

- session 成功建立
- 重试失败
- 超时
- 被新的握手覆盖

---

## 10. Core 与对象关系

整体关系如下：

```text
Core
├── local_identity
├── peers
│   └── Peer
│       ├── remote_static_public_key
│       ├── endpoint
│       ├── handshake_state
│       ├── current
│       └── previous
└── index_table
    └── local_index -> Session
```

### 关系说明

- `Peer` 是 session 的拥有者
- `Session` 通过 `peer_id` 反向指向所属 peer
- `index_table` 是 transport 收包的快速索引
- `HandshakeState` 只服务于短暂握手过程

---

## 11. 推荐的实现边界

为了保持设计清晰，建议模块边界如下：

### Core

- 总控与统一入口
- 持有 peer 集合与 index 表

### Peer

- 长期对象，只保存状态

### Session

- transport keypair 与 replay 状态

### HandshakeState

- 握手中间态

### 协议处理函数

由 Core 内部或相邻实现文件提供：

- `consume_initiation`
- `consume_response`
- `consume_cookie_reply`
- `consume_transport`
- `send_to_peer`
- `poll`

---

## 12. 结论

本设计采用了更贴近 WireGuard 的工程模型：

- 不单独设计 `PeerManager`
- `Core` 直接维护 peer 集合
- `Peer` 持有 `current / previous`
- 以 `confirmed` 表达 responder 侧未确认 current
- 以全局 `local_index -> Session` 作为 transport 收包入口
- `HandshakeState` 仅为合法握手流程保存最小必要中间状态

这个模型足以支撑你后续实现：

- 握手处理
- 会话导出
- transport 收发
- rekey / previous 保留
- endpoint roaming

下一步最自然的工作是把这份设计继续落成：

1. `Core` 结构体与接口定义
2. `HandshakeEngine` 处理流程与函数签名
3. `Session` 安装/轮换/清理的具体实现接口
4. `Transport` 收发主路径伪代码

如果你要，我下一条可以直接继续把这份设计文档扩成**“Core/Handshake/Session/Transport 四个模块的头文件级接口设计”**。
