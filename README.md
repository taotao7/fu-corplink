# fu-corplink

飞连（CorpLink）企业 VPN 的 **self-hosted Web 控制面板**。它把飞连的登录、节点选择、WireGuard 用户态隧道和本地代理整理成一个浏览器可操作的服务：打开网页 → 输入企业代号 → 登录 → 选节点 → 连接，之后本机/局域网通过一个 HTTP / SOCKS5 混合代理端口访问企业内网。

> **非官方第三方实现，与飞连官方无关。**
> 协议行为参考上游 Rust 客户端 [PinkD/corplink-rs](https://github.com/PinkD/corplink-rs)；控制面与数据面用 Go 重写，前端用 React 18 + Vite + Tailwind CSS v4 重做。整个系统编译为**单个静态二进制**（前端产物 `go:embed` 进后端）。

---

## 目录

- [核心特性](#核心特性)
- [整体架构](#整体架构)
- [连接生命周期](#连接生命周期)
- [隧道自愈机制](#隧道自愈机制)
- [快速开始](#快速开始)
- [使用流程](#使用流程)
- [代理用法](#代理用法)
- [配置参考](#配置参考)
- [HTTP API](#http-api)
- [端口](#端口)
- [与系统级-tun-vpn-共存](#与系统级-tun-vpn-共存stash--clash--surge-等)
- [协议要点](#协议要点)
- [安全提示](#安全提示)
- [已知限制](#已知限制)
- [开发](#开发)

---

## 核心特性

- **Web 控制台** — 内嵌单页应用（SPA），涵盖 admin 鉴权、企业代号设置、登录、节点列表、连接状态、实时流量、设置、退出。
- **完整登录流程** — 企业代号解析、密码 / LDAP 登录、邮箱验证码登录、飞连返回的 SSO / TPS（Lark / OIDC）登录项，以及标准 TOTP 二次验证。
- **零特权用户态 VPN** — 基于 `wireguard-go` + gVisor netstack，不需要 root、不创建 TUN 设备、不改系统路由表，天然适合容器运行。
- **混合代理端口** — 同一监听地址上自动识别 SOCKS5 / HTTP CONNECT / 普通 HTTP forward，可选代理用户名密码鉴权。
- **智能节点选择** — 拉取节点、并发探测延迟、搜索、手动固定；未固定时按 `default`（首个可达）或 `latency`（最低延迟）策略自动选择。
- **路由与协议控制** — `full` / `split` 路由模式，自动裁剪 peer IP 避免路由环；WireGuard 传输协议可自动 / 强制 UDP / 强制 TCP。
- **隧道自愈** — 后台持续监控握手时效与真实数据面，用 **make-before-break** 无缝换隧道，抵抗飞连网关的"心跳完整性"数据面切断。
- **与 TUN VPN 共存** — 可把自身全部出站（API + WireGuard 传输）走一个上游 HTTP/SOCKS5 代理，与 Stash / Clash 等系统级 TUN VPN 互不抢占。
- **单二进制交付** — 前端构建产物由 Go `embed` 打进后端二进制，一个文件即可运行。

---

## 整体架构

系统分为四层，全部编译进同一个 Go 二进制，UI 是被 `embed` 的静态资源：

```
┌────────────────────────────────────────────────────────────────────┐
│  浏览器（React SPA）                                                  │
│  ui/src: App.tsx 状态机 · api.ts 类型化 REST 客户端 · components/*    │
└───────────────────────────────┬────────────────────────────────────┘
                                 │  JSON REST /api/*
┌───────────────────────────────▼────────────────────────────────────┐
│  server —— HTTP 控制面（internal/server）                            │
│  server.go 路由 · handlers.go 业务处理 · admin.go 鉴权网关 · spa.go   │
│  职责：解析请求、admin gate、把动作转交 Manager、回吐 JSON            │
└───────────────────────────────┬────────────────────────────────────┘
                                 │  Go 方法调用
┌───────────────────────────────▼────────────────────────────────────┐
│  vpnmgr —— 编排层 / 状态机（internal/vpnmgr）                        │
│  manager.go 状态+快照 · connect.go 连接/断开/采样/自愈循环            │
│  admin.go 会话+失败限流 · config_ops.go 配置读写视图                  │
│  职责：串行化状态转移、跑后台循环（采样/上报/握手监控/隧道刷新）      │
└───────────────────────────────┬────────────────────────────────────┘
                                 │  协议 + 数据面调用
┌───────────────────────────────▼────────────────────────────────────┐
│  corplink —— 协议 + 数据面（internal/corplink，核心）                │
│  client.go 协议客户端  connect.go 选节点+组装 WgConf                  │
│  crypto/totp/cookiejar 鉴权   netstack.go 用户态 WireGuard            │
│  proxy.go / proxy_http.go 混合代理   upstream.go 上游代理路由         │
└───────────────────────────────┬────────────────────────────────────┘
                                 │  wireguard-go UAPI + gVisor netstack
                        ┌────────▼────────┐          ┌──────────────────┐
                        │ 飞连企业网关     │          │ 本机/局域网客户端 │
                        │ (WireGuard peer) │◀────────▶│ 走 :8989 混合代理 │
                        └─────────────────┘          └──────────────────┘
```

### 各层职责

| 层 | 包 | 关键文件 | 职责 |
| --- | --- | --- | --- |
| **入口** | `cmd/corplink-web` | `main.go` | 解析 `--listen` 和 config 路径、加载配置、装配三层、起 HTTP、优雅关停 |
| **控制面** | `internal/server` | `server.go` `handlers.go` `admin.go` `spa.go` | REST 路由、admin 中间件、SPA fallback；不含业务逻辑，纯转交 |
| **编排层** | `internal/vpnmgr` | `manager.go` `connect.go` `admin.go` `config_ops.go` | 连接状态机、流量采样、隧道健康监控与自愈、admin 会话与限流 |
| **协议 + 数据面** | `internal/corplink` | `client.go` `connect.go` `netstack.go` `proxy*.go` `crypto.go` `totp.go` `cookiejar.go` `upstream.go` | 飞连 API、登录/加密/TOTP、WgConf 组装与路由裁剪、用户态 WireGuard、混合代理、上游代理路由 |
| **前端** | `ui/` | `App.tsx` `api.ts` `components/*` | 状态机驱动的控制台 UI；构建产物 embed 进 `internal/server/dist` |

### 关键设计取舍

- **单进程、单二进制、状态在磁盘 config** —— 没有数据库。config 文件（`config.json`）既是配置也是持久化状态（device_id、WireGuard keypair、最近节点），会话 cookie 存在同目录的 `corplink_cookies.json`。
- **数据面全用户态** —— gVisor netstack 让 WireGuard 完全跑在用户空间，代理把 TCP 流"接"进 netstack，不碰宿主机网络栈。因此可以非特权容器运行，也能和宿主机上其它 VPN 并存。
- **编排层是唯一的状态权威** —— `Manager` 用一把 `sync.Mutex` 串行化所有状态转移（`logged_out → logged_in → connecting → connected → disconnecting`），server 层无状态，UI 靠轮询 `/api/state` 和 `/api/traffic` 反映真相。

---

## 连接生命周期

一次完整连接的数据流（浏览器动作 → 后端调用链）：

```
POST /api/company        → corplink.GetCompany      解析企业服务器域名，写入 config
POST /api/login/password → client.LoginWithPassword 密码/LDAP 登录（feilian: sha256；feilian_v1: AES）
                           （或 邮箱验证码 / SSO-TPS 轮询）
GET  /api/servers        → client.ListVPN + ProbeLatencies   并发探测各节点延迟
POST /api/connect        → Manager.Connect → connectReal：
      ① client.ListVPN + SelectVPN     按策略或固定 ID 选节点
      ② client.FetchPeerInfo(otp)      用我方公钥 + TOTP 换 wg 握手信息
      ③ client.BuildWgConf             组装 + 裁剪路由（carve peer IP，避免环）
      ④ corplink.StartNetstack…        起用户态 wireguard-go 隧道
      ⑤ device.Probe                   连通前先探测数据面（in-tunnel DNS:53）
      ⑥ corplink.NewMixedProxy         起 HTTP/SOCKS5 混合代理并监听
      ⑦ client.ReportDevice(type=100)  上报连接
      ⑧ 起 4 个后台循环（见下）
GET  /api/traffic        → Manager.Traffic()   浏览器 ~1.5s 轮询实时速率
POST /api/disconnect     → Manager.Disconnect  上报断开 + teardown
```

连接成功后 `connectReal` 启动 **4 个后台协程**，全部随断开/重连取消：

| 循环 | 周期 | 作用 |
| --- | --- | --- |
| `runSampler` | 1s | 采样字节计数算实时速率；缓存 WireGuard peer stats；记录 app 级 tx/rx/dial 时间供自愈判断 |
| `runReporter` | 60s | 定期 `ReportDevice` 保活，防止网关侧 session 过期 |
| `runHandshakeWatch` | 5s | 双信号检测隧道死亡（握手过期 / 有出站需求但无入站），触发 make-before-break 刷新 |
| `runRefresher` | 18s | 主动在网关"完整性切断"前用新 session 换隧道 |

---

## 隧道自愈机制

飞连网关有两类会悄悄打断连接的行为，普通的 WireGuard 存活检查看不出来。fu-corplink 用多重手段应对，目标是**代理连接零感知**：

**1. 主动刷新（make-before-break，`runRefresher`）**
部分飞连网关强制一个"客户端完整性心跳"——官方客户端每隔几秒上报一个加密报文，网关看不到它就会在连接约 60s 后静默切断数据面（`/vpn/report` 回 `{"code":1000,"action":"alert"}`）。我们无法伪造该私有心跳，于是**在旧隧道到期前**（默认 18s）后台**建一条全新隧道**（新 session、新的切断预算），先探测其数据面可用，再把代理**原子热切换**过去，旧隧道 drain 10s 后关闭。整个过程监听端口不断、在途连接不掉。

刷新换上的新隧道必须先通过**双重数据面探测**：除了隧道内 DNS（`223.5.5.5:53`），还要能连通**用户最近实际访问过的内网目标**之一——新 session 有时能通 DNS 但到内网网段（如 `172.16.x`）的路由要再过几秒才收敛，只探 DNS 会把代理切到一条"半通"的隧道上。前几次构建尝试严格要求内网目标可达，最后一次放宽为仅 DNS，避免内网服务真宕机时卡死轮换。

**2. 死亡检测（双信号，`runHandshakeWatch`）**
每 5s 判断当前隧道是否已死：
- **握手过期** —— `latest-handshake` 超过 210s（超过 WireGuard 自身 rekey 窗口），说明对端彻底不响应。
- **带负载假存活（RX stall）** —— 有真实出站需求（app 级发送字节增长 **或** 代理发起了 dial），但 20s 内无任何真实入站字节。这是"网关照常回握手却丢光数据包"的签名，只看握手永远发现不了。
命中任一信号就优先走 make-before-break 刷新；刷新本身失败才回退到硬重连（`reconnect`）。

**3. 代理拨号自动骑上新隧道（dial retry）**
落在"旧隧道已死、新隧道未换上"死窗口里的代理请求不会直接吃 502：每次拨号尝试限时 5s，失败特征像死隧道（超时 / `operation aborted`）就等 500ms 重新快照当前隧道再试，直到总预算 25s 用完——预算刻意大于一个完整刷新周期（18s），保证请求至少能在下一条已验证的新隧道上试一次。明确错误（如 connection refused）不重试、立即返回。

**4. HTTP 转发断点续传（forward resume）**
普通 HTTP 转发（非 CONNECT）按请求逐个拨号（绝不复用可能已死的隧道连接），响应体 6s 无进展即判定"会话被网关中途吊销"，换新隧道用 `Range` 续传拼接，客户端看到的是一条无缝完整响应。重试预算按"连续零进展次数"计（推进就重置），且每次重试会等刷新器换上**新一代**隧道再动手，不在已证死的隧道上浪费尝试。只有幂等请求（GET/HEAD 且无调用方 Range）参与续传。

**5. 不可变资产缓存（immutable asset cache）**
内容哈希命名的静态资产（Vite/webpack 的 `name-HASH.js` 等）天然不可变，完整中转成功一次后进入 64MiB LRU 内存缓存，之后的重复加载**完全不经过隧道**、毫秒级返回——页面刷新从此与隧道抖动解耦。被打断的传输前缀也会跨请求累积（浏览器重试从上次进度继续，而不是从零开始）。只缓存完整走完的 200 响应，动态路径永不缓存。

**6. 断线自动重连（reconnect retry）**
刷新失败回退硬重连时，控制面 API 的瞬时故障（EOF / 超时——往往恰好发生在数据面抖动时）会以 5s 间隔重试最多 5 次，而不是首败即放弃把整个代理打回 logged_in；只有会话真正失效（logged out）才立即停止并提示重新登录。

**7. 只看应用级流量，绝不误伤空闲隧道**
所有需求/停顿判断都基于 `countingConn` 的**应用级**字节和 dial 尝试，**不看** WireGuard 线级计数——因为 keepalive 会让线级字节永远增长。空闲隧道没有出站需求，任何自愈路径都不会动它。

> 相关常量集中在 `vpnmgr/manager.go`、`vpnmgr/connect.go`、`corplink/proxy.go` 和 `corplink/proxy_http.go`：`handshakeStaleAfter=210s`、`rxStallAfter=20s`、`tunnelRefreshAfter=18s`、`tunnelDrainAfter=10s`（按在途连接引用计数最长扩到 90s）、`minRefreshInterval=8s`、`proxyDialTimeout=25s`、`proxyDialAttemptTimeout=5s`、`forwardStallTimeout=6s`、`forwardSwapWait=30s`、`assetCacheBudget=64MiB`。判定逻辑抽成纯函数（`reconnectReason`、`probeTunnel`、`isRetryableDialError`、`isImmutableAssetPath`、`retryReconnect`），有单元测试覆盖。

---

## 快速开始

> 前端构建产物已随仓库提交（`web/internal/server/dist`），所以**只跑 `go build` 就能得到一个可用的二进制**——无需先构建前端。只有改动 `web/ui/` 下的前端源码时才需要重新构建前端。

### 方式一：从源码构建（推荐，最少依赖）

只装 Go（>= 1.23）即可运行：

```bash
git clone https://github.com/taotao7/fu-corplink.git
cd fu-corplink/web

# 构建二进制（dist 已在仓库里，直接 embed）
go build -trimpath -o corplink-web ./cmd/corplink-web

# 运行；config.json 不存在会自动创建并填好 device_id / WireGuard keypair
./corplink-web --listen 127.0.0.1:6151 ./config.json
```

启动后打开 <http://127.0.0.1:6151>。想让局域网访问就换成 `--listen 0.0.0.0:6151`（注意先看[安全提示](#安全提示)）。

> ⚠️ **本机开着 Stash / Clash / Surge 等代理软件（TUN 模式）？** 先按 [与系统级 TUN VPN 共存](#与系统级-tun-vpn-共存stash--clash--surge-等) 一节配置上游代理再点连接，否则连接会时通时断。

如需修改并重建前端（Node >= 20）：

```bash
cd web/ui && npm ci && npm run build   # 输出到 ../internal/server/dist，会被 embed
cd .. && go build -trimpath -o corplink-web ./cmd/corplink-web
```

### 方式二：Docker（本地构建镜像）

仓库自带多阶段 `Dockerfile`（前端 → Go 静态二进制 → debian-slim 运行时），本地构建即可，无需拉取预发布镜像：

```bash
git clone https://github.com/taotao7/fu-corplink.git
cd fu-corplink

docker build -t fu-corplink:dev .

docker run -d --name fu-corplink \
  -p 6151:6151 \
  -p 8989:8989 \
  -v fu-corplink-data:/etc/corplink \
  fu-corplink:dev
```

容器默认执行 `corplink-web --listen 0.0.0.0:6151 /etc/corplink/config.json`，首次启动会在挂载卷里自动生成 `config.json`（含 `device_id`、Android 设备信息、WireGuard keypair）；登录会话 cookie 也保存在同目录。

> ⚠️ **本机开着 Stash / Clash / Surge 等代理软件（TUN 模式）？** 直接启动后连接会时通时断（表现为握手失败、连上后很快断流）。这不是 bug，是两个 VPN 在抢整机路由——启动后先按 [与系统级 TUN VPN 共存](#与系统级-tun-vpn-共存stash--clash--surge-等) 一节配置上游代理再点连接。

**Docker Compose（推荐）**：仓库根目录自带 [`docker-compose.yml`](docker-compose.yml)，克隆后直接：

```bash
git clone https://github.com/taotao7/fu-corplink.git
cd fu-corplink

docker compose up -d --build     # 本地构建镜像并后台启动
```

首次启动会在数据卷 `fu-corplink-data` 里自动生成 `config.json` 和会话 cookie；容器随 Docker 自动重启（`restart: unless-stopped`）。查看日志用 `docker compose logs -f`，停止用 `docker compose down`（数据卷保留，下次 `up` 复用登录态）。

compose 已内置 `extra_hosts: host.docker.internal:host-gateway`，Linux 原生 Docker 也能访问宿主机上的系统级代理（配合下方“与系统级 TUN VPN 共存”一节的 `upstream_proxy`）。

### 前端热更新开发

```bash
cd web/ui && npm run dev   # Vite 把 /api 代理到本地 6151 的 Go 后端
```

---

## 使用流程

1. 打开 `http://localhost:6151`。
2. 若启用了控制台鉴权，先输入 admin 用户名和密码。
3. 输入企业代号，服务解析出飞连企业信息和后端域名。
4. 按页面展示的方式登录：密码 / LDAP、邮箱验证码，或 SSO / TPS。
5. 在节点列表中搜索、刷新延迟、固定节点；不固定时按配置策略自动选择。
6. 点击连接。若服务端要求 OTP 且本地无 TOTP secret，页面会要求输入 6 位验证码。
7. 连接成功后使用代理。监听地址由 `socks_listen` 决定，默认 `0.0.0.0:8989`；同机客户端通常填 `127.0.0.1:8989`。

---

## 代理用法

```bash
# SOCKS5（推荐 socks5h:// 让 DNS 也走隧道）
curl --socks5-hostname 127.0.0.1:8989 https://ifconfig.me

# HTTP CONNECT
curl --proxy 127.0.0.1:8989 https://ifconfig.me

# 普通 HTTP forward
curl --proxy http://127.0.0.1:8989 http://example.com
```

局域网内其它设备使用代理时，把 `127.0.0.1` 换成运行 fu-corplink 的机器 IP，并确保端口对该网络可达。

---

## 配置参考

程序默认读取当前目录的 `config.json`；也可把路径作为最后一个参数传入。缺失或空文件会被自动初始化。参考 [config.example.json](config.example.json)。

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `company_name` | 空 | 飞连企业代号，页面输入后写入 |
| `username` | 空 | 最近一次登录用户名 |
| `socks_listen` | `0.0.0.0:8989` | 混合代理监听地址 |
| `vpn_server_id` | `0` | 固定节点 ID；`0` = 不固定 |
| `vpn_select_strategy` | `default` | `default` 首个探测可达节点；`latency` 最低延迟节点 |
| `route_mode` | `full` | `full` 用服务端全局路由；`split` 用服务端分流路由 |
| `force_protocol` | 空 | 空 = 按节点 `protocol_mode` 自动；也可 `udp` / `tcp` |
| `upstream_proxy` | 空 | 把 fu-corplink 全部出站走上游 HTTP/SOCKS5 代理，与系统级 TUN VPN 共存（见下） |
| `proxy_auth_enabled` | `false` | 是否要求代理鉴权 |
| `proxy_username` / `proxy_password` | 空 | SOCKS5 凭据 / HTTP `Proxy-Authorization` Basic |
| `admin_auth_enabled` | `false` | 是否启用 Web 控制台鉴权 |
| `admin_username` / `admin_password` | 空 | Web 控制台 admin 凭据 |
| `device_id`、`public_key`、`private_key` | 自动生成 | 飞连设备身份 + WireGuard keypair |

`socks_listen`、节点选择策略、路由模式、WireGuard 协议、上游代理也可在 Web 控制台的"设置"里改；代理监听地址在下次连接时生效。

---

## HTTP API

前端调用的是同进程 REST API（除 `/api/admin/*` 建立鉴权外，其余端点都过 `requireAdmin` 网关）：

| 端点 | 作用 |
| --- | --- |
| `GET  /api/state` | 当前连接状态、企业、用户、代理地址 |
| `POST /api/company` | 保存企业代号并解析企业信息 |
| `GET  /api/login/methods` | 获取密码 / LDAP / SSO 登录能力 |
| `POST /api/login/password` | 密码或 LDAP 登录 |
| `POST /api/login/email/request`、`/api/login/email/verify` | 邮箱验证码登录 |
| `POST /api/login/tps/check` | 轮询 SSO / TPS 登录结果 |
| `GET  /api/servers` | 节点列表，可带 `probe=false` 跳过延迟探测 |
| `POST /api/connect`、`/api/disconnect` | 建立 / 断开 VPN |
| `GET  /api/traffic` | 连接后的速率和累计流量 |
| `GET/POST /api/config` | 读取 / 更新可编辑配置 |
| `POST /api/logout` | 退出登录 |
| `/api/admin/auth`、`/api/admin/login`、`/api/admin/logout` | Web 控制台鉴权（不过 requireAdmin 网关） |

---

## 端口

| 端口 | 用途 | 默认来源 |
| --- | --- | --- |
| `6151/tcp` | Web 控制台和 API | `--listen`；源码默认 `127.0.0.1:6151`，Docker 默认 `0.0.0.0:6151` |
| `8989/tcp` | HTTP / SOCKS5 混合代理 | `socks_listen`，默认 `0.0.0.0:8989` |

---

## 与系统级 TUN VPN 共存（Stash / Clash / Surge 等）

fu-corplink 用用户态 WireGuard，自身不建 TUN、不动系统路由表。但当**系统级 TUN VPN**开启时，它会用 `0.0.0.0/1` + `128.0.0.0/1` 这种比默认路由更具体的路由把**整机出站**（包括 fu-corplink 自己的飞连 API 请求和 WireGuard 传输）都收进 TUN，于是 fu-corplink 的握手被 TUN VPN 的规则左右、时而失效；反过来 fu-corplink 的流量也可能干扰 TUN VPN。典型表现："开了 corplink 后 git/内网走不通，关了又好"。

解决办法是把 fu-corplink 的出站交给那个 TUN VPN 的**混合代理端口**（它对代理客户端的流量会按规则走真实接口，而不进自己的 TUN 抓取）。

### 第一步：确认代理软件的混合端口

在你的代理软件里找到 HTTP/SOCKS5 混合监听端口，并**确保"允许局域网连接 (Allow LAN)"已打开**（Docker 方式运行时容器是从虚拟网卡访问宿主机的，只监听 127.0.0.1 会连不上）：

| 软件 | 默认混合端口 | 备注 |
| --- | --- | --- |
| Stash | `7890` | 设置 → HTTP 端口 |
| Clash / Clash Verge / mihomo | `7890`（或 `mixed-port` 配置值） | 打开 Allow LAN |
| Surge | `6152`（HTTP）/ `6153`（SOCKS5） | 设置 → HTTP 监听地址 |
| V2rayN / V2rayA | `10809`（HTTP）/ `10808`（SOCKS5） | 以实际配置为准 |

### 第二步：配置 fu-corplink 上游代理

**方式 A：Web 控制台（推荐）** —— 打开控制台 → 设置：

1. **上游代理 (`upstream_proxy`)** 填：
   - 源码直跑：`http://127.0.0.1:7890`
   - Docker 运行：`http://host.docker.internal:7890`（Docker Desktop / OrbStack 内置该域名；Linux 原生 Docker 见下）
   - SOCKS5 也可以：`socks5://127.0.0.1:7890`
2. **WireGuard 协议 (`force_protocol`)** 选 **强制 TCP**（UDP 无法走 HTTP 代理；SOCKS5 UDP ASSOCIATE 多数消费级客户端不支持）。
3. 保存后（重新）点连接。

**方式 B：直接改 `config.json`**（改完重启服务）：

```jsonc
{
  // ... 其余字段保持自动生成的值 ...
  "upstream_proxy": "http://host.docker.internal:7890",  // 源码直跑用 http://127.0.0.1:7890
  "force_protocol": "tcp"
}
```

**Linux 原生 Docker** 没有 `host.docker.internal`，启动容器时加一行映射即可：

```bash
docker run -d --name fu-corplink \
  --add-host host.docker.internal:host-gateway \
  -p 6151:6151 \
  -p 8989:8989 \
  -v fu-corplink-data:/etc/corplink \
  fu-corplink:dev
```

（Docker Compose 里等价写法是在服务下加 `extra_hosts: ["host.docker.internal:host-gateway"]`。）

### 第三步：验证

连接成功后，通过 fu-corplink 的代理访问一个内网地址：

```bash
curl --proxy http://127.0.0.1:8989 http://<某内网服务>/ -m 10 -o /dev/null -w '%{http_code}\n'
```

返回业务状态码（如 `200` / `302`）即为打通。若返回 `502`，查看服务日志里的 `dial ... failed`；若日志出现 `transport conn ... 7890: connection refused`，说明上游代理端口没通（回到第一步检查 Allow LAN / 端口号）。

设置后 fu-corplink 的 API 调用、节点探测、WireGuard 隧道都从该代理出去，与 TUN VPN 互不抢占。`upstream_proxy` 留空则恢复直连（默认，适合没开代理软件的环境）。

---

## 协议要点

- **鉴权** —— 没有 HMAC 签名。靠 cookie jar 会话 + 从 `csrf-token` cookie 复制到同名 header（双提交）+ 固定 `User-Agent`。
- **密码** —— `feilian` 平台发 `sha256(password)`；`feilian_v1` 发 AES-256-CBC 加密（key=`hex(md5("9007199254740991"))`，iv=`hex(sha1(key))[:16]`，PKCS7，结果 hex）。
- **2FA** —— 标准 TOTP（HMAC-SHA1，6 位，30s），密钥来自登录后 `/api/v2/p/otp` 的 otpauth uri；用服务器 `Date` 头校正时钟偏移。
- **连接** —— `/vpn/conn` 用我方公钥 + OTP 换 wg 握手信息；`route_mode=full` 用 `vpn_route_full`，`split` 用 `vpn_route_split`；自动把对端 endpoint IP 从 AllowedIPs 里裁掉避免路由环。
- **数据面** —— wireguard-go 的 gVisor netstack 模式，零特权；通过 wg-go UAPI 配置（`private_key`/`public_key`/`endpoint`/`allowed_ip`/`persistent_keepalive_interval=10`）。

---

## 安全提示

- 这是非官方实现，不要当作飞连官方客户端或官方安全边界。
- Docker 默认把控制台绑定到 `0.0.0.0:6151`。暴露到非可信网络前，请启用 `admin_auth_enabled`，或放在防火墙 / 反向代理鉴权后面。
- 代理默认监听 `0.0.0.0:8989` 且不鉴权。对局域网或公网开放前，请启用 `proxy_auth_enabled` 或限制监听地址。
- 配置目录含 device_id、WireGuard private key、登录会话 cookie 和可能的用户名密码；请按敏感数据处理（已在 `.gitignore`）。

---

## 已知限制

- 飞连上游接口可能变化，长期兼容性不保证。
- SOCKS5 UDP 和 BIND 未实现；当前混合代理只处理 TCP 场景。
- `upstream_proxy` 走 HTTP 代理时只支持 TCP 传输（WireGuard 协议需设为 `tcp`）；UDP 传输不被代理。
- Windows 未做端到端验证。
- `full` / `split` 都依赖飞连服务端返回的路由；若服务端没返回全局路由，程序会拒绝盲目回退到 `0.0.0.0/0`，避免 peer IP 路由环。

---

## 开发

```bash
# 提交前检查清单
cd web/ui && npm run build              # TypeScript 严格检查 + Vite 构建
cd web && go build ./... && go test ./... && go vet ./...
# 勿夹带 config.json / *cookies.json / 登录态等敏感信息（已在 .gitignore）
```

更详细的开发流程、目录说明和协议实现参考见 [CLAUDE.md](CLAUDE.md)。

---

## License

[MIT](LICENSE)
</content>
</invoke>
