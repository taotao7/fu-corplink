# fu-corplink

飞连（CorpLink）企业 VPN 的 self-hosted Web 控制面板。它把飞连登录、节点选择、WireGuard 用户态隧道和本地代理整理成一个浏览器可操作的服务：打开网页，输入企业代号，登录，选节点，连接后使用一个 HTTP / SOCKS5 混合代理端口。

**非官方第三方实现，与飞连官方无关。** 协议和接口行为参考 [corplink-rs](https://github.com/PinkD/corplink-rs)，后端和数据面用 Go 实现，前端是 React 18 + Vite + Tailwind CSS v4。

## 当前功能

- **Web 控制台**：内嵌 SPA，提供 admin 鉴权页、企业代号设置、登录、节点列表、连接状态、实时流量、设置和退出。
- **飞连登录流程**：支持企业代号解析、密码 / LDAP 登录、邮箱验证码登录，以及飞连接口返回的 SSO / TPS 登录项。
- **用户态 VPN**：使用 wireguard-go + gVisor netstack，不依赖 root、TUN 设备或系统路由表，适合容器运行。
- **混合代理端口**：同一监听地址自动识别 SOCKS5、HTTP CONNECT 和普通 HTTP forward；支持可选代理用户名密码。
- **节点选择**：可拉取节点、探测延迟、搜索、手动固定节点；也可使用默认策略或最低延迟策略自动选择。
- **路由和协议控制**：支持 `full` / `split` 路由模式，自动避开 peer IP 路由环；WireGuard 传输协议可自动、强制 UDP 或强制 TCP。
- **运行态观测**：连接后展示当前节点、代理地址、上传/下载速率和累计流量。
- **单二进制交付**：前端构建产物由 Go `embed` 打进后端二进制。

## 目录结构

```text
web/cmd/corplink-web        # 程序入口，加载配置并启动 HTTP 服务
web/internal/corplink       # 飞连 API、登录、WireGuard 配置、netstack、混合代理
web/internal/vpnmgr         # 连接状态机、配置更新、流量采样、admin 会话
web/internal/server         # 控制面板 API、admin gate、静态 SPA
web/ui                      # React 控制台
config.example.json         # 配置示例
Dockerfile                  # 前端构建 + Go 静态二进制 + Debian runtime
```

## 快速开始

### Docker 本地构建

```bash
docker build -t fu-corplink:dev .
docker run -d --name fu-corplink \
  -p 6151:6151 \
  -p 8989:8989 \
  -v fu-corplink-data:/etc/corplink \
  fu-corplink:dev
```

容器默认执行：

```bash
corplink-web --listen 0.0.0.0:6151 /etc/corplink/config.json
```

首次启动会在配置文件中补齐 device_id、Android 设备信息和 WireGuard keypair。登录会话 cookie 会保存在配置文件同目录。

### Docker Compose

```yaml
services:
  corplink-web:
    image: taotao7/fu-corplink:dev
    restart: unless-stopped
    ports:
      - "6151:6151" # Web 控制台
      - "8989:8989" # HTTP / SOCKS5 混合代理
    volumes:
      - corplink-web-data:/etc/corplink

volumes:
  corplink-web-data:
```

如果使用本地构建镜像，把 `image` 改成你构建时使用的名字。

### 从源码构建

需要 Go >= 1.23、Node >= 20。

```bash
cd web/ui
npm ci
npm run build

cd ..
go build -trimpath -o corplink-web ./cmd/corplink-web
./corplink-web --listen 127.0.0.1:6151 ./config.json
```

前端开发时可以单独跑 Vite，`/api` 会代理到本地 Go 后端的 `6151` 端口：

```bash
cd web/ui
npm run dev
```

## 使用流程

1. 打开 `http://localhost:6151`。
2. 如果启用了控制台鉴权，先输入 admin 用户名和密码。
3. 输入企业代号，服务会解析飞连企业信息和后端域名。
4. 根据页面展示的方式登录：密码 / LDAP、邮箱验证码，或 SSO / TPS。
5. 在节点列表中搜索、刷新延迟、固定节点；不固定时按配置策略自动选择。
6. 点击连接。若服务端要求 OTP 且本地没有 TOTP secret，页面会要求输入 6 位验证码。
7. 连接成功后使用代理。实际监听地址由 `socks_listen` 决定，默认 `0.0.0.0:8989`；同机客户端通常填 `127.0.0.1:8989`。

### 代理用法

```bash
# SOCKS5，推荐 socks5h:// 让 DNS 也走隧道
curl --socks5-hostname 127.0.0.1:8989 https://ifconfig.me

# HTTP CONNECT
curl --proxy 127.0.0.1:8989 https://ifconfig.me

# 普通 HTTP forward
curl --proxy http://127.0.0.1:8989 http://example.com
```

局域网内其他设备要使用代理时，把代理地址里的 `127.0.0.1` 换成运行 fu-corplink 的机器 IP，并确保端口对该网络可达。

## 配置

程序默认读取当前目录的 `config.json`；也可以把配置路径作为最后一个参数传入：

```bash
corplink-web --listen 127.0.0.1:6151 ./config.json
```

参考 [config.example.json](config.example.json)。缺失或空配置文件会被自动初始化。

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `company_name` | 空 | 飞连企业代号，页面输入后会写入配置 |
| `username` | 空 | 最近一次登录用户名 |
| `socks_listen` | `0.0.0.0:8989` | 混合代理监听地址 |
| `vpn_server_id` | `0` | 固定节点 ID；`0` 表示不固定 |
| `vpn_select_strategy` | `default` | `default` 为首个探测可达节点，`latency` 为最低延迟节点 |
| `route_mode` | `full` | `full` 使用服务端全局路由，`split` 使用服务端分流路由 |
| `force_protocol` | 空 | 空值按节点 `protocol_mode` 自动选择，也可设为 `udp` / `tcp` |
| `upstream_proxy` | 空 | 把 fu-corplink 的所有出站（飞连 API、WireGuard 传输）走一个上游 HTTP/SOCKS5 代理，用于和系统级 TUN VPN 共存（见下） |
| `proxy_auth_enabled` | `false` | 是否要求代理鉴权 |
| `proxy_username` / `proxy_password` | 空 | SOCKS5 用户名密码和 HTTP `Proxy-Authorization` Basic 凭据 |
| `admin_auth_enabled` | `false` | 是否启用 Web 控制台鉴权 |
| `admin_username` / `admin_password` | 空 | Web 控制台 admin 凭据 |
| `device_id`、`public_key`、`private_key` | 自动生成 | 飞连设备身份和 WireGuard keypair |

`socks_listen`、节点选择策略、路由模式和 WireGuard 协议也可以在 Web 控制台的“设置”里修改；代理监听地址会在下次连接时生效。

## HTTP API

前端调用的是同进程 REST API，主要端点如下：

| 端点 | 作用 |
| --- | --- |
| `/api/state` | 当前连接状态、企业、用户、代理地址 |
| `/api/company` | 保存企业代号并解析企业信息 |
| `/api/login/methods` | 获取密码 / LDAP / SSO 登录能力 |
| `/api/login/password` | 密码或 LDAP 登录 |
| `/api/login/email/request`、`/api/login/email/verify` | 邮箱验证码登录 |
| `/api/login/tps/check` | 轮询 SSO / TPS 登录结果 |
| `/api/servers` | 获取节点列表，可带 `probe=false` 跳过延迟探测 |
| `/api/connect`、`/api/disconnect` | 建立或断开 VPN |
| `/api/traffic` | 连接后的速率和累计流量 |
| `/api/config` | 读取或更新可编辑配置 |
| `/api/admin/auth`、`/api/admin/login`、`/api/admin/logout` | Web 控制台鉴权 |

## 端口

| 端口 | 用途 | 默认来源 |
| --- | --- | --- |
| `6151/tcp` | Web 控制台和 API | `--listen`，源码默认 `127.0.0.1:6151`，Docker 默认 `0.0.0.0:6151` |
| `8989/tcp` | HTTP / SOCKS5 混合代理 | `socks_listen`，默认 `0.0.0.0:8989` |

## 安全提示

- 这是非官方实现，不要把它当作飞连官方客户端或官方安全边界。
- Docker 默认把控制台绑定到 `0.0.0.0:6151`。暴露到非可信网络前，请启用 `admin_auth_enabled`，或放在防火墙 / 反向代理鉴权后面。
- 代理默认监听 `0.0.0.0:8989` 且不鉴权。对局域网或公网开放前，请启用 `proxy_auth_enabled` 或限制监听地址。
- 配置目录包含 device_id、WireGuard private key、登录会话 cookie 和可能的用户名密码；请按敏感数据处理。

## 与系统级 TUN VPN 共存（Stash / Clash / Surge 等）

fu-corplink 用用户态 WireGuard，自身不建 TUN、不动系统路由表。但当**系统级 TUN VPN**（如 Stash、Clash、Surge 的 TUN/Enhanced Mode）开启时，它会用 `0.0.0.0/1` + `128.0.0.0/1` 这种比默认路由更具体的路由把**整机出站**（包括 fu-corplink 自己的飞连 API 请求和 WireGuard 传输）都收进 TUN，于是 fu-corplink 的握手会被 TUN VPN 的规则左右，时而失效；反过来 fu-corplink 的流量也可能干扰 TUN VPN。表现为“开了 corplink 后 git/内网走不通，关了又好”，或“访问内网时 corplink 失效但其它正常”。

解决方法是把 fu-corplink 的出站交给那个 TUN VPN 的**混合代理端口**（它对代理客户端的流量会按规则走真实接口，而不进自己的 TUN 抓取）：

1. 在 TUN VPN 客户端里确认它的 HTTP/SOCKS5 混合端口（Stash 默认 `7890`，监听 `0.0.0.0` 或局域网可达）。
2. 在 fu-corplink 的“设置 → 上游代理 (upstream_proxy)”里填该地址：
   - 本机直跑：`http://127.0.0.1:7890`
   - Docker 里跑（容器要访问宿主机）：`http://host.docker.internal:7890`
   - 也可写 `socks5://...`。
3. 把“WireGuard 协议”设为**强制 TCP**（UDP 没法走 HTTP 代理；SOCKS5 UDP ASSOCIATE 多数消费级客户端不支持）。

设置后 fu-corplink 的飞连 API 调用、节点探测、WireGuard 隧道都从该代理出去，与 TUN VPN 互不抢占，stash 的 TUN 功能完整保留。留空则恢复直连（默认）。

## 已知限制

- 飞连上游接口可能变化，兼容性不保证长期稳定。
- SOCKS5 UDP 和 BIND 未实现；当前混合代理只处理 TCP 场景。
- `upstream_proxy` 走 HTTP 代理时只支持 TCP 传输（WireGuard 协议需设为 `tcp`）；UDP 传输不被代理。
- Windows 未做端到端验证。
- `full` / `split` 都依赖飞连服务端返回的路由；如果服务端没有返回全局路由，程序会拒绝盲目回退到 `0.0.0.0/0`，避免 peer IP 路由环。

## License

[MIT](LICENSE)
