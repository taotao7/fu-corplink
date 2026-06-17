# fu-corplink

飞连（CorpLink）企业 VPN 的 self-hosted Web 控制面板

> 浏览器登录 · 浏览器选节点 · 一个 HTTP / SOCKS5 端口让任何设备走 VPN

**非官方第三方实现，与飞连官方均无任何关联。**
Fork 自 [PinkD/corplink-rs](https://github.com/PinkD/corplink-rs)（飞连客户端的 Rust 实现），控制面与数据面已全部用 Go 重写，前端用 React 18 + Tailwind v4 + shadcn/ui 重做。

## 特性

- **零特权运行** —— wireguard-go + gVisor netstack 跑在用户态，不创建系统网卡、不改主机路由 / DNS；不需要 root / NET_ADMIN / `/dev/net/tun`，容器与沙箱友好
- **HTTP / SOCKS5 混合代理** —— 单端口同时支持 HTTP CONNECT、HTTP plain forward 和 SOCKS5（按首字节自动识别，类似 mihomo 的 mixed-port）；DNS 在隧道内解析，避免泄漏
- **现代浅色 UI** —— 登录、选节点、查实时速率、复制代理地址、退出登录一站完成
- **多种登录方式** —— 密码 / LDAP / 邮箱验证码 / 第三方 SSO（lark / OIDC）；2FA TOTP 自动管理
- **节点管理** —— 实时延迟探测 + 搜索 / 排序 + 一键固定节点；含可视化延迟色阶
- **单二进制** —— 前端通过 `//go:embed` 内嵌进 Go binary，无外部资源依赖

## 快速开始

### Docker（推荐）

镜像已发布在 Docker Hub，多架构（linux/amd64 + linux/arm64），开箱即用：

```bash
docker run -d --name corplink-web \
  --restart unless-stopped \
  -p 6151:6151 -p 23456:23456 \
  -v corplink-web-data:/etc/corplink \
  riba2534/corplink-web:latest
```

打开 `http://localhost:6151` → 输入企业代号 → 登录 → 选节点 → 连接。
连接成功后 `http://localhost:23456` 即可作为 HTTP / SOCKS5 代理使用。

> 标签 `latest` 始终指向主分支最新构建。需要锁定具体版本时，可使用以 commit sha 命名的 tag（例如 `riba2534/corplink-web:a5fa0c9`）。

如果想自己从源码构建镜像：

```bash
docker build -t corplink-web:latest .
```

### 从源码构建

需要 Go ≥ 1.23、Node ≥ 20。

```bash
# 1. 编译前端（产物 embed 到 Go binary 里）
cd web/ui && npm ci && npm run build && cd ../..

# 2. 编译 Go binary
cd web && go build -trimpath -o corplink-web ./cmd/corplink-web

# 3. 启动（首次会自动生成 config.json + WireGuard keypair）
./corplink-web --listen 127.0.0.1:6151 ./config.json
```

## 把代理暴露给宿主机 / 局域网

代理默认 listen 在 `0.0.0.0:23456`（HTTP / SOCKS5 混合），任何能连到这个端口的客户端都能用：

```bash
# SOCKS5（用 socks5h:// 让 DNS 也走隧道，避免泄漏）
curl --socks5-hostname 127.0.0.1:23456 https://ifconfig.me

# HTTP CONNECT（HTTPS 走隧道）
curl --proxy 127.0.0.1:23456 https://ifconfig.me

# HTTP plain forward（明文 HTTP）
curl --proxy http://127.0.0.1:23456 http://example.com
```

> 代理本身没有鉴权。如果暴露在 `0.0.0.0` 上，任何能到达这个端口的客户端都能拿你的企业 VPN 当跳板。生产部署请放在带防火墙规则、源 IP 白名单或 VPN 网络隔离的环境里。

## 配置

首次启动若 `config.json` 不存在或为空，会自动写入 `device_id`、WireGuard keypair、默认 `socks_listen` 等字段。常用可调项：

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `company_name` | (自动) | 企业代号（首次在 UI 输入后写入） |
| `username` | (自动) | 登录用户名 |
| `socks_listen` | `0.0.0.0:23456` | 代理监听地址（HTTP / SOCKS5 混合） |
| `vpn_server_id` | `0` | 固定节点 ID；`0` 表示按策略选 |
| `vpn_select_strategy` | `default` | `default`（首个可达）/ `latency`（最低延迟） |
| `route_mode` | `full` | `full`（默认，全局）/ `split`（按服务端下发的 routes） |

`socks_listen` 也可以直接在 UI 的 **设置** 弹窗里改，保存后下次连接生效。

> `*cookies.json` 与配置同目录，存登录态；这两类文件都包含敏感信息（WireGuard 私钥、登录会话、企业代号），任何情况下都不要 commit 到公开仓库（已在 `.gitignore` 里）。

## 端口

| 端口 | 用途 | 何时 listen |
|------|------|-------------|
| `6151` | HTTP 控制面板（前端 + REST API） | 进程启动即 listen |
| `23456` | HTTP / SOCKS5 混合代理 | 仅当 VPN 已连接时 |

两个端口都可以通过 Docker `-p 主机端口:容器端口` 自由映射；代理端口也能改 `config.json` 的 `socks_listen`，控制面板端口由 `--listen` 命令行 flag 指定。

## 已知限制

- 代理无鉴权（仅 SOCKS5 CONNECT、HTTP CONNECT、HTTP plain forward；不支持 SOCKS5 UDP / BIND）—— 由部署侧通过防火墙做访问控制
- 仅在 Linux / macOS 测试过；Windows 理论支持（wireguard-go 自身支持），但未做端到端验证
- 上游飞连 API 偶有变更，不保证与最新版后端永远兼容

## 安全注意事项

- 控制面板没有内置鉴权，依赖 listen address 和网络层隔离做防护。默认 `127.0.0.1:6151` 仅本机访问，要暴露到 LAN 请显式 `--listen 0.0.0.0:6151` 并配合防火墙 / 反向代理 + 鉴权；也可在 config 里开 `admin_auth_enabled` 启用内置的管理员登录
- 代理默认 `0.0.0.0:23456`，详见上面"代理暴露"段落
- `config.json` / `*cookies.json` 含私钥与登录态，任何情况下都不要 commit

## 贡献

欢迎 issue 与 PR。提交前请确认：

- 没有夹带个人 / 公司敏感信息（`config.json`、`*cookies.json`、登录态截图等）
- `cd web/ui && npm run build` 与 `cd web && go build ./...` 都可通过
- 改动有清晰的动机说明

开发流程与项目结构详见 [CLAUDE.md](CLAUDE.md)。

## 致谢

- 上游：[PinkD/corplink-rs](https://github.com/PinkD/corplink-rs) —— 飞连客户端的 Rust 实现
- WireGuard 用户态实现：[wireguard-go](https://git.zx2c4.com/wireguard-go)
- 用户态网络栈：[gVisor](https://gvisor.dev)
- UI 组件：[shadcn/ui](https://ui.shadcn.com) + [Tailwind CSS](https://tailwindcss.com) + [lucide](https://lucide.dev)
