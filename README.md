# fu-corplink

飞连（CorpLink）企业 VPN 的 self-hosted Web 控制面板 —— 浏览器登录、选节点、一个混合端口让任何设备走 VPN。

**非官方第三方实现，与飞连官方无关。** 协议参考 [corplink-rs](https://github.com/PinkD/corplink-rs)，控制面 / 数据面用 Go 重写，前端 React 18 + Tailwind v4。

## 特性

- **零特权** —— wireguard-go + gVisor netstack 用户态运行，无需 root / `/dev/net/tun`，容器友好
- **混合代理** —— 单端口同时支持 HTTP CONNECT / HTTP forward / SOCKS5，按首字节自动识别
- **多种登录** —— 密码 / LDAP / 邮箱验证码 / SSO（飞书 / OIDC）；2FA TOTP 自动管理
- **节点管理** —— 实时延迟探测 + 搜索 + 一键固定
- **单二进制** —— 前端 `//go:embed` 内嵌，无外部依赖

## 快速开始

### Docker

```bash
docker run -d --name corplink-web \
  --restart unless-stopped \
  -p 6151:6151 -p 8989:8989 \
  -v corplink-web-data:/etc/corplink \
  riba2534/corplink-web:latest
```

### Docker Compose

```yaml
services:
  corplink-web:
    image: riba2534/corplink-web:latest
    restart: unless-stopped
    ports:
      - "6151:6151"   # 控制面板
      - "8989:8989"   # 混合代理
    volumes:
      - corplink-web-data:/etc/corplink

volumes:
  corplink-web-data:
```

### 从源码构建

需要 Go >= 1.23、Node >= 20：

```bash
cd web/ui && npm ci && npm run build && cd ../..
cd web && go build -trimpath -o corplink-web ./cmd/corplink-web
./corplink-web --listen 127.0.0.1:6151 ./config.json
```

> 标签 `latest` 对应主分支最新构建；也可用 commit sha tag（如 `riba2534/corplink-web:a5fa0c9`）。自行构建镜像：`docker build -t corplink-web:latest .`

## 使用流程

1. 打开 `http://localhost:6151`
2. **输入企业代号** —— 你们公司飞连后台的组织标识（短英文，如 `your-company`）
3. **登录** —— 密码 / LDAP / 邮箱验证码 / SSO，界面自动探测可用方式
4. **选节点** —— 节点列表带实时延迟色阶（绿 < 60ms / 黄 60–150ms / 红），可搜索、固定
5. **连接** —— 连接成功后显示实时速率、累计流量、代理地址
6. **使用代理** —— 默认 `localhost:8989`，HTTP / SOCKS5 混合端口

> 如果节点启用了 2FA，连接时会弹出 6 位验证码输入框。

### 代理用法

```bash
# SOCKS5（推荐，socks5h:// 让 DNS 也走隧道）
curl --socks5-hostname 127.0.0.1:8989 https://ifconfig.me

# HTTP CONNECT
curl --proxy 127.0.0.1:8989 https://ifconfig.me

# HTTP plain forward
curl --proxy http://127.0.0.1:8989 http://example.com
```

**各平台配置**（代理地址填 `127.0.0.1:8989`，局域网场景填服务端 IP）：

| 平台 | 方式 |
|------|------|
| macOS | 系统设置 → 网络 → Wi-Fi → 代理 → HTTP / HTTPS / SOCKS |
| Linux | `export http_proxy=http://127.0.0.1:8989 https_proxy=http://127.0.0.1:8989` |
| Windows | 设置 → 网络和 Internet → 代理 → 手动 |
| 浏览器 | SwitchyOmega 等插件 |
| 手机 | Wi-Fi 代理设置（需代理端口暴露在局域网） |

## 配置

首次启动自动生成 `config.json`（含 device_id、WireGuard keypair、默认监听地址）。参考 [`config.example.json`](config.example.json)。

### 常用字段

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `socks_listen` | `0.0.0.0:8989` | 代理监听地址 |
| `vpn_server_id` | `0` | 固定节点 ID，0 = 按策略选 |
| `vpn_select_strategy` | `default` | `default` / `latency` |
| `route_mode` | `full` | `full`（全局）/ `split`（仅内网） |

`socks_listen`、节点策略、路由模式也可在 UI「设置」中修改，下次连接生效。

### 鉴权

**控制面板鉴权**（默认关闭，依赖 listen address 隔离）：

```json
{
  "admin_auth_enabled": true,
  "admin_username": "admin",
  "admin_password": "your-password"
}
```

**代理鉴权**（默认关闭）：

```json
{
  "proxy_auth_enabled": true,
  "proxy_username": "user",
  "proxy_password": "pass"
}
```

## 端口

| 端口 | 用途 | 何时可用 |
|------|------|----------|
| `6151` | 控制面板（前端 + API） | 启动即监听 |
| `8989` | HTTP / SOCKS5 混合代理 | VPN 连接后 |

控制面板地址由 `--listen` flag 指定（默认 `127.0.0.1:6151`）；代理地址改 `config.json` 或 UI 设置。Docker 用 `-p` 映射。

## 命令行

```
corplink-web [--listen host:port] [config.json]
```

收到 SIGINT / SIGTERM 会先断开 VPN 再优雅退出。

## 已知限制

- 仅 Linux / macOS 测试过，Windows 未端到端验证
- 上游飞连 API 偶有变更，不保证永远兼容
- 代理不支持 SOCKS5 UDP / BIND

## 安全

- 控制面板默认仅本机访问；暴露到网络请启用 `admin_auth_enabled` 或配合反向代理
- 代理默认 `0.0.0.0:8989`，无鉴权；暴露到不受信任网络请启用 `proxy_auth_enabled`
- `config.json` / `*cookies.json` 含私钥和登录态，不要 commit

## License

[MIT](LICENSE)
