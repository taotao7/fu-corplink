# CLAUDE.md

开发流程与项目结构说明。

## 这是什么

`fu-corplink` 是飞连（CorpLink）企业 VPN 的 self-hosted Web 控制面板，非官方第三方实现。
协议参考上游 Rust 实现 [PinkD/corplink-rs](https://github.com/PinkD/corplink-rs)，控制面 / 数据面用 Go 重写，前端用 React 重做。

## 仓库结构

```
.
├── Dockerfile              # 多阶段构建：前端 -> Go binary -> debian-slim 运行时
├── README.md
└── web/
    ├── go.mod
    ├── cmd/corplink-web/    # main：解析 flag、加载 config、起 HTTP 控制面
    ├── internal/
    │   ├── corplink/        # 协议 + 数据面（核心）
    │   │   ├── config.go        # 配置读写、默认值、device_id / keypair 生成
    │   │   ├── crypto.go        # x25519 keypair、feilian_v1 AES 密码、sha256/md5
    │   │   ├── totp.go          # RFC 4226/6238 TOTP（HMAC-SHA1, 6 位, 30s）
    │   │   ├── api.go           # API endpoint URL 模板
    │   │   ├── resp.go          # 上游响应结构体
    │   │   ├── cookiejar.go     # 持久化 cookie jar + csrf + 跨 host 复制
    │   │   ├── client.go        # 协议客户端：登录 / list / connect / report
    │   │   ├── connect.go       # 选节点 + 组装 WgConf + 路由裁剪
    │   │   ├── wgconf.go        # WgConf 结构 + CIDR 相减
    │   │   ├── netstack.go      # 用户态 WireGuard（wireguard-go + gVisor）
    │   │   ├── proxy.go         # 混合代理：SOCKS5
    │   │   └── proxy_http.go    # 混合代理：HTTP CONNECT / forward
    │   ├── vpnmgr/          # 编排层：状态机、流量采样、握手监控、admin 鉴权
    │   │   ├── manager.go       # Manager：状态、节点列表、流量快照
    │   │   ├── connect.go       # 连接 / 断开 / 采样 / 握手超时重连
    │   │   ├── admin.go         # 管理员会话 / 失败限流；Manager.Logout
    │   │   └── config_ops.go    # 企业解析、config 读写视图
    │   └── server/          # HTTP 控制面：REST API + SPA
    │       ├── server.go        # 路由、JSON 助手、admin 中间件挂载
    │       ├── handlers.go      # 所有 /api/* 处理函数
    │       ├── admin.go         # /api/admin/* + requireAdmin 网关
    │       ├── spa.go           # go:embed dist + SPA fallback
    │       └── dist/            # 前端构建产物（embed 进 binary）
    └── ui/                  # React 18 + Vite + Tailwind v4 前端源码
        ├── src/api.ts          # 类型化 REST 客户端
        ├── src/App.tsx         # 状态机驱动的主界面
        ├── src/components/      # 各屏幕组件
        └── src/ui/             # Button / Card / Dialog 基础组件
```

## 数据流（一次完整连接）

```
浏览器 → POST /api/company        → corplink.GetCompany   → 解析企业服务器域名
浏览器 → POST /api/login/password → client.LoginWithPassword
浏览器 → GET  /api/servers        → client.ListVPN + ProbeLatencies（并发探测延迟）
浏览器 → POST /api/connect        → manager.Connect:
            client.SelectVPN      （按策略 / 固定节点选）
            client.FetchPeerInfo  （带 TOTP，拿 wg 握手信息）
            client.BuildWgConf    （组装 + 裁剪路由）
            corplink.StartNetstack（用户态 wireguard-go 起隧道）
            corplink.NewMixedProxy（起 HTTP/SOCKS5 混合代理）
            client.ReportDevice   （上报连接 type=100）
浏览器 → GET  /api/traffic        （1.5s 轮询实时速率）
```

## 开发命令

```bash
# 前端开发（带热更新，代理 /api 到本地 6151 的 Go 后端）
cd web/ui && npm run dev

# 后端开发：先 build 一次前端产物，再跑 Go
cd web/ui && npm run build && cd ..
go run ./cmd/corplink-web --listen 127.0.0.1:6151 ./config.json

# 全量构建
cd web/ui && npm ci && npm run build && cd ..
go build -trimpath -o corplink-web ./cmd/corplink-web

# 测试 / 检查
cd web && go test ./... && go vet ./...
cd web/ui && npm run build   # tsc 严格检查 + vite 构建
```

## 提交前检查清单

- `cd web/ui && npm run build` 通过（含 TypeScript 严格检查）
- `cd web && go build ./... && go test ./... && go vet ./...` 通过
- 没有夹带 `config.json` / `*cookies.json` / 登录态等敏感信息（已在 `.gitignore`）

## 协议要点（实现参考）

- **签名**：没有 HMAC 签名。鉴权靠 cookie jar 会话 + 从 `csrf-token` cookie 复制到同名 header（双提交）+ 固定 `User-Agent`。
- **密码**：`feilian` 平台发送 `sha256(password)`；`feilian_v1` 发送 AES-256-CBC 加密（key=`hex(md5("9007199254740991"))`，iv=`hex(sha1(key))[:16]`，PKCS7，结果 hex）。
- **2FA**：标准 TOTP（HMAC-SHA1，6 位，30s），密钥来自登录后 `/api/v2/p/otp` 的 otpauth uri；用服务器 `Date` 头校正时钟偏移。
- **连接**：`/vpn/conn` 用我方公钥 + OTP 换 wg 握手信息；`route_mode=full` 用 `vpn_route_full`，`split` 用 `vpn_route_split`；自动把对端 endpoint IP 从 AllowedIPs 里裁掉以避免路由环。
- **数据面**：wireguard-go 的 gVisor netstack 模式，零特权；通过 wg-go UAPI 配置（`private_key`/`public_key`/`endpoint`/`allowed_ip`/`persistent_keepalive_interval=10`）。
```
