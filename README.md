# cf-fusion

集三家所长的一体化 Cloudflare 边缘代理脚本（单文件 `_worker.js`，零依赖）：

| 来源 | 取其所长 |
|---|---|
| [byJoey/cfnew](https://github.com/byJoey/cfnew) | 多协议、图形化 KV 配置（改完即生效）、订阅本地自生成、自定义路径、出站代理 |
| [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel) | `/admin` 管理后台、PATH 动态切换底层代理、连接日志 |
| [yonggekkk/Cloudflare-vless-trojan](https://github.com/yonggekkk/Cloudflare-vless-trojan) | 本地化部署（不依赖第三方订阅转换）、默认 CF 官方优选 IP、单节点 path 改 proxyip |

## 功能

- **多协议**：VLESS / Trojan / Shadowsocks（简化版），走 WebSocket，TLS 由 Cloudflare 边缘终止
- **管理后台**：访问 `https://你的域名/admin`，图形化改配置，保存立即生效（需绑定 KV）
- **订阅自生成**：通用链接订阅、Clash、Sing-box 全部由 Worker 本地生成，不经过任何第三方转换服务
- **优选 IP**：默认内置 CF 官方 IP，可在后台增删改，也可开放 API 管理
- **延迟测试**：后台一键测优选 IP 的 TCP 建连延迟并排序
- **单连接覆盖**：在节点 path 或 query 里写 `proxyip=1.2.3.4` / `socks5=user:pass@host:port` / `http=host:port`，只影响当前节点（edgetunnel + 甬哥风格二合一）
- **出站代理**：全局 SOCKS5 / HTTP CONNECT 出站，三种回落策略（优先代理 / 优先直连 / 只走代理防泄漏）
- **ProxyIP**：目标为 TLS 端口时改拨反代 IP，靠客户端 TLS 的 SNI 寻路
- **首页伪装**：默认显示普通页面，可设 `FAKE_URL` 跳转
- **UDP**：经 TCP 透传（DNS over TCP 兼容），满足 DNS 查询等主要 UDP 场景

## 部署（三选一）

### 方式一：Workers 粘贴部署（最简单）

1. Cloudflare 控制台 → Workers 和 Pages → 创建 Worker
2. 把 `_worker.js` 的全部内容粘贴进编辑器，部署
3. （推荐）在设置 → 绑定 → 添加 KV 命名空间，变量名填 `KV`
4. （推荐）在设置 → 变量中把 `ADMIN_PASS` 改成你自己的密码
5. 给 Worker 绑定自定义域名（TLS 才稳定）
6. 访问 `https://你的域名/admin` 进入后台

### 方式二：wrangler

```bash
npx wrangler deploy
```

### 方式三：Pages 上传部署

Cloudflare Pages → 上传资产 → 把 `_worker.js`（文件名保持 `_worker.js`）上传部署，
之后同样绑定 KV、设置环境变量。

## 环境变量（全部可选）

| 变量 | 说明 | 默认 |
|---|---|---|
| `UUID` | VLESS UUID / Trojan 密码，不填自动生成并存 KV | 自动生成 |
| `ADMIN_PASS` | 后台密码 | `admin`（务必改） |
| `SUB_KEY` | 订阅路径密钥 | UUID 去横线前 8 位 |
| `CUSTOM_PATH` | 自定义订阅路径，设了则 UUID 路径自动禁用 | 空 |
| `PROXYIP` | 全局反代 IP/域名，如 `1.2.3.4` 或 `proxy.example.com:443` | 空 |
| `OUTBOUND` | 全局出站代理：`socks5://user:pass@host:port` 或 `http://host:port` | 空 |
| `OUTBOUND_MODE` | `proxy-first` 优先代理 / `direct-first` 优先直连 / `proxy-only` 只走代理 | `proxy-first` |
| `FAKE_URL` | 首页伪装跳转地址 | 空（显示默认页） |
| `P_VLESS` / `P_TROJAN` / `P_SS` | 协议开关 `1`/`0` | `1` / `1` / `0` |
| `MAX_NODES` | 订阅最多生成节点数（1–200） | `24` |

优先级：**后台面板（KV）> 环境变量 > 默认值**。面板「清空面板配置」可回退到环境变量。

## 地址与 API

设 `KEY` 为你的订阅路径密钥（默认 UUID 前 8 位）：

- `https://域名/KEY` — 分享页（订阅地址 + 节点链接 + 客户端推荐）
- `https://域名/KEY/sub` — 通用订阅（v2rayNG / NekoBox / Shadowrocket 直接用）
- `https://域名/KEY/clash` — Clash 订阅
- `https://域名/KEY/singbox` — Sing-box 订阅
- `https://域名/KEY/v2ray` — Base64 订阅
- `https://域名/admin` — 管理后台

单连接覆盖示例（只影响该节点）：

```
path: /KEY?proxyip=1.2.3.4
path: /KEY/proxyip=1.2.3.4          (PATH 风格)
path: /KEY?socks5=user:pass@1.2.3.4:1080
path: /KEY?http=user:pass@1.2.3.4:8080
```

SS 节点：WS 路径用 `/KEY/ss`，密码为 UUID（简化版无 AEAD，仅个人使用；通用 Clash 订阅不含 SS）。

## 后台 API（需 `Authorization: Bearer <后台密码>`）

- `POST /admin/api/auth` — 校验密码
- `GET/POST/DELETE /admin/api/config` — 读 / 写 / 清空配置
- `GET/POST /admin/api/ips` — 读 / 写优选 IP（`{"reset":true}` 恢复默认）
- `GET /admin/api/links` — 订阅地址
- `POST /admin/api/latency` `{"hosts":["1.1.1.1:443"]}` — 延迟测试
- `GET /admin/api/logs` — 连接日志（需先在配置里打开）

## 客户端推荐

- Android：v2rayNG / NekoBox / Karing / ClashMeta
- Windows：v2rayN / Hiddify / Karing / Clash Verge Rev
- iOS：Shadowrocket / Stash / Surge / Karing
- macOS：Clash Verge Rev / Surge / Stash
- 软路由：passwall / ssr-plus / homeproxy

## 说明与限制

- UDP 走 TCP 透传，只保证 DNS 这类场景；完整 UDP（如游戏语音）不支持
- `https://` 出站代理暂不支持，请用 `http://` 或 `socks5://`
- 未绑定 KV 时：UUID 自动生成但只存在内存（多实例可能不一致），**强烈建议直接设置 `UUID` 环境变量**
- 本项目仅供学习研究，请遵守当地法律法规

## 致谢

- [byJoey/cfnew](https://github.com/byJoey/cfnew)
- [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel)
- [yonggekkk/Cloudflare-vless-trojan](https://github.com/yonggekkk/Cloudflare-vless-trojan)
