# cf-fusion

集百家所长的一体化 Cloudflare 边缘代理脚本（单文件 `_worker.js`，零依赖）：

| 来源 | 角色与汲取所长 |
|---|---|
| [zizifn/edgetunnel](https://github.com/zizifn/edgetunnel) | **开山鼻祖**：奠定了 Cloudflare Workers 原生 TCP Sockets 实现 VLESS over WS 的技术基石 |
| [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel) | PATH 动态切换底层代理、ProxyIP 机制与优选网络生态 |
| [yonggekkk/Cloudflare-vless-trojan](https://github.com/yonggekkk/Cloudflare-vless-trojan) | 本地化部署（不依赖第三方订阅转换）、多协议扩展与 101 握手抗阻断 |
| [byJoey/cfnew](https://github.com/byJoey/cfnew) | 图形化 KV 管理面板（改完即生效）、延迟测速与家宽链式探索 |

## 功能

- **多协议**：VLESS / Trojan / Shadowsocks（简化版），走 WebSocket，TLS 由 Cloudflare 边缘终止
- **管理后台**：访问 `https://你的域名/admin`，图形化改配置，保存立即生效（需绑定 KV）
- **订阅自生成**：通用链接订阅、Clash、Sing-box 全部由 Worker 本地生成，不经过任何第三方转换服务
- **优选 IP**：默认内置 CF 官方 IP，可在后台增删改，也可开放 API 管理
- **延迟测试**：后台一键测优选 IP 的 TCP 建连延迟并排序
- **单连接覆盖**：在节点 path 或 query 里写 `proxyip=1.2.3.4` / `socks5=user:pass@host:port` / `http=host:port`，只影响当前节点（edgetunnel + 甬哥风格二合一）
- **出站代理**：全局 SOCKS5 / HTTP CONNECT 出站，三种回落策略（优先代理 / 优先直连 / 只走代理防泄漏）
- **ProxyIP**：目标为 Cloudflare 官方 IP 时自动改拨第三方非 CF 跳板机，规避 Worker 自连接阻断
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
| `PROXYIP` | 全局出站跳板机（用于访问 Cloudflare 网站，严禁填 CF 优选 IP，必须是非 CF 的第三方 IP/域名） | 空 |
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
- `https://域名/KEY/clash` — Clash 订阅（极简规则，轻量极速）
- `https://域名/KEY/clash?rules=full` — Clash 完整分流（内置 Loyalsoldier 规则集，细分 OpenAI/流媒体/电报/谷歌等分组）
- `https://域名/KEY/singbox` — Sing-box 订阅（极简规则）
- `https://域名/KEY/singbox?rules=full` — Sing-box 完整分流（内置 MetaCubeX 二进制 SRS 规则集）
- `https://域名/KEY/v2ray` — Base64 订阅
- `https://域名/KEY/vg` — 家宽链式代理订阅（实验性，基于 VPN Gate + dialer-proxy，需后台开启）
- `https://域名/admin` — 管理后台

> **关于双模规则与隐私安全**：
> 默认模式保持极简轻量，秒级响应。`?rules=full` 完整分流模式严格遵循**本地零泄漏**原则——所有 rule-provider 和 rule-set 链接直接由客户端本地向 jsDelivr/GitHub CDN 拉取，Worker 纯本地模板渲染，你的节点与连接凭据绝不经过任何第三方订阅转换后端。

## 智能地区分组（Ingress 落地机房与备注识别）

在 Clash / Sing-box / 通用订阅中，节点会自动归类并生成对应的地区自动优选组（如 `🇭🇰 香港节点`、`🇯🇵 日本节点`、`🇺🇸 美国节点`、`🇸🇬 新加坡节点` 等）：

1. **识别机制与双层判定**：
   - **第一层（最高优先级，手动标注）**：优选 IP 支持 `#` 备注语法，如 `104.16.0.0#香港 01` 或 `speed.marisalnc.com#美国`，节点名称会自动冠以国旗 Emoji 并归入该地区分组。
   - **第二层（本地实测 Ingress 机房码）**：在管理后台点击「开始测速与识别」，Worker 会直接读取响应头中的 `cf-ray` 落地机场码（如 `HKG`/`NRT`/`SJC`/`SIN` 等）和 `loc` 归属，并自动保存在 KV 中。订阅生成时直接以此作为地区依据，准确反映流量落地出口，不依赖任何第三方 IP 库。
2. **策略组智能联动（`?rules=full`）**：
   - `🤖 OpenAI` 自动优先匹配美、日、新等合规可用地区。
   - `🎬 奈飞视频` 优先匹配港、日、新等流媒体优势地区。
   - `📺 哔哩哔哩` 优先匹配直连与港台解除限制节点。

单连接覆盖示例（只影响该节点）：

```
path: /KEY?proxyip=1.2.3.4
path: /KEY/proxyip=1.2.3.4          (PATH 风格)
path: /KEY?socks5=user:pass@1.2.3.4:1080
path: /KEY?http=user:pass@1.2.3.4:8080
```

SS 节点：WS 路径用 `/KEY/ss`，密码为 UUID（简化版无 AEAD，仅个人使用；通用 Clash 订阅不含 SS）。

## 实验性功能：家宽链式代理（VPN Gate + dialer-proxy）

cf-fusion 实验性支持通过客户端前置代理链式连接全球家庭宽带节点，将流量伪装成普通家庭住宅 IP：

```
客户端 (Mihomo)
   │
   ▼ (VLESS + WS + TLS)
Cloudflare 边缘机房 (cf-fusion 优选前置节点)
   │
   ▼ (TCP 透传 OpenVPN)
全球家庭宽带志愿者节点 (VPN Gate Residential IP)
   │
   ▼
目标网站 (识别为家庭宽带住宅出口)
```

1. **工作原理与极致压缩**：
   - 客户端 mihomo 利用 `dialer-proxy: "⚡ CF前置"` 指向由 cf-fusion 生成的优选 VLESS 节点。
   - Worker 自动拉取筑波大学 VPN Gate 镜像列表，智能过滤出支持 TCP 协议的纯净家庭宽带住宅节点（排除大学官方机房）。
   - 提取 OpenVPN 配置并利用 YAML 锚点（`&vgca` 与 `*vgca`）对证书公钥进行去重复用，使庞大的链式订阅体积压缩达 90% 以上，秒级完成拉取与解析。
2. **开启方法**：
   - 本功能**默认严格关闭**，避免未授权访问及干扰默认订阅。
   - 开启方式：在管理后台「运行配置」中勾选 **「启用家宽链式代理 (VPN Gate)」** 并保存（或设置环境变量 `ENABLE_VG=1`）。
   - 开启后，在分享页及后台链接中即可获取专用订阅地址：`https://域名/KEY/vg`。
3. **重要限制与安全提示**：
   - **客户端限制**：必须且仅支持 **mihomo (Clash Meta) ≥ 1.19.25** 内核（如 Clash Verge Rev 最新版、Clash Nyanpasu、Mihomo Party 等）。Sing-box / v2rayNG / Shadowrocket 均不支持 OpenVPN 链式语法。
   - **隐私与信任**：家庭宽带节点属于全球志愿者个人宽带，虽然他们无法解密你的 HTTPS/TLS 密文流量，但能够看到连接的目标域名与元数据。**严禁用于银行、涉密业务等敏感场景**。
   - **稳定性预期**：志愿者节点受限于个人网络环境，掉线与失联属于正常现象。订阅内置了 `⚡ 家宽自动回退` 自动容灾组。

## 后台 API（需 `Authorization: Bearer <后台密码>`）

- `POST /admin/api/auth` — 校验密码
- `GET/POST/DELETE /admin/api/config` — 读 / 写 / 清空配置
- `GET/POST /admin/api/ips` — 读 / 写优选 IP（`{"reset":true}` 恢复默认）
- `GET /admin/api/links` — 订阅地址（含极简与完整分流链接）
- `POST /admin/api/latency` `{"hosts":["1.1.1.1:443"]}` — 延迟测试
- `GET /admin/api/logs` — 连接日志（需先在配置里打开）

## 客户端推荐

- Android：v2rayNG / NekoBox / Karing / ClashMeta
- Windows：v2rayN / Hiddify / Karing / Clash Verge Rev
- iOS：Shadowrocket / Stash / Surge / Karing
- macOS：Clash Verge Rev / Surge / Stash
- 软路由：passwall / ssr-plus / homeproxy

> **内核版本建议**：Sing-box 建议使用 **1.12+** 内核。cf-fusion 的 Sing-box 配置已严格兼容 1.14+ 移除旧版纯字符串 DNS 的规范。

## 说明与限制

- UDP 走 TCP 透传，只保证 DNS 这类场景；完整 UDP（如游戏语音）不支持
- `https://` 出站代理暂不支持，请用 `http://` 或 `socks5://`
- 未绑定 KV 时：UUID 自动生成但只存在内存（多实例可能不一致），**强烈建议直接设置 `UUID` 环境变量**
- 本项目仅供学习研究，请遵守当地法律法规

## 致谢

- [zizifn/edgetunnel](https://github.com/zizifn/edgetunnel) — **开山鼻祖**：奠定了在 Cloudflare Workers 上实现 VLESS 代理的基石
- [cmliu/edgetunnel](https://github.com/cmliu/edgetunnel) — 完善了 ProxyIP 机制与海量优选节点生态
- [yonggekkk/Cloudflare-vless-trojan](https://github.com/yonggekkk/Cloudflare-vless-trojan) — 提供了多协议扩展与本地零泄露订阅的稳健实践
- [byJoey/cfnew](https://github.com/byJoey/cfnew) — 带来了现代化的 KV 管理面板、测速机制与链式探索
