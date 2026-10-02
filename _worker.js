/**
 * cf-fusion — 集三家所长的一体化 Cloudflare 边缘代理脚本
 *
 * 融合：
 *  - byJoey/cfnew        : 多协议(VLESS/Trojan/xhttp→SS)、图形化 KV 配置、订阅自生成、自定义路径
 *  - cmliu/edgetunnel    : /admin 管理面板、PATH 动态切换底层代理、流量日志
 *  - yonggekkk            : 本地化部署(不依赖第三方订阅转换)、默认 CF 官方优选 IP、单节点 path 改 proxyip
 *
 * 部署方式(三选一):
 *  1) Workers: 新建 Worker, 把本文件内容粘贴进去, 保存部署
 *  2) wrangler: wrangler deploy (见 wrangler.toml)
 *  3) Pages  : 以「上传资产」方式上传本文件(命名为 _worker.js)直接部署
 *
 * 可选绑定: KV 命名空间, 变量名 KV (用于图形化配置/优选 IP/日志, 不绑也能跑, 用环境变量)
 *
 * 环境变量(全部可选, 面板里的配置会覆盖它们):
 *  UUID         VLESS UUID / Trojan 密码 (默认自动生成并存 KV)
 *  ADMIN_PASS   后台密码 (默认 admin, 务必修改)
 *  SUB_KEY      订阅路径密钥 (默认 UUID 去横线前 8 位)
 *  CUSTOM_PATH  自定义订阅路径, 设了之后 UUID 路径自动禁用
 *  PROXYIP      全局反代 IP/域名 (如 1.2.3.4 或 proxy.example.com:443)
 *  OUTBOUND     全局出站代理: socks5://user:pass@host:port 或 http://user:pass@host:port
 *  OUTBOUND_MODE 出站方式: proxy-first(默认) / direct-first / proxy-only
 *  FAKE_URL     首页伪装: 设了就 302 跳转过去, 不设显示默认页面
 *  P_VLESS/P_TROJAN/P_SS  协议开关: 1/0 (默认 1/1/0)
 */

import { connect } from 'cloudflare:sockets';

/* ============================== 常量 ============================== */

// 默认优选: CF 官方 IP 段(甬哥「不死 IP」理念: 默认就能用, 不用天天更新)
const DEFAULT_PREFERRED_IPS = [
  '104.16.0.0', '104.17.0.0', '104.18.0.0', '104.19.0.0', '104.20.0.0',
  '104.21.0.0', '104.22.0.0', '104.24.0.0', '104.25.0.0', '104.26.0.0',
  '104.27.0.0', '172.66.0.0', '172.67.0.0', '162.159.0.0',
];
const TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
const PLAIN_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
const WS_TIMEOUT_MS = 10000;
const DIAL_TIMEOUT_MS = 8000;

/* ============================== 工具函数 ============================== */

const te = new TextEncoder();
const td = new TextDecoder();

function b64encodeUnicode(s) {
  return btoa(String.fromCharCode(...te.encode(s)));
}
function b64decodeUnicode(s) {
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return td.decode(bytes);
}
function bytesToHex(b) {
  let s = '';
  for (const x of b) s += x.toString(16).padStart(2, '0');
  return s;
}
function concatBytes(...arrs) {
  let len = 0;
  for (const a of arrs) len += a.length;
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}
function uuidToBytes(uuid) {
  const hex = uuid.replace(/-/g, '');
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function isValidUUID(s) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s || '');
}
function parseHostPort(s, defaultPort) {
  s = (s || '').trim();
  if (!s) return null;
  let m = s.match(/^\[([^\]]+)\](?::(\d+))?$/); // [ipv6]:port
  if (m) return { host: m[1], port: m[2] ? +m[2] : defaultPort };
  m = s.match(/^(.*):(\d+)$/);
  if (m && !m[1].includes(':')) return { host: m[1], port: +m[2] };
  return { host: s, port: defaultPort };
}
// socks5://user:pass@host:port | http://user:pass@host:port | user:pass@host:port(默认 socks5)
function parseProxyUrl(s) {
  s = (s || '').trim();
  if (!s) return null;
  let scheme = 'socks5';
  const m = s.match(/^(socks5?|https?):\/\/(.+)$/i);
  let rest = s;
  if (m) {
    const raw = m[1].toLowerCase();
    scheme = raw === 'socks' ? 'socks5' : raw; // socks → socks5, 其余保持原样
    rest = m[2];
  }
  let auth = null;
  const at = rest.lastIndexOf('@');
  if (at > 0) {
    const up = rest.slice(0, at).split(':');
    auth = { user: decodeURIComponent(up[0] || ''), pass: decodeURIComponent(up[1] || '') };
    rest = rest.slice(at + 1);
  }
  const hp = parseHostPort(rest, scheme === 'http' ? 80 : 1080);
  if (!hp) return null;
  return { scheme, auth, host: hp.host, port: hp.port };
}

/* ---- 纯 JS SHA-224 (Trojan 密码哈希, Workers SubtleCrypto 不支持 SHA-224) ---- */
const K256 = [
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
];
const rotr = (x, n) => (x >>> n) | (x << (32 - n));
const SHA224_IV = [0xc1059ed8,0x367cd507,0x3070dd17,0xf70e5939,0xffc00b31,0x68581511,0x64f98fa7,0xbefa4fa4];
function sha224hex(str) {
  const msg = te.encode(str);
  const bitLen = msg.length * 8;
  const padLen = (((msg.length + 8) >> 6) + 1) << 6;
  const m = new Uint8Array(padLen);
  m.set(msg); m[msg.length] = 0x80;
  const dv = new DataView(m.buffer);
  dv.setUint32(padLen - 4, bitLen >>> 0);
  dv.setUint32(padLen - 8, Math.floor(bitLen / 4294967296));
  let a=SHA224_IV[0],b=SHA224_IV[1],c=SHA224_IV[2],d=SHA224_IV[3],
      e=SHA224_IV[4],f=SHA224_IV[5],g=SHA224_IV[6],h=SHA224_IV[7];
  const w = new Uint32Array(64);
  for (let i = 0; i < padLen; i += 64) {
    for (let t = 0; t < 16; t++) w[t] = dv.getUint32(i + t * 4);
    for (let t = 16; t < 64; t++) {
      const s0 = rotr(w[t-15],7)^rotr(w[t-15],18)^(w[t-15]>>>3);
      const s1 = rotr(w[t-2],17)^rotr(w[t-2],19)^(w[t-2]>>>10);
      w[t] = (w[t-16]+s0+w[t-7]+s1)|0;
    }
    let aa=a,bb=b,cc=c,dd=d,ee=e,ff=f,gg=g,hh=h;
    for (let t = 0; t < 64; t++) {
      const S1 = rotr(ee,6)^rotr(ee,11)^rotr(ee,25);
      const ch = (ee&ff)^(~ee&gg);
      const t1 = (hh+S1+ch+K256[t]+w[t])|0;
      const S0 = rotr(aa,2)^rotr(aa,13)^rotr(aa,22);
      const maj = (aa&bb)^(aa&cc)^(bb&cc);
      const t2 = (S0+maj)|0;
      hh=gg; gg=ff; ff=ee; ee=(dd+t1)|0; dd=cc; cc=bb; bb=aa; aa=(t1+t2)|0;
    }
    a=(a+aa)|0; b=(b+bb)|0; c=(c+cc)|0; d=(d+dd)|0;
    e=(e+ee)|0; f=(f+ff)|0; g=(g+gg)|0; h=(h+hh)|0;
  }
  return [a,b,c,d,e,f,g].map(x => (x>>>0).toString(16).padStart(8,'0')).join('');
}

/* ============================== 配置 ============================== */
// 优先级: 面板 KV 配置 > 环境变量 > 默认值 (cfnew 的做法: 改完面板立即生效)

let _cfgCache = null, _cfgCacheAt = 0;
let _memUUID = ''; // 无 KV 时的内存 fallback(多 isolate 下可能不一致, 强烈建议设 UUID 环境变量)

async function kvGet(env, key) {
  try { if (env.KV) { const v = await env.KV.get(key); return v; } } catch {}
  return null;
}
async function kvGetJSON(env, key) {
  const v = await kvGet(env, key);
  if (!v) return null;
  try { return JSON.parse(v); } catch { return null; }
}
async function kvPut(env, key, val, opts) {
  try { if (env.KV) await env.KV.put(key, val, opts); } catch {}
}

function envFlag(v, def) {
  if (v === undefined || v === null || v === '') return def;
  v = String(v).toLowerCase();
  return !(v === '0' || v === 'no' || v === 'false' || v === 'off');
}

async function getConfig(env) {
  const now = Date.now();
  if (_cfgCache && now - _cfgCacheAt < 30000) return _cfgCache;

  const kvc = (await kvGetJSON(env, 'cfu:config')) || {};
  let uuid = kvc.uuid || env.UUID || '';
  if (!isValidUUID(uuid)) {
    if (_memUUID && isValidUUID(_memUUID)) uuid = _memUUID;
    else {
      uuid = (typeof crypto.randomUUID === 'function') ? crypto.randomUUID() : '00000000-0000-4000-8000-000000000000';
      _memUUID = uuid;
      await kvPut(env, 'cfu:config', JSON.stringify({ ...kvc, uuid }));
    }
  }
  const cfg = {
    uuid,
    adminPass: kvc.adminPass || env.ADMIN_PASS || 'admin',
    subKey: kvc.subKey || env.SUB_KEY || uuid.replace(/-/g, '').slice(0, 8),
    customPath: (kvc.customPath || env.CUSTOM_PATH || '').replace(/^\/+|\/+$/g, ''),
    proxyip: kvc.proxyip ?? env.PROXYIP ?? '',
    outbound: kvc.outbound ?? env.OUTBOUND ?? '',
    outboundMode: kvc.outboundMode || env.OUTBOUND_MODE || 'proxy-first',
    fakeUrl: kvc.fakeUrl || env.FAKE_URL || '',
    doh: kvc.doh || env.DOH || 'https://dns.google/dns-query',
    pVless: kvc.pVless ?? envFlag(env.P_VLESS, true),
    pTrojan: kvc.pTrojan ?? envFlag(env.P_TROJAN, true),
    pSs: kvc.pSs ?? envFlag(env.P_SS, false),
    preferredIps: Array.isArray(kvc.preferredIps) && kvc.preferredIps.length ? kvc.preferredIps : DEFAULT_PREFERRED_IPS.slice(),
    maxNodes: Math.min(Math.max(+kvc.maxNodes || +env.MAX_NODES || 24, 1), 200),
    logConn: kvc.logConn ?? envFlag(env.LOG_CONN, false),
    _trojanHash: '', // 懒加载
  };
  _cfgCache = cfg; _cfgCacheAt = now;
  return cfg;
}
function trojanHash(cfg) {
  if (!cfg._trojanHash) cfg._trojanHash = sha224hex(cfg.uuid);
  return cfg._trojanHash;
}
function clearConfigCache() { _cfgCache = null; _cfgCacheAt = 0; }

// 管理员鉴权: Authorization: Bearer <密码> (面板 JS 存在 sessionStorage, 全程 HTTPS)
function isAuthed(request, cfg) {
  const h = request.headers.get('Authorization') || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return false;
  const a = m[1], b = cfg.adminPass;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/* ---- 单连接覆盖参数 (edgetunnel PATH 风格 + 甬哥 /pyip= 风格, 二合一) ----
   支持写在 query (?proxyip=1.2.3.4) 或 path 段 (/proxyip=1.2.3.4 /pyip=1.2.3.4) */
function parseOverrides(url, pathSegs) {
  const o = {};
  const q = url.searchParams;
  if (q.get('proxyip') || q.get('pyip')) o.proxyip = q.get('proxyip') || q.get('pyip');
  if (q.get('socks5') || q.get('socks')) o.outbound = 'socks5://' + (q.get('socks5') || q.get('socks'));
  if (q.get('http')) o.outbound = 'http://' + q.get('http');
  if (q.get('outbound')) o.outbound = q.get('outbound');
  for (const seg of pathSegs) {
    let m = seg.match(/^(?:proxyip|pyip)=(.+)$/i);
    if (m) o.proxyip = decodeURIComponent(m[1]);
    m = seg.match(/^socks5?=(.+)$/i);
    if (m) o.outbound = 'socks5://' + decodeURIComponent(m[1]);
    m = seg.match(/^https?=(.+)$/i);
    if (m) o.outbound = 'http://' + decodeURIComponent(m[1]);
  }
  return o;
}
function validSubPath(seg, cfg) {
  if (!seg) return false;
  if (cfg.customPath) return seg === cfg.customPath; // 设了自定义路径, UUID 路径自动禁用
  return seg === cfg.subKey || seg === cfg.uuid;
}

/* ============================== 路由 ============================== */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    let cfg;
    try { cfg = await getConfig(env); }
    catch (e) { return new Response('Config error: ' + e.message, { status: 500 }); }
    const segs = url.pathname.split('/').filter(Boolean).map(s => {
      try { return decodeURIComponent(s); } catch { return s; }
    });

    // 1) WebSocket 代理入口
    if ((request.headers.get('Upgrade') || '').toLowerCase() === 'websocket') {
      if (!segs.length || !validSubPath(segs[0], cfg)) {
        return new Response('Forbidden', { status: 403 });
      }
      return handleWS(request, env, cfg, segs.slice(1));
    }

    // 2) 管理后台
    if (segs[0] === 'admin' && segs[1] === 'api') {
      return handleAdminAPI(request, env, cfg, segs.slice(2), url);
    }
    if (segs[0] === 'admin') {
      return new Response(adminPanelHTML(), { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
    }

    // 3) 订阅 / 分享页
    if (segs.length && validSubPath(segs[0], cfg)) {
      const sub = (segs[1] || '').toLowerCase();
      if (sub === 'sub') return subPlain(cfg, url);
      if (sub === 'clash') return subClash(cfg, url);
      if (sub === 'singbox' || sub === 'sing-box') return subSingbox(cfg, url);
      if (sub === 'v2ray') return subV2ray(cfg, url);
      if (!sub) {
        return new Response(sharePageHTML(cfg, url), { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
      }
      return new Response('Not Found', { status: 404 });
    }

    // 4) 首页伪装
    if (url.pathname === '/' || url.pathname === '') {
      if (cfg.fakeUrl) return Response.redirect(cfg.fakeUrl, 302);
      return new Response(fakePageHTML(), { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
    }
    return new Response('Not Found', { status: 404 });
  }
};

/* ---- 首页伪装页 ---- */
function fakePageHTML() {
  return '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Welcome</title>'
    + '<style>body{font-family:sans-serif;color:#333;max-width:640px;margin:8% auto;padding:0 20px}'
    + 'h1{font-weight:400}</style></head><body>'
    + '<h1>Welcome to nginx!</h1>'
    + '<p>If you see this page, the web server is successfully installed and working.</p>'
    + '</body></html>';
}

/* ---- 分享页: 订阅地址 + 节点链接 + 客户端推荐 ---- */
function sharePageHTML(cfg, url) {
  const host = url.host;
  const key = cfg.customPath || cfg.subKey;
  const base = 'https://' + host + '/' + key;
  const nodes = buildNodes(cfg, host).slice(0, 12);
  let nodeRows = '';
  for (const n of nodes) {
    const link = cfg.pVless ? n.vless : cfg.pTrojan ? n.trojan : n.ss;
    nodeRows += '<div class="node"><code>' + escHtml(link) + '</code>'
      + '<button onclick="copyText(this)" data-t="' + escAttr(link) + '">复制</button></div>';
  }
  return '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
    + '<title>cf-fusion 订阅</title><style>'
    + 'body{font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;background:#f5f6f8;color:#222;margin:0;padding:24px}'
    + '.wrap{max-width:860px;margin:0 auto}.card{background:#fff;border-radius:12px;padding:20px;margin-bottom:16px;box-shadow:0 1px 4px rgba(0,0,0,.06)}'
    + 'h2{margin:0 0 12px;font-size:18px}.row{display:flex;gap:8px;margin-bottom:8px;align-items:center;flex-wrap:wrap}'
    + 'code{flex:1;background:#f0f2f5;padding:8px 10px;border-radius:8px;word-break:break-all;font-size:12px}'
    + 'button{background:#1677ff;color:#fff;border:0;border-radius:8px;padding:8px 14px;cursor:pointer;white-space:nowrap}'
    + 'button:active{opacity:.8}.node{display:flex;gap:8px;margin-bottom:8px;align-items:center}'
    + '.tip{color:#888;font-size:13px}.clients{line-height:2}</style></head><body><div class="wrap">'
    + '<div class="card"><h2>订阅地址</h2>'
    + subRow(base + '/sub', '通用订阅 (v2rayNG / NekoBox / Shadowrocket)') 
    + subRow(base + '/clash', 'Clash 订阅 (极简规则)')
    + subRow(base + '/clash?rules=full', 'Clash 完整分流 (含 Loyalsoldier 规则集)')
    + subRow(base + '/singbox', 'Sing-box 订阅 (极简规则, 建议 1.12+ 内核)')
    + subRow(base + '/singbox?rules=full', 'Sing-box 完整分流 (含 MetaCubeX 规则集)')
    + '<p class="tip">把订阅地址填入客户端的订阅管理即可, 每 15 分钟左右会自动更新优选。</p></div>'
    + '<div class="card"><h2>节点链接 (前 ' + nodes.length + ' 个)</h2>' + nodeRows + '</div>'
    + '<div class="card"><h2>客户端推荐</h2><div class="clients">'
    + 'Android: v2rayNG / NekoBox / Karing / ClashMeta<br>'
    + 'Windows: v2rayN / Hiddify / Karing / Clash Verge Rev<br>'
    + 'iOS: Shadowrocket(小火箭) / Stash / Surge / Karing / Hiddify<br>'
    + 'macOS: Clash Verge Rev / Surge / Stash<br>'
    + '软路由: passwall / ssr-plus / homeproxy</div>'
    + '<p class="tip">管理后台: https://' + host + '/admin</p></div>'
    + '</div><script>'
    + 'function copyText(btn){var t=btn.getAttribute("data-t");'
    + 'if(navigator.clipboard){navigator.clipboard.writeText(t).then(function(){btn.textContent="已复制";setTimeout(function(){btn.textContent="复制"},1200)});}'
    + 'else{var ta=document.createElement("textarea");ta.value=t;document.body.appendChild(ta);ta.select();document.execCommand("copy");document.body.removeChild(ta);btn.textContent="已复制";}}'
    + '</script></body></html>';
}
function subRow(u, label) {
  return '<div class="row"><code>' + escHtml(u) + '</code>'
    + '<button onclick="copyText(this)" data-t="' + escAttr(u) + '">复制</button>'
    + '<span class="tip">' + escHtml(label) + '</span></div>';
}
function escHtml(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}
function escAttr(s) {
  return String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
}

/* ============================== 管理后台面板 ============================== */
function adminPanelHTML() {
  return '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
  + '<title>cf-fusion 管理后台</title><style>'
  + '*{box-sizing:border-box}body{font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;background:#f0f2f5;color:#222;margin:0}'
  + '.top{background:#1677ff;color:#fff;padding:14px 20px;font-size:17px;font-weight:600}'
  + '.tabs{display:flex;background:#fff;border-bottom:1px solid #e5e5e5;position:sticky;top:0;z-index:5;overflow-x:auto}'
  + '.tab{padding:12px 18px;cursor:pointer;white-space:nowrap;color:#666}'
  + '.tab.on{color:#1677ff;border-bottom:2px solid #1677ff;font-weight:600}'
  + '.wrap{max-width:900px;margin:0 auto;padding:18px}'
  + '.card{background:#fff;border-radius:10px;padding:18px;margin-bottom:14px;box-shadow:0 1px 3px rgba(0,0,0,.06)}'
  + '.card h3{margin:0 0 14px;font-size:16px}'
  + '.f{margin-bottom:12px}.f label{display:block;font-size:13px;color:#666;margin-bottom:5px}'
  + '.f input[type=text],.f input[type=number],.f select,.f textarea{width:100%;padding:9px 10px;border:1px solid #d9d9d9;border-radius:8px;font-size:14px}'
  + '.f textarea{height:150px;font-family:monospace;font-size:12px;resize:vertical}'
  + '.row2{display:grid;grid-template-columns:1fr 1fr;gap:12px}'
  + '.chk{display:flex;align-items:center;gap:8px;margin-bottom:10px;font-size:14px}'
  + '.btn{background:#1677ff;color:#fff;border:0;border-radius:8px;padding:10px 22px;cursor:pointer;font-size:14px;margin-right:8px}'
  + '.btn.ghost{background:#fff;color:#1677ff;border:1px solid #1677ff}'
  + '.btn.danger{background:#fff;color:#e5484d;border:1px solid #e5484d}'
  + '.btn:active{opacity:.85}.hide{display:none}'
  + '.msg{padding:10px 14px;border-radius:8px;margin-bottom:12px;font-size:14px;display:none}'
  + '.msg.ok{display:block;background:#e6f7e6;color:#1a7f37}.msg.err{display:block;background:#fdecea;color:#c62828}'
  + 'table{width:100%;border-collapse:collapse;font-size:13px}th,td{padding:8px;border-bottom:1px solid #eee;text-align:left}'
  + 'th{background:#fafafa;color:#666}.mono{font-family:monospace;font-size:12px;word-break:break-all}'
  + '#login{position:fixed;inset:0;background:rgba(0,0,0,.45);display:flex;align-items:center;justify-content:center;z-index:99}'
  + '#login .box{background:#fff;border-radius:12px;padding:28px;width:320px}'
  + '#login input{width:100%;padding:10px;border:1px solid #d9d9d9;border-radius:8px;margin:12px 0;font-size:15px}'
  + '.linkrow{display:flex;gap:8px;align-items:center;margin-bottom:8px}'
  + '.linkrow code{flex:1;background:#f5f5f5;padding:8px;border-radius:6px;font-size:11px;word-break:break-all}'
  + '.cp{background:#eef4ff;color:#1677ff;border:0;border-radius:6px;padding:7px 12px;cursor:pointer;white-space:nowrap}'
  + '@media(max-width:640px){.row2{grid-template-columns:1fr}}'
  + '</style></head><body>'
  + '<div class="top">cf-fusion 管理后台</div>'
  + '<div class="tabs" id="tabs">'
  + '<div class="tab on" data-t="sub">订阅信息</div><div class="tab" data-t="config">节点配置</div>'
  + '<div class="tab" data-t="ips">优选 IP</div><div class="tab" data-t="speed">延迟测试</div>'
  + '<div class="tab" data-t="logs">连接日志</div></div>'
  + '<div class="wrap"><div class="msg" id="msg"></div>'
  // 订阅 tab
  + '<div class="card page" id="p-sub"><h3>订阅地址</h3><div id="links"></div>'
  + '<p style="color:#888;font-size:13px">修改配置后订阅立即生效, 无需重新部署。</p></div>'
  // 配置 tab
  + '<div class="card page hide" id="p-config"><h3>节点配置</h3>'
  + '<div class="row2"><div class="f"><label>UUID (VLESS ID / Trojan 密码)</label><input type="text" id="c-uuid"></div>'
  + '<div class="f"><label>后台密码</label><input type="text" id="c-adminPass"></div></div>'
  + '<div class="row2"><div class="f"><label>订阅路径密钥 SUB_KEY</label><input type="text" id="c-subKey"></div>'
  + '<div class="f"><label>自定义路径 (留空用上面两项, 设了则 UUID 路径禁用)</label><input type="text" id="c-customPath"></div></div>'
  + '<div class="f"><label>全局 ProxyIP (反代 IP/域名, 如 1.2.3.4 或 proxy.example.com:443)</label><input type="text" id="c-proxyip"></div>'
  + '<div class="row2"><div class="f"><label>全局出站代理 (socks5://user:pass@host:port 或 http://host:port)</label><input type="text" id="c-outbound"></div>'
  + '<div class="f"><label>出站方式</label><select id="c-outboundMode">'
  + '<option value="proxy-first">优先走代理, 失败回落直连</option>'
  + '<option value="direct-first">优先直连, 失败走代理</option>'
  + '<option value="proxy-only">只走代理, 失败即断开(防 IP 泄漏)</option></select></div></div>'
  + '<div class="row2"><div class="f"><label>首页伪装地址 (留空显示默认页面)</label><input type="text" id="c-fakeUrl"></div>'
  + '<div class="f"><label>DoH 服务器</label><input type="text" id="c-doh"></div></div>'
  + '<div class="f"><label>订阅最多生成节点数 (1-200)</label><input type="number" id="c-maxNodes" min="1" max="200"></div>'
  + '<div class="chk"><input type="checkbox" id="c-pVless"><label for="c-pVless">启用 VLESS</label></div>'
  + '<div class="chk"><input type="checkbox" id="c-pTrojan"><label for="c-pTrojan">启用 Trojan</label></div>'
  + '<div class="chk"><input type="checkbox" id="c-pSs"><label for="c-pSs">启用 Shadowsocks (简化版, 密码=UUID)</label></div>'
  + '<div class="chk"><input type="checkbox" id="c-logConn"><label for="c-logConn">记录连接日志 (存 KV, 最多 100 条)</label></div>'
  + '<button class="btn" onclick="saveConfig()">保存</button>'
  + '<button class="btn ghost" onclick="loadConfig()">重新加载</button>'
  + '<button class="btn danger" onclick="resetConfig()">清空面板配置(回退到环境变量)</button></div>'
  // 优选 IP tab
  + '<div class="card page hide" id="p-ips"><h3>优选 IP / 域名 (每行一个, 用于生成订阅节点)</h3>'
  + '<div class="f"><textarea id="ips" placeholder="1.1.1.1"></textarea></div>'
  + '<button class="btn" onclick="saveIps()">保存</button>'
  + '<button class="btn ghost" onclick="defaultIps()">恢复默认官方 IP</button></div>'
  // 测速 tab
  + '<div class="card page hide" id="p-speed"><h3>延迟测试 (服务端 TCP 建连耗时)</h3>'
  + '<div class="f"><label>测试目标 (每行一个, 格式 ip 或 ip:端口, 最多 20 个)</label>'
  + '<textarea id="speedHosts" style="height:110px"></textarea></div>'
  + '<button class="btn" onclick="runSpeed()">开始测试</button>'
  + '<div id="speedRes" style="margin-top:14px"></div></div>'
  // 日志 tab
  + '<div class="card page hide" id="p-logs"><h3>连接日志</h3>'
  + '<button class="btn ghost" onclick="loadLogs()">刷新</button>'
  + '<div id="logs" style="margin-top:12px"></div>'
  + '<p style="color:#888;font-size:13px">需先在「节点配置」里打开「记录连接日志」。</p></div>'
  + '</div>'
  // 登录框
  + '<div id="login"><div class="box"><h3 style="margin:0">请输入后台密码</h3>'
  + '<input type="password" id="pw" placeholder="后台密码" onkeydown="if(event.key===\'Enter\')doLogin()">'
  + '<button class="btn" style="width:100%" onclick="doLogin()">登录</button>'
  + '<p style="color:#888;font-size:12px">默认 admin, 请在「节点配置」中修改。</p></div></div>'
  + '<script>'
  + 'var pw=sessionStorage.getItem("cfu_pw")||"";'
  + 'function api(path,opt){opt=opt||{};opt.headers=opt.headers||{};opt.headers["Authorization"]="Bearer "+pw;'
  + 'return fetch("/admin/api/"+path,opt).then(function(r){if(r.status===401)throw new Error("密码错误");return r.json();});}'
  + 'function showMsg(t,ok){var m=document.getElementById("msg");m.textContent=t;m.className="msg "+(ok?"ok":"err");setTimeout(function(){m.className="msg"},4000);}'
  + 'function doLogin(){pw=document.getElementById("pw").value;'
  + 'api("auth",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({})}).then(function(){'
  + 'sessionStorage.setItem("cfu_pw",pw);document.getElementById("login").style.display="none";init();})'
  + '.catch(function(e){showMsg(e.message,false);});}'
  + 'document.querySelectorAll(".tab").forEach(function(el){el.onclick=function(){'
  + 'document.querySelectorAll(".tab").forEach(function(x){x.classList.remove("on")});el.classList.add("on");'
  + 'document.querySelectorAll(".page").forEach(function(x){x.classList.add("hide")});'
  + 'document.getElementById("p-"+el.getAttribute("data-t")).classList.remove("hide");};});'
  + 'function cp2(btn,t){var done=function(){btn.textContent="已复制";setTimeout(function(){btn.textContent="复制"},1200);};'
  + 'if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(done);}else{'
  + 'var ta=document.createElement("textarea");ta.value=t;document.body.appendChild(ta);ta.select();'
  + 'try{document.execCommand("copy")}catch(e){}document.body.removeChild(ta);done();}}'
  + 'function esc(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");}'
  + 'function loadLinks(){api("links").then(function(d){var h="";'
  + 'var items=[["通用订阅",d.sub],["Clash 极简订阅",d.clash],["Clash 完整分流",d.clashFull],["Sing-box 极简订阅",d.singbox],["Sing-box 完整分流",d.singboxFull],["分享页",d.share]];'
  + 'items.forEach(function(it){h+=\'<div class="linkrow"><code>\'+esc(it[1])+\'</code><button class="cp" onclick="cp2(this,\\\'\'+it[1]+\'\\\')">复制</button></div>\';});'
  + 'document.getElementById("links").innerHTML=h;}).catch(function(e){showMsg(e.message,false);});}'
  + 'function loadConfig(){api("config").then(function(c){'
  + '["uuid","adminPass","subKey","customPath","proxyip","outbound","outboundMode","fakeUrl","doh","maxNodes"].forEach(function(k){'
  + 'var el=document.getElementById("c-"+k);if(el)el.value=c[k]||"";});'
  + 'document.getElementById("c-pVless").checked=!!c.pVless;'
  + 'document.getElementById("c-pTrojan").checked=!!c.pTrojan;'
  + 'document.getElementById("c-pSs").checked=!!c.pSs;'
  + 'document.getElementById("c-logConn").checked=!!c.logConn;'
  + '}).catch(function(e){showMsg(e.message,false);});}'
  + 'function saveConfig(){var c={};'
  + '["uuid","adminPass","subKey","customPath","proxyip","outbound","outboundMode","fakeUrl","doh"].forEach(function(k){'
  + 'c[k]=document.getElementById("c-"+k).value.trim();});'
  + 'c.maxNodes=parseInt(document.getElementById("c-maxNodes").value)||24;'
  + 'c.pVless=document.getElementById("c-pVless").checked;'
  + 'c.pTrojan=document.getElementById("c-pTrojan").checked;'
  + 'c.pSs=document.getElementById("c-pSs").checked;'
  + 'c.logConn=document.getElementById("c-logConn").checked;'
  + 'api("ips").then(function(d){c.preferredIps=d.ips;'
  + 'return api("config",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(c)});})'
  + '.then(function(r){if(r.ok){showMsg("保存成功, 已立即生效",true);if(c.adminPass&&c.adminPass!==pw){pw=c.adminPass;sessionStorage.setItem("cfu_pw",pw);}}'
  + 'else showMsg("保存失败: "+(r.error||""),false);}).catch(function(e){showMsg(e.message,false);});}'
  + 'function resetConfig(){if(!confirm("清空面板配置并回退到环境变量?"))return;'
  + 'api("config",{method:"DELETE"}).then(function(){showMsg("已清空, 重新加载中",true);loadConfig();loadIps();});}'
  + 'function loadIps(){api("ips").then(function(d){document.getElementById("ips").value=(d.ips||[]).join("\\n");'
  + 'document.getElementById("speedHosts").value=(d.ips||[]).slice(0,20).map(function(ip){return ip+":443"}).join("\\n");});}'
  + 'function saveIps(){var ips=document.getElementById("ips").value.split("\\n").map(function(s){return s.trim()}).filter(Boolean);'
  + 'api("ips",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ips:ips})})'
  + '.then(function(){showMsg("优选 IP 已保存",true);}).catch(function(e){showMsg(e.message,false);});}'
  + 'function defaultIps(){api("ips",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({reset:true})})'
  + '.then(function(d){document.getElementById("ips").value=(d.ips||[]).join("\\n");showMsg("已恢复默认",true);});}'
  + 'function runSpeed(){var hosts=document.getElementById("speedHosts").value.split("\\n").map(function(s){return s.trim()}).filter(Boolean).slice(0,20);'
  + 'if(!hosts.length)return;document.getElementById("speedRes").innerHTML="测试中...";'
  + 'api("latency",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({hosts:hosts})})'
  + '.then(function(d){var rows=d.results.map(function(r){'
  + 'return "<tr><td class=\\"mono\\">"+esc(r.host)+"</td><td>"+(r.ms==null?("失败"):("<b>"+r.ms+" ms</b>"))+"</td></tr>";}).join("");'
  + 'document.getElementById("speedRes").innerHTML="<table><tr><th>目标</th><th>延迟</th></tr>"+rows+"</table>";})'
  + '.catch(function(e){showMsg(e.message,false);});}'
  + 'function loadLogs(){api("logs").then(function(d){var rows=(d.logs||[]).map(function(l){'
  + 'return "<tr><td class=\\"mono\\">"+esc(l.t)+"</td><td>"+esc(l.proto)+"</td><td class=\\"mono\\">"+esc(l.target)+"</td></tr>";}).join("");'
  + 'document.getElementById("logs").innerHTML="<table><tr><th>时间</th><th>协议</th><th>目标</th></tr>"+rows+"</table>";})'
  + '.catch(function(e){showMsg(e.message,false);});}'
  + 'function init(){loadLinks();loadConfig();loadIps();}'
  + 'if(pw){api("auth",{method:"POST"}).then(function(){document.getElementById("login").style.display="none";init();}).catch(function(){document.getElementById("login").style.display="flex";});}'
  + 'else{document.getElementById("login").style.display="flex";}'
  + '</script></body></html>';
}

/* ============================== 管理 API ============================== */

async function handleAdminAPI(request, env, cfg, segs, url) {
  const unauth = () => new Response(JSON.stringify({ error: 'unauthorized' }), { status: 401 });
  const json = (o, status = 200) => new Response(JSON.stringify(o), {
    status, headers: { 'Content-Type': 'application/json;charset=utf-8' },
  });

  // 登录校验(无状态: 密码即 Bearer token)
  if (segs[0] === 'auth' && request.method === 'POST') {
    return isAuthed(request, cfg) ? json({ ok: true }) : unauth();
  }
  if (!isAuthed(request, cfg)) return unauth();

  const action = segs[0];

  // 读/写配置
  if (action === 'config') {
    if (request.method === 'GET') {
      const { _trojanHash, ...pub } = cfg;
      return json(pub);
    }
    if (request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return json({ error: 'bad json' }, 400); }
      if (body.uuid && !isValidUUID(body.uuid)) return json({ error: 'uuid 格式不正确' }, 400);
      const kvc = (await kvGetJSON(env, 'cfu:config')) || {};
      const next = { ...kvc };
      for (const k of ['uuid','adminPass','subKey','customPath','proxyip','outbound','outboundMode','fakeUrl','doh','maxNodes','pVless','pTrojan','pSs','logConn','preferredIps']) {
        if (body[k] !== undefined) next[k] = body[k];
      }
      if (typeof next.customPath === 'string') next.customPath = next.customPath.replace(/^\/+|\/+$/g, '');
      if (!Array.isArray(next.preferredIps)) delete next.preferredIps;
      await kvPut(env, 'cfu:config', JSON.stringify(next));
      clearConfigCache();
      return json({ ok: true });
    }
    if (request.method === 'DELETE') { // 清空面板配置, 回退到环境变量
      try { if (env.KV) await env.KV.delete('cfu:config'); } catch {}
      clearConfigCache();
      return json({ ok: true });
    }
  }

  // 优选 IP 管理
  if (action === 'ips') {
    if (request.method === 'GET') return json({ ips: cfg.preferredIps });
    if (request.method === 'POST') {
      let body;
      try { body = await request.json(); } catch { return json({ error: 'bad json' }, 400); }
      const kvc = (await kvGetJSON(env, 'cfu:config')) || {};
      let ips;
      if (body.reset) ips = DEFAULT_PREFERRED_IPS.slice();
      else {
        ips = (body.ips || []).map(s => String(s).trim()).filter(Boolean).slice(0, 200);
        if (!ips.length) return json({ error: '列表不能为空' }, 400);
      }
      kvc.preferredIps = ips;
      await kvPut(env, 'cfu:config', JSON.stringify(kvc));
      clearConfigCache();
      return json({ ok: true, ips });
    }
  }

  // 订阅地址
  if (action === 'links' && request.method === 'GET') {
    const key = cfg.customPath || cfg.subKey;
    const base = 'https://' + url.host + '/' + key;
    return json({
      share: base,
      sub: base + '/sub',
      clash: base + '/clash',
      clashFull: base + '/clash?rules=full',
      singbox: base + '/singbox',
      singboxFull: base + '/singbox?rules=full',
      v2ray: base + '/v2ray'
    });
  }

  // 延迟测试: 服务端对目标 TCP 建连计时 (cfnew 内置测速的服务端版)
  if (action === 'latency' && request.method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return json({ error: 'bad json' }, 400); }
    const hosts = (body.hosts || []).map(s => String(s).trim()).filter(Boolean).slice(0, 20);
    const results = await Promise.all(hosts.map(async (h) => {
      const hp = parseHostPort(h, 443);
      if (!hp) return { host: h, ms: null };
      const t0 = Date.now();
      try {
        const sock = await withTimeout(connect({ hostname: hp.host, port: hp.port }), 4000, 'timeout');
        try { sock.close(); } catch {}
        return { host: h, ms: Date.now() - t0 };
      } catch { return { host: h, ms: null }; }
    }));
    results.sort((a, b) => (a.ms ?? 1e9) - (b.ms ?? 1e9));
    return json({ results });
  }

  // 连接日志
  if (action === 'logs' && request.method === 'GET') {
    const logs = (await kvGetJSON(env, 'cfu:logs')) || [];
    return json({ logs: logs.slice(-100).reverse() });
  }

  return json({ error: 'not found' }, 404);
}

function withTimeout(promise, ms, msg) {
  return Promise.race([
    promise,
    new Promise((_, rej) => setTimeout(() => rej(new Error(msg || 'timeout')), ms)),
  ]);
}

async function logConn(env, cfg, proto, target) {
  if (!cfg.logConn || !env.KV) return;
  try {
    const logs = (await kvGetJSON(env, 'cfu:logs')) || [];
    logs.push({ t: new Date().toISOString().replace('T', ' ').slice(0, 19), proto, target });
    await kvPut(env, 'cfu:logs', JSON.stringify(logs.slice(-100)));
  } catch {}
}

/* ============================== 订阅生成(本地化: 不依赖外部转换器) ============================== */

function buildNodes(cfg, host) {
  const key = cfg.customPath || cfg.subKey;
  const path = '/' + key;
  const ips = cfg.preferredIps && cfg.preferredIps.length ? cfg.preferredIps : DEFAULT_PREFERRED_IPS;
  const descs = [{ name: 'CF-直连', ip: host, port: 443, tls: true }];
  let n = 0;
  outer:
  for (const ip of ips) {
    for (const port of [443, 80]) {
      if (descs.length >= cfg.maxNodes) break outer;
      n++;
      const short = String(ip).replace(/[^0-9a-z]/gi, '').slice(-6) || ('x' + n);
      descs.push({ name: 'CF优选-' + short + '-' + n, ip: String(ip), port, tls: port === 443 });
    }
  }
  return descs.map(d => ({
    name: d.name, ip: d.ip, port: d.port, tls: d.tls,
    vless: vlessLink(cfg, host, path, d),
    trojan: trojanLink(cfg, host, path, d),
    ss: ssLink(cfg, d),
  }));
}
function vlessLink(cfg, host, path, d) {
  const p = new URLSearchParams({
    encryption: 'none', security: d.tls ? 'tls' : 'none',
    sni: host, fp: 'chrome', type: 'ws', host, path,
  });
  return 'vless://' + cfg.uuid + '@' + d.ip + ':' + d.port + '?' + p.toString() + '#' + encodeURIComponent(d.name);
}
function trojanLink(cfg, host, path, d) {
  const p = new URLSearchParams({
    security: d.tls ? 'tls' : 'none',
    sni: host, fp: 'chrome', type: 'ws', host, path,
  });
  return 'trojan://' + cfg.uuid + '@' + d.ip + ':' + d.port + '?' + p.toString() + '#' + encodeURIComponent(d.name);
}
function ssLink(cfg, d) {
  // 简化版 SS: 明文 none, 密码为 UUID (仅本脚本支持, 通用客户端不可用)
  return 'ss://' + btoa('none:' + cfg.uuid) + '@' + d.ip + ':' + d.port + '#' + encodeURIComponent(d.name + '-ss');
}

function subPlain(cfg, url) {
  const nodes = buildNodes(cfg, url.host);
  const lines = [];
  for (const n of nodes) {
    if (cfg.pVless) lines.push(n.vless);
    if (cfg.pTrojan) lines.push(n.trojan);
    if (cfg.pSs) lines.push(n.ss);
  }
  return new Response(lines.join('\n'), { headers: { 'Content-Type': 'text/plain;charset=utf-8' } });
}
function subV2ray(cfg, url) {
  const nodes = buildNodes(cfg, url.host);
  const lines = [];
  for (const n of nodes) {
    if (cfg.pVless) lines.push(n.vless);
    if (cfg.pTrojan) lines.push(n.trojan);
  }
  return new Response(b64encodeUnicode(lines.join('\n')), { headers: { 'Content-Type': 'text/plain;charset=utf-8' } });
}

function q(s) { return '"' + String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"'; }

function subClash(cfg, url) {
  const host = url.host;
  const key = cfg.customPath || cfg.subKey;
  const nodes = buildNodes(cfg, host);
  const isFull = url.searchParams.get('rules') === 'full' || url.searchParams.get('full') === '1';
  const proxies = [];
  for (const n of nodes) {
    const nm = n.name;
    if (cfg.pVless) {
      proxies.push('  - name: ' + q(nm + '-vless') + '\n    type: vless\n    server: ' + n.ip + '\n    port: ' + n.port
        + '\n    uuid: ' + cfg.uuid + '\n    tls: ' + (n.tls ? 'true' : 'false')
        + '\n    servername: ' + host + '\n    client-fingerprint: chrome\n    network: ws'
        + '\n    ws-opts:\n      path: /' + key + '\n      headers:\n        Host: ' + host);
    }
    if (cfg.pTrojan) {
      proxies.push('  - name: ' + q(nm + '-trojan') + '\n    type: trojan\n    server: ' + n.ip + '\n    port: ' + n.port
        + '\n    password: ' + cfg.uuid + '\n    sni: ' + host
        + '\n    client-fingerprint: chrome\n    network: ws'
        + '\n    ws-opts:\n      path: /' + key + '\n      headers:\n        Host: ' + host);
    }
  }
  const allNames = [];
  for (const n of nodes) {
    if (cfg.pVless) allNames.push(n.name + '-vless');
    if (cfg.pTrojan) allNames.push(n.name + '-trojan');
  }
  const nameList = allNames.length ? allNames.map(q).join(', ') : 'DIRECT';

  let yaml = '';
  if (isFull) {
    const loyalsoldierBase = 'https://fastly.jsdelivr.net/gh/Loyalsoldier/clash-rules@release';
    const provider = (name, type) =>
      `  ${name}:\n    type: http\n    behavior: ${type}\n    url: "${loyalsoldierBase}/${name}.txt"\n    path: ./rulesets/loyalsoldier/${name}.txt\n    interval: 86400`;

    const fullProviders = [
      'rule-providers:',
      provider('reject', 'domain'),
      provider('icloud', 'domain'),
      provider('apple', 'domain'),
      provider('google', 'domain'),
      provider('proxy', 'domain'),
      provider('direct', 'domain'),
      provider('private', 'domain'),
      provider('gfw', 'domain'),
      provider('greatfire', 'domain'),
      provider('tld-not-cn', 'domain'),
      provider('telegramcidr', 'ipcidr'),
      provider('cncidr', 'ipcidr'),
      provider('lancidr', 'ipcidr'),
      provider('applications', 'classical')
    ].join('\n');

    const fullGroups = [
      'proxy-groups:',
      '  - name: ' + q('🚀 节点选择') + '\n    type: select\n    proxies: [' + q('♻️ 自动选择') + ', ' + nameList + ', ' + q('🎯 全球直连') + ']',
      '  - name: ' + q('♻️ 自动选择') + '\n    type: url-test\n    url: http://www.gstatic.com/generate_204\n    interval: 300\n    proxies: [' + nameList + ']',
      '  - name: ' + q('🌍 国外媒体') + '\n    type: select\n    proxies: [' + q('🚀 节点选择') + ', ' + q('♻️ 自动选择') + ', ' + nameList + ', ' + q('🎯 全球直连') + ']',
      '  - name: ' + q('📺 哔哩哔哩') + '\n    type: select\n    proxies: [' + q('🎯 全球直连') + ', ' + q('🚀 节点选择') + ', ' + q('♻️ 自动选择') + ', ' + nameList + ']',
      '  - name: ' + q('📹 油管视频') + '\n    type: select\n    proxies: [' + q('🚀 节点选择') + ', ' + q('🌍 国外媒体') + ', ' + q('♻️ 自动选择') + ', ' + nameList + ', ' + q('🎯 全球直连') + ']',
      '  - name: ' + q('🎬 奈飞视频') + '\n    type: select\n    proxies: [' + q('🚀 节点选择') + ', ' + q('🌍 国外媒体') + ', ' + q('♻️ 自动选择') + ', ' + nameList + ', ' + q('🎯 全球直连') + ']',
      '  - name: ' + q('📲 电报信息') + '\n    type: select\n    proxies: [' + q('🚀 节点选择') + ', ' + q('♻️ 自动选择') + ', ' + nameList + ', ' + q('🎯 全球直连') + ']',
      '  - name: ' + q('🌐 谷歌服务') + '\n    type: select\n    proxies: [' + q('🚀 节点选择') + ', ' + q('♻️ 自动选择') + ', ' + nameList + ', ' + q('🎯 全球直连') + ']',
      '  - name: ' + q('🤖 OpenAI') + '\n    type: select\n    proxies: [' + q('🚀 节点选择') + ', ' + q('♻️ 自动选择') + ', ' + nameList + ', ' + q('🎯 全球直连') + ']',
      '  - name: ' + q('Ⓜ️ 微软服务') + '\n    type: select\n    proxies: [' + q('🎯 全球直连') + ', ' + q('🚀 节点选择') + ', ' + q('♻️ 自动选择') + ', ' + nameList + ']',
      '  - name: ' + q('🍎 苹果服务') + '\n    type: select\n    proxies: [' + q('🎯 全球直连') + ', ' + q('🚀 节点选择') + ', ' + q('♻️ 自动选择') + ', ' + nameList + ']',
      '  - name: ' + q('🎯 全球直连') + '\n    type: select\n    proxies: [DIRECT]',
      '  - name: ' + q('🛑 全球拦截') + '\n    type: select\n    proxies: [REJECT, DIRECT]',
      '  - name: ' + q('🐟 漏网之鱼') + '\n    type: select\n    proxies: [' + q('🚀 节点选择') + ', ' + q('♻️ 自动选择') + ', ' + nameList + ', ' + q('🎯 全球直连') + ']'
    ].join('\n');

    const fullRules = [
      'rules:',
      '  - DOMAIN-SUFFIX,local,' + q('🎯 全球直连'),
      '  - DOMAIN-SUFFIX,googleapis.cn,' + q('🌐 谷歌服务'),
      '  - DOMAIN-SUFFIX,gstatic.com,' + q('🌐 谷歌服务'),
      '  - DOMAIN-SUFFIX,googlevideo.com,' + q('📹 油管视频'),
      '  - DOMAIN-SUFFIX,googleusercontent.com,' + q('🌐 谷歌服务'),
      '  - DOMAIN-KEYWORD,youtube,' + q('📹 油管视频'),
      '  - DOMAIN-SUFFIX,youtube.com,' + q('📹 油管视频'),
      '  - DOMAIN-SUFFIX,youtu.be,' + q('📹 油管视频'),
      '  - DOMAIN-KEYWORD,netflix,' + q('🎬 奈飞视频'),
      '  - DOMAIN-SUFFIX,nflxext.com,' + q('🎬 奈飞视频'),
      '  - DOMAIN-SUFFIX,nflxso.net,' + q('🎬 奈飞视频'),
      '  - DOMAIN-SUFFIX,nflxvideo.net,' + q('🎬 奈飞视频'),
      '  - DOMAIN-SUFFIX,nflximg.com,' + q('🎬 奈飞视频'),
      '  - DOMAIN-SUFFIX,nflximg.net,' + q('🎬 奈飞视频'),
      '  - DOMAIN-SUFFIX,netflix.com,' + q('🎬 奈飞视频'),
      '  - DOMAIN-SUFFIX,netflix.net,' + q('🎬 奈飞视频'),
      '  - DOMAIN-SUFFIX,bilibili.com,' + q('📺 哔哩哔哩'),
      '  - DOMAIN-SUFFIX,bilivideo.com,' + q('📺 哔哩哔哩'),
      '  - DOMAIN-SUFFIX,hdslb.com,' + q('📺 哔哩哔哩'),
      '  - DOMAIN-KEYWORD,openai,' + q('🤖 OpenAI'),
      '  - DOMAIN-KEYWORD,chatgpt,' + q('🤖 OpenAI'),
      '  - DOMAIN-SUFFIX,openai.com,' + q('🤖 OpenAI'),
      '  - DOMAIN-SUFFIX,chatgpt.com,' + q('🤖 OpenAI'),
      '  - DOMAIN-SUFFIX,oaistatic.com,' + q('🤖 OpenAI'),
      '  - DOMAIN-SUFFIX,oaiusercontent.com,' + q('🤖 OpenAI'),
      '  - DOMAIN-SUFFIX,anthropic.com,' + q('🤖 OpenAI'),
      '  - DOMAIN-SUFFIX,claude.ai,' + q('🤖 OpenAI'),
      '  - DOMAIN-SUFFIX,perplexity.ai,' + q('🤖 OpenAI'),
      '  - DOMAIN-SUFFIX,gemini.google.com,' + q('🤖 OpenAI'),
      '  - RULE-SET,applications,' + q('🎯 全球直连'),
      '  - RULE-SET,private,' + q('🎯 全球直连'),
      '  - RULE-SET,reject,' + q('🛑 全球拦截'),
      '  - RULE-SET,icloud,' + q('🍎 苹果服务'),
      '  - RULE-SET,apple,' + q('🍎 苹果服务'),
      '  - RULE-SET,google,' + q('🌐 谷歌服务'),
      '  - RULE-SET,proxy,' + q('🚀 节点选择'),
      '  - RULE-SET,gfw,' + q('🚀 节点选择'),
      '  - RULE-SET,greatfire,' + q('🚀 节点选择'),
      '  - RULE-SET,tld-not-cn,' + q('🚀 节点选择'),
      '  - RULE-SET,direct,' + q('🎯 全球直连'),
      '  - RULE-SET,lancidr,' + q('🎯 全球直连') + ',no-resolve',
      '  - RULE-SET,cncidr,' + q('🎯 全球直连') + ',no-resolve',
      '  - RULE-SET,telegramcidr,' + q('📲 电报信息') + ',no-resolve',
      '  - GEOIP,LAN,' + q('🎯 全球直连') + ',no-resolve',
      '  - GEOIP,CN,' + q('🎯 全球直连') + ',no-resolve',
      '  - MATCH,' + q('🐟 漏网之鱼')
    ].join('\n');

    yaml =
      '# cf-fusion 完整分流规则 (Loyalsoldier 规则集, 客户端直连获取)\n'
      + 'mixed-port: 7890\nallow-lan: true\nmode: rule\nlog-level: info\n'
      + 'dns:\n  enable: true\n  ipv6: false\n  nameserver:\n    - 223.5.5.5\n    - 8.8.8.8\n'
      + 'proxies:\n' + proxies.join('\n') + '\n'
      + fullGroups + '\n'
      + fullProviders + '\n'
      + fullRules + '\n';
  } else {
    yaml =
      '# cf-fusion 极简订阅 (本地生成, 无第三方转换)\n'
      + 'mixed-port: 7890\nallow-lan: true\nmode: rule\nlog-level: info\n'
      + 'dns:\n  enable: true\n  ipv6: false\n  nameserver:\n    - 223.5.5.5\n    - 8.8.8.8\n'
      + 'proxies:\n' + proxies.join('\n') + '\n'
      + 'proxy-groups:\n'
      + '  - name: ' + q('🚀 节点选择') + '\n    type: select\n    proxies: [' + q('♻️ 自动选择') + ', ' + nameList + ', ' + q('🎯 全球直连') + ']\n'
      + '  - name: ' + q('♻️ 自动选择') + '\n    type: url-test\n    url: http://www.gstatic.com/generate_204\n    interval: 300\n    proxies: [' + nameList + ']\n'
      + '  - name: ' + q('🎯 全球直连') + '\n    type: select\n    proxies: [DIRECT, ' + q('🚀 节点选择') + ']\n'
      + '  - name: ' + q('🛑 全球拦截') + '\n    type: select\n    proxies: [REJECT, DIRECT]\n'
      + 'rules:\n'
      + '  - DOMAIN-SUFFIX,local,' + q('🎯 全球直连') + '\n'
      + '  - IP-CIDR,192.168.0.0/16,' + q('🎯 全球直连') + ',no-resolve\n'
      + '  - IP-CIDR,10.0.0.0/8,' + q('🎯 全球直连') + ',no-resolve\n'
      + '  - IP-CIDR,172.16.0.0/12,' + q('🎯 全球直连') + ',no-resolve\n'
      + '  - IP-CIDR,127.0.0.0/8,' + q('🎯 全球直连') + ',no-resolve\n'
      + '  - GEOIP,CN,' + q('🎯 全球直连') + '\n'
      + '  - MATCH,' + q('🚀 节点选择') + '\n';
  }
  return new Response(yaml, { headers: { 'Content-Type': 'text/yaml;charset=utf-8' } });
}

function subSingbox(cfg, url) {
  const host = url.host;
  const key = cfg.customPath || cfg.subKey;
  const nodes = buildNodes(cfg, host);
  const isFull = url.searchParams.get('rules') === 'full' || url.searchParams.get('full') === '1';
  const outbounds = [];
  const tags = [];
  for (const n of nodes) {
    if (cfg.pVless) {
      const tag = n.name + '-vless';
      tags.push(tag);
      outbounds.push({
        type: 'vless', tag, server: n.ip, server_port: n.port, uuid: cfg.uuid,
        tls: { enabled: n.tls, server_name: host, utls: { enabled: true, fingerprint: 'chrome' } },
        transport: { type: 'ws', path: '/' + key, headers: { Host: host } },
      });
    }
    if (cfg.pTrojan) {
      const tag = n.name + '-trojan';
      tags.push(tag);
      outbounds.push({
        type: 'trojan', tag, server: n.ip, server_port: n.port, password: cfg.uuid,
        tls: { enabled: n.tls, server_name: host, utls: { enabled: true, fingerprint: 'chrome' } },
        transport: { type: 'ws', path: '/' + key, headers: { Host: host } },
      });
    }
  }

  let conf;
  if (isFull) {
    const srsSite = 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite';
    const srsIp = 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip';
    const sRule = name => ({ tag: `geosite-${name}`, type: 'remote', format: 'binary', url: `${srsSite}/${name}.srs`, download_detour: 'direct' });
    const iRule = name => ({ tag: `geoip-${name}`, type: 'remote', format: 'binary', url: `${srsIp}/${name}.srs`, download_detour: 'direct' });

    const ruleSets = [
      sRule('cn'), sRule('private'), sRule('apple'), sRule('apple-cn'), sRule('microsoft'), sRule('microsoft@cn'),
      sRule('google'), sRule('telegram'), sRule('openai'), sRule('anthropic'), sRule('youtube'), sRule('netflix'),
      sRule('disney'), sRule('spotify'), sRule('tiktok'), sRule('twitter'), sRule('facebook'), sRule('github'),
      sRule('geolocation-!cn'), sRule('category-ads-all'), iRule('cn'), iRule('private'), iRule('telegram')
    ];

    const fullOutbounds = [
      { type: 'selector', tag: '🚀 节点选择', outbounds: ['♻️ 自动选择', ...tags, 'direct'], default: '♻️ 自动选择' },
      { type: 'urltest', tag: '♻️ 自动选择', outbounds: tags, url: 'http://www.gstatic.com/generate_204', interval: '5m' },
      { type: 'selector', tag: '🌍 国外媒体', outbounds: ['🚀 节点选择', '♻️ 自动选择', 'direct', ...tags] },
      { type: 'selector', tag: '📲 电报信息', outbounds: ['🚀 节点选择', '♻️ 自动选择', 'direct', ...tags] },
      { type: 'selector', tag: '🌐 谷歌服务', outbounds: ['🚀 节点选择', '♻️ 自动选择', 'direct', ...tags] },
      { type: 'selector', tag: '🤖 OpenAI', outbounds: ['🚀 节点选择', '♻️ 自动选择', 'direct', ...tags] },
      { type: 'selector', tag: 'Ⓜ️ 微软服务', outbounds: ['direct', '🚀 节点选择', '♻️ 自动选择', ...tags] },
      { type: 'selector', tag: '🍎 苹果服务', outbounds: ['direct', '🚀 节点选择', '♻️ 自动选择', ...tags] },
      { type: 'selector', tag: '📺 哔哩哔哩', outbounds: ['direct', '🚀 节点选择', '♻️ 自动选择', ...tags] },
      { type: 'selector', tag: '📹 油管视频', outbounds: ['🚀 节点选择', '🌍 国外媒体', '♻️ 自动选择', 'direct', ...tags] },
      { type: 'selector', tag: '🎬 奈飞视频', outbounds: ['🚀 节点选择', '🌍 国外媒体', '♻️ 自动选择', 'direct', ...tags] },
      { type: 'selector', tag: '🎯 全球直连', outbounds: ['direct'] },
      { type: 'selector', tag: '🐟 漏网之鱼', outbounds: ['🚀 节点选择', '♻️ 自动选择', 'direct', ...tags] },
      ...outbounds,
      { type: 'direct', tag: 'direct' },
      { type: 'block', tag: 'block' },
    ];

    const fullRouteRules = [
      { action: 'sniff' },
      { protocol: 'dns', action: 'hijack-dns' },
      { ip_is_private: true, outbound: 'direct' },
      { rule_set: 'geosite-category-ads-all', action: 'reject' },
      { rule_set: 'geosite-private', outbound: 'direct' },
      { rule_set: 'geosite-apple-cn', outbound: 'direct' },
      { rule_set: 'geosite-microsoft@cn', outbound: 'direct' },
      { rule_set: 'geosite-apple', outbound: '🍎 苹果服务' },
      { rule_set: 'geosite-microsoft', outbound: 'Ⓜ️ 微软服务' },
      { rule_set: 'geosite-openai', outbound: '🤖 OpenAI' },
      { rule_set: 'geosite-anthropic', outbound: '🤖 OpenAI' },
      { rule_set: 'geosite-telegram', outbound: '📲 电报信息' },
      { rule_set: 'geoip-telegram', outbound: '📲 电报信息' },
      { rule_set: 'geosite-google', outbound: '🌐 谷歌服务' },
      { rule_set: 'geosite-youtube', outbound: '🌍 国外媒体' },
      { rule_set: 'geosite-netflix', outbound: '🌍 国外媒体' },
      { rule_set: 'geosite-disney', outbound: '🌍 国外媒体' },
      { rule_set: 'geosite-spotify', outbound: '🌍 国外媒体' },
      { rule_set: 'geosite-tiktok', outbound: '🌍 国外媒体' },
      { rule_set: 'geosite-twitter', outbound: '🌍 国外媒体' },
      { rule_set: 'geosite-facebook', outbound: '🌍 国外媒体' },
      { rule_set: 'geosite-github', outbound: '🚀 节点选择' },
      { rule_set: 'geosite-geolocation-!cn', outbound: '🚀 节点选择' },
      { rule_set: 'geosite-cn', outbound: 'direct' },
      { rule_set: 'geoip-cn', outbound: 'direct' },
    ];

    conf = {
      log: { level: 'info' },
      dns: { servers: [{ tag: 'local', address: '223.5.5.5', detour: 'direct' }] },
      outbounds: fullOutbounds,
      route: {
        rule_set: ruleSets,
        rules: fullRouteRules,
        final: '🐟 漏网之鱼',
        auto_detect_interface: true,
      },
    };
  } else {
    outbounds.push(
      { type: 'selector', tag: '🚀 节点选择', outbounds: ['♻️ 自动选择', ...tags, 'direct'] },
      { type: 'urltest', tag: '♻️ 自动选择', outbounds: tags, url: 'http://www.gstatic.com/generate_204', interval: '5m' },
      { type: 'direct', tag: 'direct' },
      { type: 'block', tag: 'block' },
    );
    conf = {
      log: { level: 'info' },
      dns: { servers: [{ tag: 'local', address: '223.5.5.5', detour: 'direct' }] },
      outbounds,
      route: {
        rules: [
          { geosite: 'cn', geoip: ['cn', 'private'], outbound: 'direct' },
        ],
        final: '🚀 节点选择',
        auto_detect_interface: true,
      },
    };
  }
  return new Response(JSON.stringify(conf, null, 2), { headers: { 'Content-Type': 'application/json;charset=utf-8' } });
}

/* ============================== WebSocket 代理核心 ============================== */

async function handleWS(request, env, cfg, extraSegs) {
  const pair = new WebSocketPair();
  const client = pair[0], server = pair[1];
  server.accept();
  const url = new URL(request.url);
  const overrides = parseOverrides(url, extraSegs);
  // 不 await: 握手响应(101)先返回, 连接处理在后台跑
  handleConnection(server, env, cfg, overrides, extraSegs).catch(() => {
    try { server.close(1011, 'internal error'); } catch {}
  });
  return new Response(null, { status: 101, webSocket: client });
}

async function handleConnection(ws, env, cfg, overrides, extraSegs) {
  const reader = makeWSReader(ws);
  const isSS = cfg.pSs && extraSegs.some(s => s.toLowerCase() === 'ss');

  // 读够字节做协议嗅探 (VLESS 首字节 0x00+UUID / Trojan 首 56 字节为密码哈希)
  let buf = await reader.readAtLeast(24, WS_TIMEOUT_MS);
  if (!buf) { ws.close(1008, 'timeout'); return; }
  let sess = null;
  for (let i = 0; i < 10 && !sess; i++) {
    const r = tryParseSession(buf, cfg, isSS);
    if (r === 'need-more') {
      sess = null;
      buf = await reader.readAtLeast(buf.length + 64, 4000);
      if (!buf) break;
    } else sess = r;
  }
  if (!sess) { ws.close(1008, 'bad request'); return; }
  reader.consume(sess.headerLen);

  let dial;
  try {
    dial = await dialOut(cfg, overrides, sess.host, sess.port);
  } catch {
    ws.close(1011, 'dial failed');
    return;
  }
  const sock = dial.sock;
  logConn(env, cfg, sess.proto, sess.host + ':' + sess.port);
  const closeSock = () => { try { sock.close(); } catch {} };
  ws.addEventListener('close', closeSock);
  ws.addEventListener('error', closeSock);

  if (sess.udp) {
    if (sess.responsePrefix.length) ws.send(sess.responsePrefix);
    await handleUDP(ws, reader, sock, sess);
    return;
  }
  const writer = sock.writable.getWriter();
  ws.addEventListener('close', () => { try { writer.releaseLock(); } catch {} });
  // 切换为直通模式: 已缓冲的(去掉协议头后)数据先发, 后续消息实时转发
  reader.setForward(async (d) => { await writer.write(d); });
  await pumpSocketToWS(sock, ws, [sess.responsePrefix, dial.leftover]);
}

/* ---- UDP: 按 2 字节长度切包, 经 TCP 转发(DNS over TCP 兼容, 这是此类脚本的通用做法) ---- */
async function handleUDP(ws, reader, sock, sess) {
  const writer = sock.writable.getWriter();
  const sreader = new SocketReader(sock.readable);
  let udpBuf = new Uint8Array(0);
  reader.setForward(async (d) => {
    udpBuf = concatBytes(udpBuf, d);
    while (udpBuf.length >= 2) {
      const len = (udpBuf[0] << 8) | udpBuf[1];
      if (udpBuf.length < 2 + len) break;
      const pkt = udpBuf.slice(0, 2 + len);
      udpBuf = udpBuf.slice(2 + len);
      await writer.write(pkt); // TCP 承载的 DNS 同样是 2 字节长度前缀, 直接透传
    }
  });
  try {
    for (;;) {
      const lh = await sreader.readExactly(2, 15000);
      const len = (lh[0] << 8) | lh[1];
      if (len > 65535) break;
      const data = await sreader.readExactly(len, 15000);
      if (ws.readyState !== 1) break;
      ws.send(concatBytes(lh, data)); // VLESS/Trojan UDP 回包: 2 字节长度 + 数据
    }
  } catch {} finally {
    try { writer.releaseLock(); } catch {}
    sreader.release();
    try { ws.close(); } catch {}
    try { sock.close(); } catch {}
  }
}

async function pumpSocketToWS(sock, ws, prefixes) {
  try {
    for (const p of prefixes) {
      if (p && p.length && ws.readyState === 1) ws.send(p);
    }
    const r = sock.readable.getReader();
    try {
      for (;;) {
        const { done, value } = await r.read();
        if (done) break;
        if (ws.readyState !== 1) break;
        ws.send(value);
      }
    } finally { r.releaseLock(); }
  } catch {} finally {
    try { ws.close(); } catch {}
    try { sock.close(); } catch {}
  }
}

/* ---- WS 带缓冲读取器: 握手阶段缓存, 握手完成后切换直通 ---- */
function makeWSReader(ws) {
  const queue = [];
  let forward = null;
  let closed = false;
  let waiter = null;
  let buf = new Uint8Array(0);
  ws.addEventListener('message', (e) => {
    let d;
    if (e.data instanceof ArrayBuffer) d = new Uint8Array(e.data);
    else if (typeof e.data === 'string') d = te.encode(e.data);
    else { try { d = new Uint8Array(e.data); } catch { return; } }
    if (forward) forward(d);
    else { queue.push(d); if (waiter) { const w = waiter; waiter = null; w(); } }
  });
  const onClose = () => { closed = true; if (waiter) { const w = waiter; waiter = null; w(); } };
  ws.addEventListener('close', onClose);
  ws.addEventListener('error', onClose);
  async function readAtLeast(n, timeoutMs) {
    const t0 = Date.now();
    for (;;) {
      while (queue.length && buf.length < n) {
        const c = queue.shift();
        const nb = new Uint8Array(buf.length + c.length);
        nb.set(buf); nb.set(c, buf.length);
        buf = nb;
      }
      if (buf.length >= n) return buf;
      if (closed) return buf.length ? buf : null;
      const remain = timeoutMs - (Date.now() - t0);
      if (remain <= 0) return buf.length ? buf : null;
      await new Promise((res) => {
        waiter = res;
        setTimeout(() => { if (waiter === res) { waiter = null; res(); } }, remain);
      });
    }
  }
  function consume(n) { buf = buf.slice(n); }
  function setForward(fn) {
    forward = (d) => { Promise.resolve(fn(d)).catch(() => { try { ws.close(); } catch {} }); };
    if (buf.length) { const b = buf; buf = new Uint8Array(0); forward(b); }
    while (queue.length) forward(queue.shift());
  }
  return { readAtLeast, consume, setForward };
}

/* ============================== 协议解析 ============================== */

function tryParseSession(buf, cfg, isSS) {
  if (isSS) {
    const s = parseSsHeader(buf);
    if (s) return { ...s, proto: 'ss', udp: false, responsePrefix: new Uint8Array(0) };
    return 'need-more';
  }
  if (cfg.pVless) {
    const v = parseVlessHeader(buf, cfg);
    if (v === 'need-more') return 'need-more';
    if (v) return { ...v, proto: 'vless', responsePrefix: new Uint8Array([0, 0]) };
  }
  if (cfg.pTrojan) {
    const t = parseTrojanHeader(buf, cfg);
    if (t === 'need-more') return 'need-more';
    if (t) return { ...t, proto: 'trojan', responsePrefix: new Uint8Array(0) };
  }
  return null;
}

function parseVlessHeader(buf, cfg) {
  if (buf.length < 24) return 'need-more';
  if (buf[0] !== 0x00) return null;
  const ub = uuidToBytes(cfg.uuid);
  for (let i = 0; i < 16; i++) if (buf[1 + i] !== ub[i]) return null;
  const m = buf[17];
  if (buf.length < 24 + m) return 'need-more';
  const cmd = buf[18 + m];
  if (cmd !== 1 && cmd !== 2) return null; // 3 = MUX 不支持
  const port = (buf[19 + m] << 8) | buf[20 + m];
  const atyp = buf[21 + m];
  let host, headerLen;
  if (atyp === 1) {
    if (buf.length < 26 + m) return 'need-more';
    host = buf[22+m] + '.' + buf[23+m] + '.' + buf[24+m] + '.' + buf[25+m];
    headerLen = 26 + m;
  } else if (atyp === 2) {
    const len = buf[22 + m];
    if (buf.length < 24 + m + len) return 'need-more';
    try { host = td.decode(buf.slice(23 + m, 23 + m + len)); } catch { return null; }
    headerLen = 24 + m + len;
  } else if (atyp === 3) {
    if (buf.length < 38 + m) return 'need-more';
    const parts = [];
    for (let i = 0; i < 8; i++) parts.push(((buf[22+m+i*2] << 8) | buf[23+m+i*2]).toString(16));
    host = parts.join(':');
    headerLen = 38 + m;
  } else return null;
  return { host, port, udp: cmd === 2, headerLen };
}

function parseTrojanHeader(buf, cfg) {
  if (buf.length < 60) return 'need-more';
  let hex = '';
  for (let i = 0; i < 56; i++) hex += String.fromCharCode(buf[i]);
  if (hex !== trojanHash(cfg)) return null;
  if (buf[56] !== 0x0d || buf[57] !== 0x0a) return null;
  const cmd = buf[58];
  if (cmd !== 1 && cmd !== 3) return null;
  const atyp = buf[59];
  let host, headerLen;
  if (atyp === 1) {
    if (buf.length < 68) return 'need-more';
    host = buf[60] + '.' + buf[61] + '.' + buf[62] + '.' + buf[63];
    headerLen = 68;
  } else if (atyp === 3) {
    const len = buf[60];
    if (buf.length < 65 + len) return 'need-more';
    try { host = td.decode(buf.slice(61, 61 + len)); } catch { return null; }
    headerLen = 65 + len;
  } else if (atyp === 4) {
    if (buf.length < 80) return 'need-more';
    const parts = [];
    for (let i = 0; i < 8; i++) parts.push(((buf[60+i*2] << 8) | buf[61+i*2]).toString(16));
    host = parts.join(':');
    headerLen = 80;
  } else return null;
  const port = (buf[headerLen-4] << 8) | buf[headerLen-3];
  if (buf[headerLen-2] !== 0x0d || buf[headerLen-1] !== 0x0a) return null;
  return { host, port, udp: cmd === 3, headerLen };
}

// 简化版 SS: 首包为 SOCKS5 风格地址头(ATYP+ADDR+PORT)+数据, 无 AEAD, 仅个人使用
function parseSsHeader(buf) {
  if (buf.length < 7) return 'need-more';
  const atyp = buf[0];
  let host, headerLen;
  if (atyp === 1) {
    host = buf[1] + '.' + buf[2] + '.' + buf[3] + '.' + buf[4];
    headerLen = 7;
  } else if (atyp === 3) {
    const len = buf[1];
    if (buf.length < 4 + len) return 'need-more';
    try { host = td.decode(buf.slice(2, 2 + len)); } catch { return null; }
    headerLen = 4 + len;
  } else if (atyp === 4) {
    if (buf.length < 19) return 'need-more';
    const parts = [];
    for (let i = 0; i < 8; i++) parts.push(((buf[1+i*2] << 8) | buf[2+i*2]).toString(16));
    host = parts.join(':');
    headerLen = 19;
  } else return null;
  const port = (buf[headerLen-2] << 8) | buf[headerLen-1];
  return { host, port, headerLen };
}

/* ============================== 出站拨号 ============================== */

async function dialOut(cfg, overrides, host, port) {
  const outboundStr = (overrides.outbound || cfg.outbound || '').trim();
  const mode = cfg.outboundMode || 'proxy-first';
  const proxyip = (overrides.proxyip || cfg.proxyip || '').trim();
  let targetHost = host, targetPort = port;
  // ProxyIP: 目标是 TLS 端口时, 改拨反代 IP, 靠客户端 TLS 的 SNI 寻路 (三家通用做法)
  if (proxyip && TLS_PORTS.includes(port)) {
    const hp = parseHostPort(proxyip, 443);
    if (hp) { targetHost = hp.host; targetPort = hp.port; }
  }
  const direct = async () => {
    const sock = await withTimeout(connect({ hostname: targetHost, port: targetPort }), DIAL_TIMEOUT_MS, 'dial timeout');
    return { sock, leftover: new Uint8Array(0) };
  };
  const viaProxy = async () => {
    const p = parseProxyUrl(outboundStr);
    if (!p) throw new Error('bad outbound proxy');
    if (p.scheme === 'socks5') {
      const sock = await connectViaSocks5(p, targetHost, targetPort);
      return { sock, leftover: new Uint8Array(0) };
    }
    if (p.scheme === 'http') return connectViaHttp(p, targetHost, targetPort);
    throw new Error('unsupported proxy scheme (仅支持 socks5/http)');
  };
  if (!outboundStr) return direct();
  if (mode === 'proxy-only') return viaProxy();
  if (mode === 'direct-first') {
    try { return await direct(); } catch { return viaProxy(); }
  }
  try { return await viaProxy(); } catch { return direct(); } // proxy-first
}

async function connectViaSocks5(p, host, port) {
  const sock = await withTimeout(connect({ hostname: p.host, port: p.port }), DIAL_TIMEOUT_MS, 'proxy dial timeout');
  const r = new SocketReader(sock.readable);
  const w = sock.writable.getWriter();
  try {
    const methods = p.auth ? [0x02] : [0x00];
    await w.write(new Uint8Array([0x05, methods.length, ...methods]));
    const mres = await r.readExactly(2);
    if (mres[0] !== 0x05) throw new Error('bad socks5 greeting');
    if (mres[1] === 0x02) {
      if (!p.auth) throw new Error('socks5 需要认证');
      const u = te.encode(p.auth.user), pw = te.encode(p.auth.pass);
      if (u.length > 255 || pw.length > 255) throw new Error('socks5 认证信息过长');
      await w.write(concatBytes(new Uint8Array([0x01, u.length]), u, new Uint8Array([pw.length]), pw));
      const ares = await r.readExactly(2);
      if (ares[1] !== 0x00) throw new Error('socks5 认证失败');
    } else if (mres[1] !== 0x00) throw new Error('socks5 无可用认证方式');
    const hb = te.encode(host);
    if (hb.length > 255) throw new Error('目标域名过长');
    await w.write(concatBytes(
      new Uint8Array([0x05, 0x01, 0x00, 0x03, hb.length]), hb,
      new Uint8Array([(port >> 8) & 0xff, port & 0xff])));
    const rep = await r.readExactly(4);
    if (rep[0] !== 0x05 || rep[1] !== 0x00) throw new Error('socks5 连接目标失败: ' + rep[1]);
    const atyp = rep[3];
    if (atyp === 1) await r.readExactly(6);
    else if (atyp === 3) { const l = (await r.readExactly(1))[0]; await r.readExactly(l + 2); }
    else if (atyp === 4) await r.readExactly(18);
    else throw new Error('socks5 响应地址类型异常');
  } catch (e) {
    try { w.releaseLock(); } catch {}
    r.release();
    try { sock.close(); } catch {}
    throw e;
  }
  w.releaseLock();
  r.release();
  return sock;
}

async function connectViaHttp(p, host, port) {
  const sock = await withTimeout(connect({ hostname: p.host, port: p.port }), DIAL_TIMEOUT_MS, 'proxy dial timeout');
  const r = new SocketReader(sock.readable);
  const w = sock.writable.getWriter();
  try {
    let req = 'CONNECT ' + host + ':' + port + ' HTTP/1.1\r\nHost: ' + host + ':' + port + '\r\n';
    if (p.auth) req += 'Proxy-Authorization: Basic ' + btoa(p.auth.user + ':' + p.auth.pass) + '\r\n';
    req += 'Connection: keep-alive\r\n\r\n';
    await w.write(te.encode(req));
    const head = await r.readUntil(te.encode('\r\n\r\n'));
    const status = td.decode(head).split('\r\n')[0];
    if (!/ 200(\s|$)/.test(status)) throw new Error('http 代理拒绝: ' + status);
  } catch (e) {
    try { w.releaseLock(); } catch {}
    r.release();
    try { sock.close(); } catch {}
    throw e;
  }
  const leftover = r.leftover();
  w.releaseLock();
  r.release();
  return { sock, leftover };
}

/* ---- TCP Socket 定长/定界读取器(握手阶段用) ---- */
class SocketReader {
  constructor(readable) {
    this.reader = readable.getReader();
    this.buf = new Uint8Array(0);
    this.eof = false;
  }
  async _fill() {
    if (this.eof) return false;
    const { done, value } = await this.reader.read();
    if (done) { this.eof = true; return false; }
    const nb = new Uint8Array(this.buf.length + value.length);
    nb.set(this.buf); nb.set(value, this.buf.length);
    this.buf = nb;
    return true;
  }
  async readExactly(n, timeoutMs = 8000) {
    const t0 = Date.now();
    while (this.buf.length < n) {
      if (Date.now() - t0 > timeoutMs) throw new Error('read timeout');
      if (!await this._fill()) throw new Error('unexpected eof');
    }
    const out = this.buf.slice(0, n);
    this.buf = this.buf.slice(n);
    return out;
  }
  async readUntil(delim, maxLen = 8192, timeoutMs = 8000) {
    const t0 = Date.now();
    for (;;) {
      const idx = findSub(this.buf, delim);
      if (idx >= 0) {
        const out = this.buf.slice(0, idx + delim.length);
        this.buf = this.buf.slice(idx + delim.length);
        return out;
      }
      if (this.buf.length > maxLen) throw new Error('header too large');
      if (Date.now() - t0 > timeoutMs) throw new Error('read timeout');
      if (!await this._fill()) throw new Error('unexpected eof');
    }
  }
  leftover() { return this.buf; }
  release() { try { this.reader.releaseLock(); } catch {} }
}
function findSub(buf, sub) {
  outer: for (let i = 0; i + sub.length <= buf.length; i++) {
    for (let j = 0; j < sub.length; j++) if (buf[i + j] !== sub[j]) continue outer;
    return i;
  }
  return -1;
}
