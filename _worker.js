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

/* ============================== 常量与地区定义 ============================== */

// 默认优选: CF 官方 Anycast 节点 IP (默认开箱即用，国内三大运营商均有路由)
const DEFAULT_PREFERRED_IPS = [
  '104.16.1.1', '104.17.1.1', '104.18.1.1', '104.19.1.1', '104.20.1.1',
  '104.21.1.1', '104.22.1.1', '104.24.1.1', '104.25.1.1', '104.26.1.1',
  '104.27.1.1', '172.67.1.1', '162.159.1.1', '1.1.1.1', '1.0.0.1'
];

// 常见落地机房与地区分类 (Ingress 机场码 / Colo 识别)
const REGIONS = [
  { code: 'HK', name: '香港节点', flag: '🇭🇰', match: /香港|HK|Hong\s*Kong|HKG/i, colos: ['HKG'] },
  { code: 'JP', name: '日本节点', flag: '🇯🇵', match: /日本|东京|大阪|JP|Japan|Tokyo|Osaka|NRT|HND|KIX|FUK|OKA|CTS/i, colos: ['NRT', 'HND', 'KIX', 'FUK', 'OKA', 'CTS'] },
  { code: 'US', name: '美国节点', flag: '🇺🇸', match: /美国|美区|US|USA|United\s*States|America|SJC|LAX|SFO|ORD|IAD|EWR|JFK|SEA|ATL|DFW|DEN|PHX|MIA|BOS/i, colos: ['SJC', 'LAX', 'SFO', 'ORD', 'IAD', 'EWR', 'JFK', 'SEA', 'ATL', 'DFW', 'DEN', 'PHX', 'MIA', 'BOS', 'CLT', 'IAH', 'DTW', 'MSP'] },
  { code: 'SG', name: '新加坡节点', flag: '🇸🇬', match: /新加坡|狮城|SG|Singapore|SIN/i, colos: ['SIN'] },
  { code: 'TW', name: '台湾节点', flag: '🇹🇼', match: /台湾|台北|TW|Taiwan|Taipei|TPE|KHH/i, colos: ['TPE', 'KHH'] },
  { code: 'KR', name: '韩国节点', flag: '🇰🇷', match: /韩国|首尔|KR|Korea|Seoul|ICN/i, colos: ['ICN'] },
  { code: 'DE', name: '德国节点', flag: '🇩🇪', match: /德国|DE|Germany|Frankfurt|Berlin|FRA|BER|MUC/i, colos: ['FRA', 'BER', 'MUC', 'DUS'] },
  { code: 'UK', name: '英国节点', flag: '🇬🇧', match: /英国|UK|GB|Britain|London|LHR|MAN/i, colos: ['LHR', 'MAN', 'EDI'] },
];

function identifyRegion(remark, coloInfo) {
  // 1. 用户手动备注优先级最高 (#香港, #JP, #美国等)
  if (remark) {
    for (const reg of REGIONS) {
      if (reg.match.test(remark)) return reg;
    }
  }
  // 2. 本地测速记录的 Ingress 落地机场码 / 地区 (从 KV 读)
  if (coloInfo) {
    const loc = (coloInfo.loc || '').toUpperCase();
    const colo = (coloInfo.colo || '').toUpperCase();
    for (const reg of REGIONS) {
      if (loc && (loc === reg.code || (reg.code === 'UK' && loc === 'GB'))) return reg;
      if (colo && reg.colos.includes(colo)) return reg;
    }
  }
  return null;
}

const TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
const PLAIN_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
const WS_TIMEOUT_MS = 10000;
const DIAL_TIMEOUT_MS = 8000;

/* ============================== 工具函数 ============================== */

const te = new TextEncoder();
const td = new TextDecoder();

/* ---- TCP Socket 定长/定界读取器 ---- */
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

// 探测目标 IP 的 Cloudflare Ingress 落地机房 (Colo / 机场码)
async function probeColo(host) {
  try {
    const sock = await withTimeout(connect({ hostname: host, port: 80 }), 3000, 'timeout');
    const w = sock.writable.getWriter();
    await w.write(te.encode('GET /cdn-cgi/trace HTTP/1.1\r\nHost: cloudflare.com\r\nConnection: close\r\n\r\n'));
    w.releaseLock();
    const r = new SocketReader(sock.readable);
    const head = await r.readUntil(te.encode('\r\n\r\n'), 4096, 3000);
    const headStr = td.decode(head);
    let bodyStr = '';
    const clM = headStr.match(/content-length:\s*(\d+)/i);
    const contentLen = clM ? parseInt(clM[1], 10) : 0;
    try {
      if (contentLen > 0 && contentLen <= 4096) {
        const bodyBytes = await r.readExactly(contentLen, 1500);
        bodyStr = td.decode(bodyBytes);
      } else {
        // 无 Content-Length 或分块时读取可用残余数据
        const chunks = [r.leftover()];
        const t0 = Date.now();
        while (Date.now() - t0 < 1500) {
          const ok = await r._fill();
          if (!ok) break;
          chunks.push(r.leftover());
          r.buf = new Uint8Array(0);
        }
        bodyStr = td.decode(concatBytes(...chunks));
      }
    } catch {
      bodyStr = td.decode(r.leftover());
    }
    try { sock.close(); } catch {}
    const text = headStr + '\n' + bodyStr;
    const rayM = text.match(/cf-ray:\s*[a-f0-9]+-([A-Z]+)/i);
    const coloM = text.match(/colo=([A-Z]+)/i);
    const locM = text.match(/loc=([A-Z]+)/i);
    const colo = (rayM ? rayM[1] : (coloM ? coloM[1] : null))?.toUpperCase() || null;
    const loc = (locM ? locM[1] : null)?.toUpperCase() || null;
    return { colo, loc };
  } catch {
    return { colo: null, loc: null };
  }
}

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
/* ============================== ProxyIP 解析 (edgetunnel 做法) ============================== */
// ProxyIP 是域名时, 按 TXT → A → AAAA 顺序解析出真实 IP 列表 (如 ProxyIP.US.CMLiussss.net 的 TXT 指向真实 proxy IP)
// 带 5 分钟缓存, 避免每个连接都查 DNS
const _proxyIPCache = new Map();
async function _dohQuery(dohUrl, name, type) {
  const typeCode = type === 'TXT' ? 16 : type === 'A' ? 1 : 28;
  const resp = await fetch(`${dohUrl}?name=${encodeURIComponent(name)}&type=${type}`, {
    headers: { 'accept': 'application/dns-json' },
  });
  if (!resp.ok) throw new Error(`DoH ${resp.status}`);
  const data = await resp.json();
  return (data.Answer || []).filter(a => a.type === typeCode).map(a => a.data);
}
function _isIPAddr(h) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(h) || h.includes(':');
}
async function resolveProxyIPs(cfg, proxyip) {
  const now = Date.now();
  const cached = _proxyIPCache.get(proxyip);
  if (cached && cached.expire > now) return cached.ips;
  const dohUrl = cfg.doh || 'https://cloudflare-dns.com/dns-query';
  const out = [];
  for (const entry of proxyip.split(',').map(s => s.trim()).filter(Boolean)) {
    const hp = parseHostPort(entry, 443);
    if (!hp) continue;
    let host = hp.host, port = hp.port;
    const tpM = entry.match(/\.tp(\d+)/i);
    if (tpM) port = parseInt(tpM[1], 10);
    if (_isIPAddr(host)) { out.push([host, port]); continue; }
    let done = false;
    try {
      const txts = await _dohQuery(dohUrl, host, 'TXT');
      for (let txt of txts) {
        if (txt.startsWith('"') && txt.endsWith('"')) txt = txt.slice(1, -1);
        for (const part of txt.replace(/\\010/g, ',').split(',').map(s => s.trim()).filter(Boolean)) {
          const php = parseHostPort(part, port);
          if (!php) continue;
          if (_isIPAddr(php.host)) { out.push([php.host, php.port]); done = true; }
          else {
            try {
              for (const a of await _dohQuery(dohUrl, php.host, 'A')) { out.push([a, php.port]); done = true; }
            } catch (e) { /* skip */ }
          }
        }
      }
      if (done) continue;
    } catch (e) { /* fall through */ }
    try {
      const aRecs = await _dohQuery(dohUrl, host, 'A');
      if (aRecs.length) { for (const a of aRecs) out.push([a, port]); continue; }
    } catch (e) { /* fall through */ }
    try {
      const aaaaRecs = await _dohQuery(dohUrl, host, 'AAAA');
      if (aaaaRecs.length) { for (const a of aaaaRecs) out.push([`[${a}]`, port]); continue; }
    } catch (e) { /* fall through */ }
    out.push([host, port]);
  }
  const ips = out.slice(0, 8);
  _proxyIPCache.set(proxyip, { ips, expire: now + 5 * 60 * 1000 });
  return ips;
}

function parseNodeItem(raw) {
  let str = String(raw || '').trim();
  let remark = '';
  const hashIdx = str.indexOf('#');
  if (hashIdx >= 0) {
    remark = str.slice(hashIdx + 1).trim();
    str = str.slice(0, hashIdx).trim();
  }
  const hp = parseHostPort(str, null);
  const ip = hp ? hp.host : str;
  const port = hp && hp.port ? hp.port : null;
  return { ip, explicitPort: port, remark };
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
  const coloMap = (await kvGetJSON(env, 'cfu:colos')) || {};
  let uuid = String(kvc.uuid || env.UUID || '').trim();
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
    adminPass: String(kvc.adminPass || env.ADMIN_PASS || 'admin').trim(),
    subKey: String(kvc.subKey || env.SUB_KEY || uuid.replace(/-/g, '').slice(0, 8)).trim(),
    customPath: (kvc.customPath || env.CUSTOM_PATH || '').replace(/^\/+|\/+$/g, ''),
    proxyip: (kvc.proxyip || env.PROXYIP || '').trim(),
    outbound: (kvc.outbound || env.OUTBOUND || '').trim(),
    outboundMode: kvc.outboundMode || env.OUTBOUND_MODE || 'proxy-first',
    fakeUrl: kvc.fakeUrl || env.FAKE_URL || '',
    doh: kvc.doh || env.DOH || 'https://cloudflare-dns.com/dns-query',
    pVless: kvc.pVless ?? envFlag(env.P_VLESS, true),
    pTrojan: kvc.pTrojan ?? envFlag(env.P_TROJAN, true),
    pSs: kvc.pSs ?? envFlag(env.P_SS, false),
    preferredIps: Array.isArray(kvc.preferredIps) && kvc.preferredIps.length ? kvc.preferredIps : DEFAULT_PREFERRED_IPS.slice(),
    maxNodes: Math.min(Math.max(+kvc.maxNodes || +env.MAX_NODES || 24, 1), 200),
    logConn: kvc.logConn ?? envFlag(env.LOG_CONN, false),
    enableVg: kvc.enableVg ?? envFlag(env.ENABLE_VG, false),
    coloMap,
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
  const a = m[1].trim(), b = (cfg.adminPass || '').trim();
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
      return handleWS(request, env, ctx, cfg, segs.slice(1));
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
      // 订阅路径严格匹配：多余路径段直接 404，避免拼错地址却返回错误格式的内容
      if (segs.length > 2) return new Response('Not Found', { status: 404 });
      const sub = (segs[1] || '').toLowerCase();
      const target = (url.searchParams.get('target') || '').toLowerCase();
      if (sub === 'vg' || sub === 'jk' || target === 'vg' || target === 'jk') {
        return handleHomeBroadbandSub(cfg, url);
      }
      if (sub === 'sub') return subPlain(cfg, url);
      if (sub === 'clash') return subClash(cfg, url);
      if (sub === 'singbox' || sub === 'sing-box') return subSingbox(cfg, url);
      if (sub === 'v2ray') return subV2ray(cfg, url);
      if (!sub) {
        return new Response(sharePageHTML(cfg, url), { headers: { 'Content-Type': 'text/html;charset=utf-8' } });
      }
      return new Response('Not Found', { status: 404 });
    }

    // 3.5) 出站诊断 (需要 admin 密码)
    if (segs[0] === 'diag' && (url.searchParams.get('key') || '').trim() === cfg.adminPass) {
      const out = { time: new Date().toISOString(), proxyip: cfg.proxyip || '(empty)', doh: cfg.doh };
      // a) 直接拨号测试
      try {
        const t0 = Date.now();
        const s = await withTimeout(connect({ hostname: 'example.com', port: 443 }), 8000, 'timeout');
        s.close();
        out.direct443 = `OK (${Date.now() - t0}ms)`;
      } catch (e) { out.direct443 = `FAIL: ${e.message}`; }
      // a2) 直连 TLS 握手测试 (SNI=example.com)
      try {
        const t0 = Date.now();
        const s = await withTimeout(connect({ hostname: 'example.com', port: 443 }), 8000, 'timeout');
        const sniB = new TextEncoder().encode('example.com');
        const ext = new Uint8Array(9 + sniB.length);
        const ev = new DataView(ext.buffer);
        ev.setUint16(0, 0x0000); ev.setUint16(2, 5 + sniB.length);
        ev.setUint16(4, 3 + sniB.length); ext[6] = 0x00;
        ev.setUint16(7, sniB.length); ext.set(sniB, 9);
        const helloLen = 2 + 32 + 1 + 2 + 2 + 2 + ext.length;
        const hello = new Uint8Array(helloLen);
        const hv = new DataView(hello.buffer);
        let o2 = 0;
        hv.setUint16(o2, 0x0303); o2 += 2;
        crypto.getRandomValues(hello.subarray(o2, o2 + 32)); o2 += 32;
        hello[o2++] = 0x00;
        hv.setUint16(o2, 0x002f); o2 += 2;
        hello[o2++] = 0x01; hello[o2++] = 0x00;
        hv.setUint16(o2, ext.length); o2 += 2;
        hello.set(ext, o2);
        const rec = new Uint8Array(5 + hello.length);
        rec[0] = 0x16; rec[1] = 0x03; rec[2] = 0x01;
        new DataView(rec.buffer).setUint16(3, hello.length);
        rec.set(hello, 5);
        const w2 = s.writable.getWriter();
        await w2.write(rec); w2.releaseLock();
        const r2 = s.readable.getReader();
        const rd2 = await withTimeout(r2.read(), 8000, 'no response');
        r2.releaseLock(); s.close();
        out.directTls = (rd2.value && rd2.value[0] === 0x16) ? `OK (${Date.now() - t0}ms)` : `FAIL: empty`;
      } catch (e) { out.directTls = `FAIL: ${e.message}`; }
      // b) ProxyIP 解析测试
      if (cfg.proxyip) {
        // b0) SNI 寻路测试: 经 ProxyIP 发 TLS ClientHello, 看能否拿到 ServerHello
        try {
          const pipIps = await resolveProxyIPs(cfg, cfg.proxyip);
          if (pipIps.length) {
            const [th, tp] = pipIps[0];
            const t0 = Date.now();
            const s = await withTimeout(connect({ hostname: th, port: tp }), 8000, 'timeout');
            // 最小 TLS ClientHello, SNI=example.com
            const sniB = new TextEncoder().encode('example.com');
            const extLen = 2 + 2 + 2 + 1 + sniB.length;
            const ext = new Uint8Array(4 + extLen);
            const ev = new DataView(ext.buffer);
            ev.setUint16(0, 0x0000); ev.setUint16(2, extLen - 4);
            ev.setUint16(4, extLen - 6); ext[6] = 0x00;
            ev.setUint16(7, sniB.length); ext.set(sniB, 9);
            const helloLen = 2 + 32 + 1 + 2 + 2 + 2 + ext.length;
            const hello = new Uint8Array(helloLen);
            const hv = new DataView(hello.buffer);
            let o = 0;
            hv.setUint16(o, 0x0303); o += 2;
            crypto.getRandomValues(hello.subarray(o, o + 32)); o += 32;
            hello[o++] = 0x00;
            hv.setUint16(o, 0x002f); o += 2;
            hello[o++] = 0x01; hello[o++] = 0x00;
            hv.setUint16(o, ext.length); o += 2;
            hello.set(ext, o);
            const rec = new Uint8Array(5 + hello.length);
            rec[0] = 0x16; rec[1] = 0x03; rec[2] = 0x01;
            new DataView(rec.buffer).setUint16(3, hello.length);
            rec.set(hello, 5);
            const w = s.writable.getWriter();
            await w.write(rec); w.releaseLock();
            const r = s.readable.getReader();
            const rd = await withTimeout(r.read(), 8000, 'no response');
            r.releaseLock(); s.close();
            const bytes = rd.value ? Array.from(rd.value.slice(0, 3)).map(b => b.toString(16).padStart(2, '0')).join(' ') : 'empty';
            out.sniTest = (rd.value && rd.value[0] === 0x16) ? `OK (${Date.now() - t0}ms): got TLS ServerHello via ${th}` : `FAIL: got [${bytes}] via ${th}`;
          }
        } catch (e) { out.sniTest = `FAIL: ${e.message}`; }

        try {
          const t0 = Date.now();
          const ips = await resolveProxyIPs(cfg, cfg.proxyip);
          out.proxyipResolve = `OK (${Date.now() - t0}ms): ${ips.map(x => x.join(':')).join(', ')}`;
          // c) 逐个拨号测试
          out.proxyipDial = [];
          for (const [ph, pp] of ips.slice(0, 4)) {
            try {
              const t1 = Date.now();
              const s = await withTimeout(connect({ hostname: ph, port: pp }), 8000, 'timeout');
              s.close();
              out.proxyipDial.push(`${ph}:${pp} OK (${Date.now() - t1}ms)`);
            } catch (e) { out.proxyipDial.push(`${ph}:${pp} FAIL: ${e.message}`); }
          }
        } catch (e) { out.proxyipResolve = `FAIL: ${e.message}`; }
      }
      return new Response(JSON.stringify(out, null, 2), { headers: { 'Content-Type': 'application/json' } });
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
    + (cfg.enableVg ? subRow(base + '/vg', 'CLASH 家宽链式订阅 (仅 mihomo ≥ 1.19.25)') : '')
    + '<p class="tip">把订阅地址填入客户端的订阅管理即可, 每 15 分钟左右会自动更新优选。</p></div>'
    + (cfg.enableVg ? '<div class="card" style="background:#fffbe6;border:1px solid #ffe58f"><h2>⚠️ 家宽链式代理须知</h2><p class="tip" style="color:#ad6800">1. 流量出口为全球志愿者共享家庭宽带，TLS 可保内容安全，但出口端可观测目标域名与 DNS。请勿用于敏感账户！<br>2. 仅支持 mihomo ≥ 1.19.25 (如 Clash Verge Rev、FlClash)；Sing-box、v2rayNG 等客户端不支持链式代理。<br>3. 节点掉线为正常现象，「🏠 家宽自动」策略组具备自动切换能力。</p></div>' : '')
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
  + '.msg{position:fixed;top:16px;left:50%;transform:translateX(-50%);z-index:9999;padding:12px 24px;border-radius:24px;font-size:14px;box-shadow:0 4px 16px rgba(0,0,0,.2);font-weight:600;display:none;max-width:90%;text-align:center}'
  + '.msg.ok{display:block;background:#2e7d32;color:#fff}.msg.err{display:block;background:#d32f2f;color:#fff}'
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
  + '<div class="f"><label>全局出站跳板 ProxyIP（用于访问 Cloudflare 网站，严禁填 CF 优选 IP，必须是非 CF 的第三方 IP 或域名，如 ProxyIP.US.CMLiussss.net）</label><input type="text" id="c-proxyip"></div>'
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
  + '<div class="chk"><input type="checkbox" id="c-enableVg"><label for="c-enableVg">启用家宽链式代理 (实验性: 仅支持 mihomo/Clash Meta 内核)</label></div>'
  + '<button class="btn" id="btnSaveCfg" onclick="saveConfig(this)">保存</button>'
  + '<button class="btn ghost" onclick="loadConfig()">重新加载</button>'
  + '<button class="btn danger" onclick="resetConfig()">清空面板配置(回退到环境变量)</button></div>'
  // 优选 IP tab
  + '<div class="card page hide" id="p-ips"><h3>优选 IP / 域名 (每行一个, 用于生成订阅节点)</h3>'
  + '<div class="f"><textarea id="ips" placeholder="1.1.1.1"></textarea></div>'
  + '<button class="btn" onclick="saveIps()">保存</button>'
  + '<button class="btn ghost" onclick="defaultIps()">恢复默认官方 IP</button></div>'
  // 测速 tab
  + '<div class="card page hide" id="p-speed"><h3>延迟测试与落地机房识别</h3>'
  + '<div class="f"><label>测试目标 (每行一个, 格式 ip 或 ip:端口 或 ip#备注, 最多 30 个)</label>'
  + '<textarea id="speedHosts" style="height:110px"></textarea></div>'
  + '<button class="btn" onclick="runSpeed()">开始测速与识别</button>'
  + '<div id="speedRes" style="margin-top:14px"></div>'
  + '<p style="color:#888;font-size:13px;margin-top:10px">💡 测速时会读取响应头中的 cf-ray 与 trace 信息识别 Ingress 落地机房 (如 HKG/NRT/SJC) 并存入 KV。注意：此处探测的是 Worker 视角的落地机房（基于当前 Worker 执行环境），不同客户端运营商的 Anycast 路由可能略有差异；如需锁定特定地区，可直接在 IP 后追加 <code>#备注</code>（如 <code>1.1.1.1#香港</code>），手动备注优先级最高。</p></div>'
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
  + 'var items=[["通用订阅",d.sub],["Clash 极简订阅",d.clash],["Clash 完整分流",d.clashFull],["Sing-box 极简订阅",d.singbox],["Sing-box 完整分流",d.singboxFull]];'
  + 'if(d.vg)items.push(["CLASH 家宽链式 (仅 mihomo)",d.vg]);'
  + 'items.push(["分享页",d.share]);'
  + 'items.forEach(function(it){h+=\'<div class="linkrow"><code>\'+esc(it[1])+\'</code><button class="cp" onclick="cp2(this,\\\'\'+it[1]+\'\\\')">复制</button></div>\';});'
  + 'document.getElementById("links").innerHTML=h;}).catch(function(e){showMsg(e.message,false);});}'
  + 'function loadConfig(){api("config").then(function(c){'
  + '["uuid","adminPass","subKey","customPath","proxyip","outbound","outboundMode","fakeUrl","doh","maxNodes"].forEach(function(k){'
  + 'var el=document.getElementById("c-"+k);if(el)el.value=c[k]||"";});'
  + 'document.getElementById("c-pVless").checked=!!c.pVless;'
  + 'document.getElementById("c-pTrojan").checked=!!c.pTrojan;'
  + 'document.getElementById("c-pSs").checked=!!c.pSs;'
  + 'document.getElementById("c-logConn").checked=!!c.logConn;'
  + 'document.getElementById("c-enableVg").checked=!!c.enableVg;'
  + '}).catch(function(e){showMsg(e.message,false);});}'
  + 'function saveConfig(btn){btn=btn||document.getElementById("btnSaveCfg");if(btn){btn.disabled=true;btn.textContent="保存中...";}var c={};'
  + '["uuid","adminPass","subKey","customPath","proxyip","outbound","outboundMode","fakeUrl","doh"].forEach(function(k){'
  + 'c[k]=document.getElementById("c-"+k).value.trim();});'
  + 'c.maxNodes=parseInt(document.getElementById("c-maxNodes").value)||24;'
  + 'c.pVless=document.getElementById("c-pVless").checked;'
  + 'c.pTrojan=document.getElementById("c-pTrojan").checked;'
  + 'c.pSs=document.getElementById("c-pSs").checked;'
  + 'c.logConn=document.getElementById("c-logConn").checked;'
  + 'c.enableVg=document.getElementById("c-enableVg").checked;'
  + 'api("ips").then(function(d){c.preferredIps=d.ips;'
  + 'return api("config",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(c)});})'
  + '.then(function(r){if(btn){btn.disabled=false;btn.textContent="✓ 保存成功";setTimeout(function(){btn.textContent="保存";},2000);}'
  + 'if(r.ok){showMsg("保存成功, 已立即生效",true);if(c.adminPass&&c.adminPass!==pw){pw=c.adminPass;sessionStorage.setItem("cfu_pw",pw);}}'
  + 'else showMsg("保存失败: "+(r.error||""),false);}).catch(function(e){if(btn){btn.disabled=false;btn.textContent="保存";}'
  + 'showMsg(e.message,false);});}'
  + 'function resetConfig(){if(!confirm("清空面板配置并回退到环境变量?"))return;'
  + 'api("config",{method:"DELETE"}).then(function(){showMsg("已清空, 重新加载中",true);loadConfig();loadIps();});}'
  + 'function loadIps(){api("ips").then(function(d){document.getElementById("ips").value=(d.ips||[]).join("\\n");'
  + 'document.getElementById("speedHosts").value=(d.ips||[]).slice(0,20).map(function(ip){return ip+":443"}).join("\\n");});}'
  + 'function saveIps(){var ips=document.getElementById("ips").value.split("\\n").map(function(s){return s.trim()}).filter(Boolean);'
  + 'api("ips",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ips:ips})})'
  + '.then(function(){showMsg("优选 IP 已保存",true);}).catch(function(e){showMsg(e.message,false);});}'
  + 'function defaultIps(){api("ips",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({reset:true})})'
  + '.then(function(d){document.getElementById("ips").value=(d.ips||[]).join("\\n");showMsg("已恢复默认",true);});}'
  + 'function runSpeed(){var hosts=document.getElementById("speedHosts").value.split("\\n").map(function(s){return s.trim()}).filter(Boolean).slice(0,30);'
  + 'if(!hosts.length)return;document.getElementById("speedRes").innerHTML="测速与识别落地机房中...";'
  + 'api("latency",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({hosts:hosts})})'
  + '.then(function(d){var rows=d.results.map(function(r){'
  + 'var msText=r.ms==null?("<span style=\\\"color:#f5222d\\\">失败</span>"):("<b>"+r.ms+" ms</b>");'
  + 'var coloText=r.colo?("<span style=\\\"background:#e6f4ff;color:#0958d9;padding:2px 6px;border-radius:4px;font-family:monospace;font-weight:600\\\">"+esc(r.colo)+"</span>"):("-");'
  + 'var regText=r.region?esc(r.region):("-");'
  + 'return "<tr><td class=\\"mono\\">"+esc(r.host)+"</td><td>"+msText+"</td><td>"+coloText+"</td><td>"+regText+"</td></tr>";}).join("");'
  + 'document.getElementById("speedRes").innerHTML="<table><tr><th>目标</th><th>延迟</th><th>落地机房 (Colo)</th><th>地区</th></tr>"+rows+"</table>";})'
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
      if (!env.KV) return json({ error: 'Worker 缺少 KV 绑定，请检查 wrangler.toml 的 kv_namespaces 配置' }, 500);
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
    const res = {
      share: base,
      sub: base + '/sub',
      clash: base + '/clash',
      clashFull: base + '/clash?rules=full',
      singbox: base + '/singbox',
      singboxFull: base + '/singbox?rules=full',
      v2ray: base + '/v2ray'
    };
    if (cfg.enableVg) res.vg = base + '/vg';
    return json(res);
  }

  // 延迟测试: 服务端对目标 TCP 建连计时 + 自动识别 Cloudflare Ingress 落地机房 (Colo/机场码)
  if (action === 'latency' && request.method === 'POST') {
    let body;
    try { body = await request.json(); } catch { return json({ error: 'bad json' }, 400); }
    const hosts = (body.hosts || []).map(s => String(s).trim()).filter(Boolean).slice(0, 30);
    const coloCache = (await kvGetJSON(env, 'cfu:colos')) || {};
    let coloUpdated = false;

    const results = await Promise.all(hosts.map(async (raw) => {
      const item = parseNodeItem(raw);
      if (!item.ip) return { host: raw, ms: null, colo: null, loc: null, region: null };
      const hp = parseHostPort(item.ip, item.explicitPort || 443);
      if (!hp) return { host: raw, ms: null, colo: null, loc: null, region: null };

      const t0 = Date.now();
      try {
        const sock = await withTimeout(connect({ hostname: hp.host, port: hp.port }), 4000, 'timeout');
        const ms = Date.now() - t0;
        try { sock.close(); } catch {}

        let info = coloCache[hp.host];
        if (!info || (Date.now() - (info.t || 0) > 86400000)) {
          const probe = await probeColo(hp.host);
          if (probe.colo) {
            info = { colo: probe.colo, loc: probe.loc, t: Date.now() };
            coloCache[hp.host] = info;
            coloUpdated = true;
          }
        }
        const reg = identifyRegion(item.remark, info);
        return {
          host: raw,
          ms,
          colo: info?.colo || null,
          loc: info?.loc || null,
          region: reg ? `${reg.flag} ${reg.name.replace('节点', '')}` : null
        };
      } catch {
        const info = coloCache[hp.host];
        const reg = identifyRegion(item.remark, info);
        return {
          host: raw,
          ms: null,
          colo: info?.colo || null,
          loc: info?.loc || null,
          region: reg ? `${reg.flag} ${reg.name.replace('节点', '')}` : null
        };
      }
    }));

    if (coloUpdated && env.KV) {
      await kvPut(env, 'cfu:colos', JSON.stringify(coloCache));
      clearConfigCache();
    }
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
  const coloMap = cfg.coloMap || {};
  const descs = [{ name: 'CF-直连', ip: host, port: 443, tls: true, regionCode: null }];
  let n = 0;
  outer:
  for (const raw of ips) {
    const item = parseNodeItem(raw);
    if (!item.ip) continue;
    const ports = item.explicitPort ? [item.explicitPort] : [443];
    const coloInfo = coloMap[item.ip];
    const reg = identifyRegion(item.remark, coloInfo);
    for (const port of ports) {
      if (descs.length >= cfg.maxNodes) break outer;
      n++;
      const short = item.ip.replace(/[^0-9a-z]/gi, '').slice(-6) || ('x' + n);
      let nodeName;
      if (item.remark) {
        nodeName = `${reg ? reg.flag + ' ' : ''}${item.remark}-${port}`;
      } else if (coloInfo && coloInfo.colo) {
        nodeName = `${reg ? reg.flag + ' ' : ''}CF优选-${coloInfo.colo}-${short}-${port}`;
      } else {
        nodeName = `${reg ? reg.flag + ' ' : ''}CF优选-${short}-${port}`;
      }
      descs.push({
        name: nodeName,
        ip: item.ip,
        port,
        tls: TLS_PORTS.includes(port),
        regionCode: reg ? reg.code : null,
      });
    }
  }
  return descs.map(d => ({
    name: d.name, ip: d.ip, port: d.port, tls: d.tls, regionCode: d.regionCode,
    vless: vlessLink(cfg, host, path, d),
    trojan: trojanLink(cfg, host, path, d),
    ss: ssLink(cfg, d),
  }));
}
function vlessLink(cfg, host, path, d) {
  const wsPath = path + (d.tls ? '?ed=2048' : '');
  const p = new URLSearchParams({
    encryption: 'none', security: d.tls ? 'tls' : 'none',
    sni: host, fp: 'chrome', type: 'ws', host, path: wsPath,
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
        + '\n    servername: ' + host + '\n    client-fingerprint: chrome\n    udp: true\n    network: ws'
        + '\n    ws-opts:\n      path: /' + key + '?ed=2048\n      headers:\n        Host: ' + host);
    }
    if (cfg.pTrojan) {
      proxies.push('  - name: ' + q(nm + '-trojan') + '\n    type: trojan\n    server: ' + n.ip + '\n    port: ' + n.port
        + '\n    password: ' + cfg.uuid + '\n    sni: ' + host
        + '\n    client-fingerprint: chrome\n    udp: true\n    network: ws'
        + '\n    ws-opts:\n      path: /' + key + '\n      headers:\n        Host: ' + host);
    }
  }
  const allNames = [];
  for (const n of nodes) {
    if (cfg.pVless) allNames.push(n.name + '-vless');
    if (cfg.pTrojan) allNames.push(n.name + '-trojan');
  }
  const nameList = allNames.length ? allNames.map(q).join(', ') : 'DIRECT';

  // 地区分组
  const regionGroupBlocks = [];
  const activeRegionNames = [];
  const regionMap = {};
  for (const reg of REGIONS) {
    const rProxies = [];
    for (const n of nodes) {
      if (n.regionCode === reg.code) {
        if (cfg.pVless) rProxies.push(q(n.name + '-vless'));
        if (cfg.pTrojan) rProxies.push(q(n.name + '-trojan'));
      }
    }
    if (rProxies.length > 0) {
      const gName = `${reg.flag} ${reg.name}`;
      activeRegionNames.push(gName);
      regionMap[reg.code] = gName;
      regionGroupBlocks.push(
        '  - name: ' + q(gName) + '\n    type: url-test\n    url: http://www.gstatic.com/generate_204\n    interval: 300\n    proxies: [' + rProxies.join(', ') + ']'
      );
    }
  }
  const regList = activeRegionNames.map(q).join(', ');
  const mainProxies = [q('♻️ 自动选择'), ...(regList ? [regList] : []), nameList, q('🎯 全球直连')].join(', ');

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

    const openAiRegions = ['US', 'JP', 'SG'].map(c => regionMap[c]).filter(Boolean).map(q);
    const netflixRegions = ['HK', 'JP', 'SG', 'US'].map(c => regionMap[c]).filter(Boolean).map(q);
    const biliRegions = ['HK', 'TW'].map(c => regionMap[c]).filter(Boolean).map(q);

    const fullGroups = [
      'proxy-groups:',
      '  - name: ' + q('🚀 节点选择') + '\n    type: select\n    proxies: [' + mainProxies + ']',
      '  - name: ' + q('♻️ 自动选择') + '\n    type: url-test\n    url: http://www.gstatic.com/generate_204\n    interval: 300\n    proxies: [' + nameList + ']',
      ...(regionGroupBlocks.length ? regionGroupBlocks : []),
      '  - name: ' + q('🌍 国外媒体') + '\n    type: select\n    proxies: [' + [q('🚀 节点选择'), ...activeRegionNames.map(q), q('♻️ 自动选择'), nameList, q('🎯 全球直连')].join(', ') + ']',
      '  - name: ' + q('📺 哔哩哔哩') + '\n    type: select\n    proxies: [' + [q('🎯 全球直连'), ...biliRegions, q('🚀 节点选择'), q('♻️ 自动选择'), nameList].join(', ') + ']',
      '  - name: ' + q('📹 油管视频') + '\n    type: select\n    proxies: [' + [q('🚀 节点选择'), ...activeRegionNames.map(q), q('🌍 国外媒体'), q('♻️ 自动选择'), nameList, q('🎯 全球直连')].join(', ') + ']',
      '  - name: ' + q('🎬 奈飞视频') + '\n    type: select\n    proxies: [' + [...netflixRegions, q('🚀 节点选择'), q('🌍 国外媒体'), q('♻️ 自动选择'), nameList, q('🎯 全球直连')].join(', ') + ']',
      '  - name: ' + q('📲 电报信息') + '\n    type: select\n    proxies: [' + [q('🚀 节点选择'), ...activeRegionNames.map(q), q('♻️ 自动选择'), nameList, q('🎯 全球直连')].join(', ') + ']',
      '  - name: ' + q('🌐 谷歌服务') + '\n    type: select\n    proxies: [' + [q('🚀 节点选择'), ...activeRegionNames.map(q), q('♻️ 自动选择'), nameList, q('🎯 全球直连')].join(', ') + ']',
      '  - name: ' + q('🤖 OpenAI') + '\n    type: select\n    proxies: [' + [...openAiRegions, q('🚀 节点选择'), q('♻️ 自动选择'), nameList, q('🎯 全球直连')].join(', ') + ']',
      '  - name: ' + q('Ⓜ️ 微软服务') + '\n    type: select\n    proxies: [' + [q('🎯 全球直连'), q('🚀 节点选择'), ...activeRegionNames.map(q), q('♻️ 自动选择'), nameList].join(', ') + ']',
      '  - name: ' + q('🍎 苹果服务') + '\n    type: select\n    proxies: [' + [q('🎯 全球直连'), q('🚀 节点选择'), ...activeRegionNames.map(q), q('♻️ 自动选择'), nameList].join(', ') + ']',
      '  - name: ' + q('🎯 全球直连') + '\n    type: select\n    proxies: [DIRECT]',
      '  - name: ' + q('🛑 全球拦截') + '\n    type: select\n    proxies: [REJECT, DIRECT]',
      '  - name: ' + q('🐟 漏网之鱼') + '\n    type: select\n    proxies: [' + [q('🚀 节点选择'), ...activeRegionNames.map(q), q('♻️ 自动选择'), nameList, q('🎯 全球直连')].join(', ') + ']'
    ].join('\n');

    const fullRules = [
      'rules:',
      '  - AND,((NETWORK,udp),(DST-PORT,443)),REJECT',
      '  - DOMAIN-SUFFIX,local,🎯 全球直连',
      '  - DOMAIN-SUFFIX,googleapis.cn,🌐 谷歌服务',
      '  - DOMAIN-SUFFIX,gstatic.com,🌐 谷歌服务',
      '  - DOMAIN-SUFFIX,googlevideo.com,📹 油管视频',
      '  - DOMAIN-SUFFIX,googleusercontent.com,🌐 谷歌服务',
      '  - DOMAIN-KEYWORD,youtube,📹 油管视频',
      '  - DOMAIN-SUFFIX,youtube.com,📹 油管视频',
      '  - DOMAIN-SUFFIX,youtu.be,📹 油管视频',
      '  - DOMAIN-KEYWORD,netflix,🎬 奈飞视频',
      '  - DOMAIN-SUFFIX,nflxext.com,🎬 奈飞视频',
      '  - DOMAIN-SUFFIX,nflxso.net,🎬 奈飞视频',
      '  - DOMAIN-SUFFIX,nflxvideo.net,🎬 奈飞视频',
      '  - DOMAIN-SUFFIX,nflximg.com,🎬 奈飞视频',
      '  - DOMAIN-SUFFIX,nflximg.net,🎬 奈飞视频',
      '  - DOMAIN-SUFFIX,netflix.com,🎬 奈飞视频',
      '  - DOMAIN-SUFFIX,netflix.net,🎬 奈飞视频',
      '  - DOMAIN-SUFFIX,bilibili.com,📺 哔哩哔哩',
      '  - DOMAIN-SUFFIX,bilivideo.com,📺 哔哩哔哩',
      '  - DOMAIN-SUFFIX,hdslb.com,📺 哔哩哔哩',
      '  - DOMAIN-KEYWORD,openai,🤖 OpenAI',
      '  - DOMAIN-KEYWORD,chatgpt,🤖 OpenAI',
      '  - DOMAIN-SUFFIX,openai.com,🤖 OpenAI',
      '  - DOMAIN-SUFFIX,chatgpt.com,🤖 OpenAI',
      '  - DOMAIN-SUFFIX,oaistatic.com,🤖 OpenAI',
      '  - DOMAIN-SUFFIX,oaiusercontent.com,🤖 OpenAI',
      '  - DOMAIN-SUFFIX,anthropic.com,🤖 OpenAI',
      '  - DOMAIN-SUFFIX,claude.ai,🤖 OpenAI',
      '  - DOMAIN-SUFFIX,perplexity.ai,🤖 OpenAI',
      '  - DOMAIN-SUFFIX,gemini.google.com,🤖 OpenAI',
      '  - RULE-SET,applications,🎯 全球直连',
      '  - RULE-SET,private,🎯 全球直连',
      '  - RULE-SET,reject,🛑 全球拦截',
      '  - RULE-SET,icloud,🍎 苹果服务',
      '  - RULE-SET,apple,🍎 苹果服务',
      '  - RULE-SET,google,🌐 谷歌服务',
      '  - RULE-SET,proxy,🚀 节点选择',
      '  - RULE-SET,gfw,🚀 节点选择',
      '  - RULE-SET,tld-not-cn,🚀 节点选择',
      '  - RULE-SET,direct,🎯 全球直连',
      '  - RULE-SET,lancidr,🎯 全球直连,no-resolve',
      '  - RULE-SET,cncidr,🎯 全球直连,no-resolve',
      '  - RULE-SET,telegramcidr,📲 电报信息,no-resolve',
      '  - GEOIP,LAN,🎯 全球直连,no-resolve',
      '  - GEOIP,CN,🎯 全球直连,no-resolve',
      '  - MATCH,🐟 漏网之鱼'
    ].join('\n');

    const clashDNS =
      'dns:\n'
      + '  enable: true\n'
      + '  ipv6: false\n'
      + '  enhanced-mode: fake-ip\n'
      + '  fake-ip-range: 198.18.0.1/16\n'
      + '  fake-ip-filter:\n'
      + '    - "*.lan"\n'
      + '    - "*.local"\n'
      + '    - "*.msftncsi.com"\n'
      + '    - "*.msftconnecttest.com"\n'
      + '    - "connectivitycheck.gstatic.com"\n'
      + '    - "connectivitycheck.android.com"\n'
      + '    - "time.*.com"\n'
      + '    - "pool.ntp.org"\n'
      + '  nameserver:\n'
      + '    - 223.5.5.5\n'
      + '    - 119.29.29.29\n'
      + '  fallback:\n'
      + '    - https://1.1.1.1/dns-query\n'
      + '    - https://8.8.8.8/dns-query\n'
      + '  fallback-filter:\n'
      + '    geoip: true\n'
      + '    geoip-code: CN\n';

    yaml =
      '# cf-fusion 完整分流规则 (Loyalsoldier 规则集, 客户端直连获取)\n'
      + 'mixed-port: 7890\nallow-lan: true\nmode: rule\nlog-level: info\n'
      + clashDNS
      + 'proxies:\n' + proxies.join('\n') + '\n'
      + fullGroups + '\n'
      + fullProviders + '\n'
      + fullRules + '\n';
  } else {
    const clashDNS =
      'dns:\n'
      + '  enable: true\n'
      + '  ipv6: false\n'
      + '  enhanced-mode: fake-ip\n'
      + '  fake-ip-range: 198.18.0.1/16\n'
      + '  fake-ip-filter:\n'
      + '    - "*.lan"\n'
      + '    - "*.local"\n'
      + '    - "*.msftncsi.com"\n'
      + '    - "*.msftconnecttest.com"\n'
      + '    - "connectivitycheck.gstatic.com"\n'
      + '    - "connectivitycheck.android.com"\n'
      + '    - "time.*.com"\n'
      + '    - "pool.ntp.org"\n'
      + '  nameserver:\n'
      + '    - 223.5.5.5\n'
      + '    - 119.29.29.29\n'
      + '  fallback:\n'
      + '    - https://1.1.1.1/dns-query\n'
      + '    - https://8.8.8.8/dns-query\n'
      + '  fallback-filter:\n'
      + '    geoip: true\n'
      + '    geoip-code: CN\n';

    yaml =
      '# cf-fusion 极简订阅 (本地生成, 无第三方转换)\n'
      + 'mixed-port: 7890\nallow-lan: true\nmode: rule\nlog-level: info\n'
      + clashDNS
      + 'proxies:\n' + proxies.join('\n') + '\n'
      + 'proxy-groups:\n'
      + '  - name: ' + q('🚀 节点选择') + '\n    type: select\n    proxies: [' + mainProxies + ']\n'
      + '  - name: ' + q('♻️ 自动选择') + '\n    type: url-test\n    url: http://www.gstatic.com/generate_204\n    interval: 300\n    proxies: [' + nameList + ']\n'
      + (regionGroupBlocks.length ? regionGroupBlocks.join('\n') + '\n' : '')
      + '  - name: ' + q('🎯 全球直连') + '\n    type: select\n    proxies: [DIRECT]\n'
      + '  - name: ' + q('🛑 全球拦截') + '\n    type: select\n    proxies: [REJECT, DIRECT]\n'
      + 'rules:\n'
      + '  - AND,((NETWORK,udp),(DST-PORT,443)),REJECT\n'
      + '  - DOMAIN-SUFFIX,local,🎯 全球直连\n'
      + '  - IP-CIDR,192.168.0.0/16,🎯 全球直连,no-resolve\n'
      + '  - IP-CIDR,10.0.0.0/8,🎯 全球直连,no-resolve\n'
      + '  - IP-CIDR,172.16.0.0/12,🎯 全球直连,no-resolve\n'
      + '  - IP-CIDR,127.0.0.0/8,🎯 全球直连,no-resolve\n'
      + '  - GEOIP,CN,🎯 全球直连,no-resolve\n'
      + '  - MATCH,🚀 节点选择\n';
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
        transport: { type: 'ws', path: '/' + key, headers: { Host: host }, max_early_data: 2048, early_data_header_name: 'Sec-WebSocket-Protocol' },
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

  // 地区分组
  const regionOutbounds = [];
  const activeRegionTags = [];
  const regionTagMap = {};
  for (const reg of REGIONS) {
    const rTags = [];
    for (const n of nodes) {
      if (n.regionCode === reg.code) {
        if (cfg.pVless) rTags.push(n.name + '-vless');
        if (cfg.pTrojan) rTags.push(n.name + '-trojan');
      }
    }
    if (rTags.length > 0) {
      const gTag = `${reg.flag} ${reg.name}`;
      activeRegionTags.push(gTag);
      regionTagMap[reg.code] = gTag;
      regionOutbounds.push({
        type: 'urltest',
        tag: gTag,
        outbounds: rTags,
        url: 'http://www.gstatic.com/generate_204',
        interval: '5m'
      });
    }
  }

  const inbounds = [
    {
      type: 'tun',
      tag: 'tun-in',
      address: ['172.19.0.1/30'],
      auto_route: true,
      strict_route: true,
      stack: 'mixed',
    }
  ];

  let conf;
  if (isFull) {
    const srsSite = 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite';
    const srsIp = 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip';
    const sRule = name => ({ tag: `geosite-${name}`, type: 'remote', format: 'binary', url: `${srsSite}/${name}.srs` });
    const iRule = name => ({ tag: `geoip-${name}`, type: 'remote', format: 'binary', url: `${srsIp}/${name}.srs` });

    const ruleSets = [
      sRule('cn'), sRule('private'), sRule('apple'), sRule('apple-cn'), sRule('microsoft'), sRule('microsoft@cn'),
      sRule('google'), sRule('telegram'), sRule('openai'), sRule('anthropic'), sRule('youtube'), sRule('netflix'),
      sRule('disney'), sRule('spotify'), sRule('tiktok'), sRule('twitter'), sRule('facebook'), sRule('github'),
      sRule('geolocation-!cn'), sRule('category-ads-all'), iRule('cn'), iRule('private'), iRule('telegram')
    ];

    const openAiRegions = ['US', 'JP', 'SG'].map(c => regionTagMap[c]).filter(Boolean);
    const netflixRegions = ['HK', 'JP', 'SG', 'US'].map(c => regionTagMap[c]).filter(Boolean);
    const biliRegions = ['HK', 'TW'].map(c => regionTagMap[c]).filter(Boolean);

    const fullOutbounds = [
      { type: 'selector', tag: '🚀 节点选择', outbounds: ['♻️ 自动选择', ...activeRegionTags, ...tags, 'direct'], default: '♻️ 自动选择' },
      { type: 'urltest', tag: '♻️ 自动选择', outbounds: tags, url: 'http://www.gstatic.com/generate_204', interval: '5m' },
      ...regionOutbounds,
      { type: 'selector', tag: '🌍 国外媒体', outbounds: ['🚀 节点选择', ...activeRegionTags, '♻️ 自动选择', 'direct', ...tags] },
      { type: 'selector', tag: '📲 电报信息', outbounds: ['🚀 节点选择', ...activeRegionTags, '♻️ 自动选择', 'direct', ...tags] },
      { type: 'selector', tag: '🌐 谷歌服务', outbounds: ['🚀 节点选择', ...activeRegionTags, '♻️ 自动选择', 'direct', ...tags] },
      { type: 'selector', tag: '🤖 OpenAI', outbounds: [...openAiRegions, '🚀 节点选择', ...activeRegionTags, '♻️ 自动选择', 'direct', ...tags] },
      { type: 'selector', tag: 'Ⓜ️ 微软服务', outbounds: ['direct', '🚀 节点选择', ...activeRegionTags, '♻️ 自动选择', ...tags] },
      { type: 'selector', tag: '🍎 苹果服务', outbounds: ['direct', '🚀 节点选择', ...activeRegionTags, '♻️ 自动选择', ...tags] },
      { type: 'selector', tag: '📺 哔哩哔哩', outbounds: ['direct', ...biliRegions, '🚀 节点选择', '♻️ 自动选择', ...tags] },
      { type: 'selector', tag: '📹 油管视频', outbounds: ['🚀 节点选择', ...activeRegionTags, '🌍 国外媒体', '♻️ 自动选择', 'direct', ...tags] },
      { type: 'selector', tag: '🎬 奈飞视频', outbounds: [...netflixRegions, '🚀 节点选择', '🌍 国外媒体', '♻️ 自动选择', 'direct', ...tags] },
      { type: 'selector', tag: '🎯 全球直连', outbounds: ['direct'] },
      { type: 'selector', tag: '🐟 漏网之鱼', outbounds: ['🚀 节点选择', ...activeRegionTags, '♻️ 自动选择', 'direct', ...tags] },
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

    const singboxDNS = {
      servers: [
        { tag: 'dns-remote', type: 'https', server: '1.1.1.1', detour: '🚀 节点选择' },
        { tag: 'dns-remote-backup', type: 'https', server: '8.8.8.8', detour: '🚀 节点选择' },
        { tag: 'dns-direct', type: 'udp', server: '223.5.5.5' },
        { tag: 'dns-local', type: 'local' },
      ],
      rules: [
        { clash_mode: 'Direct', server: 'dns-direct' },
        { clash_mode: 'Global', server: 'dns-remote' },
        { rule_set: 'geosite-category-ads-all', action: 'reject' },
        { rule_set: 'geosite-cn', server: 'dns-direct' },
        { rule_set: 'geosite-apple-cn', server: 'dns-direct' },
        { rule_set: 'geosite-microsoft@cn', server: 'dns-direct' },
      ],
      final: 'dns-remote',
      strategy: 'ipv4_only'
    };

    conf = {
      log: { level: 'info' },
      dns: singboxDNS,
      inbounds,
      outbounds: fullOutbounds,
      route: {
        default_domain_resolver: 'dns-direct',
        default_http_client: 'http-direct',
        rule_set: ruleSets,
        rules: fullRouteRules,
        final: '🐟 漏网之鱼',
        auto_detect_interface: true,
      },
      http_clients: [{ tag: 'http-direct' }],
    };
  } else {
    outbounds.push(
      { type: 'selector', tag: '🚀 节点选择', outbounds: [tags[0] || 'direct', '♻️ 自动选择', ...activeRegionTags, ...tags.slice(1), 'direct'], default: tags[0] || 'direct' },
      { type: 'urltest', tag: '♻️ 自动选择', outbounds: tags, url: 'http://www.gstatic.com/generate_204', interval: '5m' },
      ...regionOutbounds,
      { type: 'direct', tag: 'direct' },
      { type: 'block', tag: 'block' },
    );
    const miniSrsSite = 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite';
    const miniSrsIp = 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip';
    const singboxDNS = {
      servers: [
        { tag: 'dns-remote', type: 'https', server: '1.1.1.1', detour: '🚀 节点选择' },
        { tag: 'dns-remote-backup', type: 'https', server: '8.8.8.8', detour: '🚀 节点选择' },
        { tag: 'dns-direct', type: 'udp', server: '223.5.5.5' },
        { tag: 'dns-local', type: 'local' },
      ],
      rules: [
        { clash_mode: 'Direct', server: 'dns-direct' },
        { clash_mode: 'Global', server: 'dns-remote' },
        { rule_set: 'geosite-cn', server: 'dns-direct' },
      ],
      final: 'dns-remote',
      strategy: 'ipv4_only'
    };
    conf = {
      log: { level: 'info' },
      dns: singboxDNS,
      inbounds,
      outbounds,
      route: {
        default_domain_resolver: 'dns-direct',
        default_http_client: 'http-direct',
        rule_set: [
          { tag: 'geosite-cn', type: 'remote', format: 'binary', url: `${miniSrsSite}/cn.srs` },
          { tag: 'geoip-cn', type: 'remote', format: 'binary', url: `${miniSrsIp}/cn.srs` },
          { tag: 'geoip-private', type: 'remote', format: 'binary', url: `${miniSrsIp}/private.srs` },
        ],
        rules: [
          { action: 'sniff' },
          { protocol: 'dns', action: 'hijack-dns' },
          { ip_is_private: true, outbound: 'direct' },
          { rule_set: 'geoip-private', outbound: 'direct' },
          { rule_set: 'geosite-cn', outbound: 'direct' },
          { rule_set: 'geoip-cn', outbound: 'direct' },
        ],
        final: '🚀 节点选择',
        auto_detect_interface: true,
      },
      http_clients: [{ tag: 'http-direct' }],
    };
  }
  return new Response(JSON.stringify(conf, null, 2), { headers: { 'Content-Type': 'application/json;charset=utf-8' } });
}

/* ============================== 实验性功能: 家宽链式代理 (VPN Gate) ============================== */

const VG_API_URL = 'https://www.vpngate.net/api/iphone/';
const VG_CACHE_TTL_MS = 30 * 60 * 1000; // 30 分钟缓存
let _vgCache = null;
let _vgCacheAt = 0;

function indentCert(text, indent) {
  return text.split('\n').map(l => l.trim()).filter(Boolean).map(l => indent + l).join('\n');
}

function parseVgCsv(csvText) {
  const candidates = [];
  for (const rawLine of csvText.split('\n')) {
    const line = rawLine.trim();
    if (!line || line.startsWith('*') || line.startsWith('#')) continue;
    const lastComma = line.lastIndexOf(',');
    if (lastComma < 0) continue;
    const b64 = line.slice(lastComma + 1).trim();
    const cols = line.slice(0, lastComma).split(',');
    if (cols.length < 7) continue;
    // 过滤掉自营机房服务器
    if ((cols[0] || '').startsWith('public-vpn')) continue;
    if ((cols[1] || '').startsWith('219.100.37.')) continue;
    if (!b64 || b64.length < 100) continue;
    candidates.push({
      country: (cols[6] || '').toUpperCase() || 'OTHER',
      speed: parseInt(cols[4], 10) || 0,
      b64,
    });
  }
  candidates.sort((a, b) => b.speed - a.speed);

  const nodes = [];
  let certs = null;
  for (const item of candidates) {
    let conf = '';
    try {
      conf = atob(item.b64.replace(/\s/g, ''));
    } catch { continue; }

    if (!conf.includes('proto tcp')) continue;
    const remoteM = conf.match(/remote\s+([0-9a-zA-Z\.\-]+)\s+(\d+)/);
    if (!remoteM) continue;

    if (!certs) {
      const caM = conf.match(/<ca>([\s\S]*?)<\/ca>/);
      const certM = conf.match(/<cert>([\s\S]*?)<\/cert>/);
      const keyM = conf.match(/<key>([\s\S]*?)<\/key>/);
      if (caM && certM && keyM) {
        certs = { ca: caM[1].trim(), cert: certM[1].trim(), key: keyM[1].trim() };
      }
      if (!certs) continue;
    }

    const cipherM = conf.match(/cipher\s+([A-Za-z0-9\-]+)/);
    const authM = conf.match(/auth\s+([A-Za-z0-9\-]+)/);
    nodes.push({
      country: item.country,
      host: remoteM[1],
      port: parseInt(remoteM[2], 10) || 443,
      cipher: cipherM ? cipherM[1] : 'AES-128-CBC',
      auth: authM ? authM[1] : 'SHA1',
    });
    if (nodes.length >= 60) break; // 最多保留 60 个优质住宅宽带节点
  }
  return { nodes, certs };
}

async function fetchVgNodes() {
  const now = Date.now();
  if (_vgCache && now - _vgCacheAt < VG_CACHE_TTL_MS) return _vgCache;

  let text = '';
  let lastErr = null;
  for (const u of [VG_API_URL, VG_API_URL.replace(/^https:/, 'http:')]) {
    try {
      const res = await fetch(u, {
        headers: { 'User-Agent': 'Mozilla/5.0', 'Accept': 'text/plain' },
        cf: { cacheTtl: 1800, cacheEverything: true },
      });
      if (res.ok) {
        text = await res.text();
        break;
      }
      lastErr = new Error('HTTP ' + res.status);
    } catch (e) {
      lastErr = e;
    }
  }
  if (!text) throw (lastErr || new Error('无法连接 VPN Gate 节点源'));
  const parsed = parseVgCsv(text);
  if (!parsed.nodes.length || !parsed.certs) throw new Error('未解析出可用 TCP 家宽节点');
  _vgCache = parsed;
  _vgCacheAt = now;
  return parsed;
}

async function handleHomeBroadbandSub(cfg, url) {
  if (!cfg.enableVg) {
    return new Response(
      '【cf-fusion】家宽链式代理功能未开启。\n\n如需使用，请前往管理后台 (/admin) 在「节点配置」中开启「启用家宽链式代理 (实验性)」并保存。',
      { status: 403, headers: { 'Content-Type': 'text/plain;charset=utf-8' } }
    );
  }

  const host = url.host;
  const cfNodes = buildNodes(cfg, host);
  const tlsNodes = cfNodes.filter(n => n.tls);
  const frontNodes = tlsNodes.length ? tlsNodes : cfNodes;
  const frontGroup = '⚡ CF前置';
  const autoGroup = '🏠 家宽自动';
  const selectGroup = '🏠 家宽节点';
  const mainGroup = '🚀 节点选择';

  let vgData;
  try {
    vgData = await fetchVgNodes();
  } catch (e) {
    return new Response(
      `家宽节点列表拉取失败：${e.message}\n请稍后重试，客户端将保留现有缓存。`,
      { status: 503, headers: { 'Content-Type': 'text/plain;charset=utf-8' } }
    );
  }

  const countryCounts = {};
  const vgItems = vgData.nodes.map(n => {
    countryCounts[n.country] = (countryCounts[n.country] || 0) + 1;
    const seq = String(countryCounts[n.country]).padStart(2, '0');
    return {
      ...n,
      name: `🏠 ${n.country}-家宽-${seq}`,
    };
  });

  const frontProxies = [];
  const frontNames = [];
  for (const n of frontNodes) {
    const fn = n.name + '-vless';
    frontNames.push(fn);
    frontProxies.push(
      '  - name: ' + q(fn) + '\n    type: vless\n    server: ' + n.ip + '\n    port: ' + n.port
      + '\n    uuid: ' + cfg.uuid + '\n    tls: ' + (n.tls ? 'true' : 'false')
      + '\n    servername: ' + host + '\n    client-fingerprint: chrome\n    network: ws'
      + '\n    ws-opts:\n      path: /' + (cfg.customPath || cfg.subKey) + '?ed=2048\n      headers:\n        Host: ' + host
    );
  }

  const vgProxies = [];
  vgItems.forEach((n, idx) => {
    const lines = [
      `  - name: ${q(n.name)}`,
      '    type: openvpn',
      `    server: ${n.host}`,
      `    port: ${n.port}`,
      '    proto: tcp',
      '    username: vpn',
      '    password: vpn',
      `    cipher: ${n.cipher}`,
      `    auth: ${n.auth}`,
      '    udp: false',
      '    handshake-timeout: 30',
      '    remote-dns-resolve: true',
      '    dns: [ 8.8.8.8, 1.1.1.1 ]',
      `    dialer-proxy: ${q(frontGroup)}`,
    ];
    if (idx === 0) {
      lines.push('    ca: &vgca |-\n' + indentCert(vgData.certs.ca, '      '));
      lines.push('    cert: &vgcert |-\n' + indentCert(vgData.certs.cert, '      '));
      lines.push('    key: &vgkey |-\n' + indentCert(vgData.certs.key, '      '));
    } else {
      lines.push('    ca: *vgca', '    cert: *vgcert', '    key: *vgkey');
    }
    vgProxies.push(lines.join('\n'));
  });

  const speedSortedNames = vgItems.map(i => q(i.name)).join(', ');
  const countrySortedNames = vgItems.slice()
    .sort((a, b) => a.country.localeCompare(b.country))
    .map(i => q(i.name)).join(', ');

  const yaml = [
    '# ============================================================================== #',
    '# cf-fusion 实验性家宽链式订阅 (VPN Gate Residential Broadband via dialer-proxy)  #',
    '#                                                                                #',
    '# ⚠️ 免责与安全声明:                                                            #',
    '# 1. 流量出口为全球志愿者共享家庭宽带，TLS 内容安全，但出口端可看到目标域名与 DNS  #',
    '# 2. 节点由志愿者维护，掉线属于正常现象；「🏠 家宽自动」策略组具备自动故障转移   #',
    '# 3. 客户端限制：本配置仅适用于 mihomo ≥ 1.19.25 (Clash Verge Rev / FlClash 等)  #',
    '# ============================================================================== #',
    'mixed-port: 7890',
    'allow-lan: false',
    'mode: rule',
    'log-level: info',
    'unified-delay: true',
    'tcp-concurrent: true',
    'dns:',
    '  enable: true',
    '  ipv6: false',
    '  enhanced-mode: fake-ip',
    '  fake-ip-range: 198.18.0.1/16',
    '  nameserver:',
    '    - 223.5.5.5',
    '    - 1.1.1.1',
    '',
    'proxies:',
    ...frontProxies,
    ...vgProxies,
    '',
    'proxy-groups:',
    '  - name: ' + q(frontGroup) + '\n    type: url-test\n    url: http://www.gstatic.com/generate_204\n    interval: 300\n    proxies: [' + frontNames.map(q).join(', ') + ']',
    '  - name: ' + q(autoGroup) + '\n    type: fallback\n    url: http://www.gstatic.com/generate_204\n    interval: 1800\n    lazy: true\n    proxies: [' + speedSortedNames + ']',
    '  - name: ' + q(selectGroup) + '\n    type: select\n    proxies: [' + countrySortedNames + ']',
    '  - name: ' + q(mainGroup) + '\n    type: select\n    proxies: [' + q(autoGroup) + ', ' + q(selectGroup) + ', ' + q(frontGroup) + ', DIRECT]',
    '',
    'rules:',
    '  - DOMAIN-SUFFIX,local,DIRECT',
    '  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve',
    '  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve',
    '  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve',
    '  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve',
    '  - GEOIP,CN,DIRECT',
    '  - MATCH,' + mainGroup,
    ''
  ].join('\n');

  return new Response(yaml, {
    headers: { 'Content-Type': 'text/yaml;charset=utf-8', 'Cache-Control': 'no-store' }
  });
}

/* ============================== WebSocket 代理核心 ============================== */

async function handleWS(request, env, ctx, cfg, extraSegs) {
  const pair = new WebSocketPair();
  const client = pair[0], server = pair[1];
  server.accept();
  const url = new URL(request.url);
  const overrides = parseOverrides(url, extraSegs);

  // Early Data (0-RTT) 支持: 客户端可能将首包放在 Sec-WebSocket-Protocol 头中
  const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
  let earlyData = null;
  if (earlyDataHeader) {
    try {
      const b64 = earlyDataHeader.replace(/-/g, '+').replace(/_/g, '/');
      const bin = atob(b64);
      const arr = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
      earlyData = arr;
    } catch {}
  }

  // 保持 Worker 协程活跃，防止在 101 返回后被边缘环境提前回收
  const p = handleConnection(server, env, cfg, overrides, extraSegs, earlyData).catch(() => {
    try { server.close(1011, 'internal error'); } catch {}
  });
  if (ctx && typeof ctx.waitUntil === 'function') ctx.waitUntil(p);

  const respHeaders = {};
  if (earlyDataHeader) {
    respHeaders['Sec-WebSocket-Protocol'] = earlyDataHeader;
  }
  return new Response(null, { status: 101, webSocket: client, headers: respHeaders });
}

async function handleConnection(ws, env, cfg, overrides, extraSegs, earlyData) {
  const reader = makeWSReader(ws, earlyData);
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

  // UDP 专有处理: 若为 DNS 查询 (53 端口), 走 DoH (https://cloudflare-dns.com/dns-query) 快速响应
  // 彻底规避 Cloudflare Workers 无 UDP 出站能力导致全网无法解析域名的致命问题
  if (sess.udp) {
    if (sess.port === 53) {
      await handleDnsUdp(ws, reader, sess, cfg);
      return;
    }
    ws.close(1003, 'UDP only supported for DNS (port 53)');
    return;
  }

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

  const writer = sock.writable.getWriter();
  ws.addEventListener('close', () => { try { writer.releaseLock(); } catch {} });
  // 切换为直通模式: 已缓冲的(去掉协议头后)数据先发, 后续消息实时转发
  reader.setForward(async (d) => { await writer.write(d); });
  // 关键修复: 将 2 字节 VLESS 头 (或响应前缀) 与远端返回的首包数据合并发送, 严禁提前独立发送空头
  await pumpSocketToWS(sock, ws, sess.responsePrefix, dial.leftover);
}

/* ---- DNS over HTTPS: 代理 UDP 53 端口查询 ---- */
async function handleDnsUdp(ws, reader, sess, cfg) {
  let headerToSend = sess.responsePrefix && sess.responsePrefix.length ? sess.responsePrefix : null;
  const dohUrl = cfg.doh || 'https://cloudflare-dns.com/dns-query';

  let udpBuf = new Uint8Array(0);
  async function processDnsQuery(msg) {
    try {
      const resp = await fetch(dohUrl, {
        method: 'POST',
        headers: {
          'Accept': 'application/dns-message',
          'Content-Type': 'application/dns-message',
        },
        body: msg,
      });
      if (!resp.ok) return;
      const resBuf = await resp.arrayBuffer();
      const resBytes = new Uint8Array(resBuf);
      const lenBuf = new Uint8Array([(resBytes.length >> 8) & 0xff, resBytes.length & 0xff]);
      if (ws.readyState !== 1) return;
      if (headerToSend) {
        ws.send(concatBytes(headerToSend, lenBuf, resBytes));
        headerToSend = null;
      } else {
        ws.send(concatBytes(lenBuf, resBytes));
      }
    } catch {}
  }

  reader.setForward(async (d) => {
    udpBuf = concatBytes(udpBuf, d);
    while (udpBuf.length >= 2) {
      const len = (udpBuf[0] << 8) | udpBuf[1];
      if (udpBuf.length < 2 + len) break;
      const dnsMsg = udpBuf.slice(2, 2 + len);
      udpBuf = udpBuf.slice(2 + len);
      await processDnsQuery(dnsMsg);
    }
  });
}

/* ---- 远端 Socket 数据流推送到 WebSocket (严格保证协议响应头与首包合并) ---- */
async function pumpSocketToWS(sock, ws, responsePrefix, leftover) {
  let headerToSend = responsePrefix && responsePrefix.length ? responsePrefix : null;
  try {
    if (leftover && leftover.length) {
      if (headerToSend) {
        ws.send(concatBytes(headerToSend, leftover));
        headerToSend = null;
      } else {
        ws.send(leftover);
      }
    }
    const r = sock.readable.getReader();
    try {
      for (;;) {
        const { done, value } = await r.read();
        if (done) break;
        if (ws.readyState !== 1) break;
        if (headerToSend) {
          ws.send(concatBytes(headerToSend, value));
          headerToSend = null;
        } else {
          ws.send(value);
        }
      }
    } finally { r.releaseLock(); }
  } catch {} finally {
    try { ws.close(); } catch {}
    try { sock.close(); } catch {}
  }
}

/* ---- WS 带缓冲读取器: 支持 Early Data、握手阶段缓存、握手完成后切换直通 ---- */
function makeWSReader(ws, earlyData) {
  const queue = earlyData && earlyData.length ? [earlyData] : [];
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

// Cloudflare 官方 IP 段 (https://www.cloudflare.com/ips/)
// Worker 不能直连这些 IP, 必须经 ProxyIP 跳板
const CF_IPV4_RANGES = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22',
  '141.101.64.0/18', '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20',
  '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'
];
function _ipv4ToInt(ip) {
  const p = ip.split('.');
  if (p.length !== 4) return -1;
  let n = 0;
  for (const o of p) { const v = parseInt(o, 10); if (isNaN(v) || v < 0 || v > 255) return -1; n = (n << 8) + v; }
  return n >>> 0;
}
function isCloudflareIP(ip) {
  if (!ip || ip.includes(':')) return false; // IPv6 暂不检测
  const ipInt = _ipv4ToInt(ip);
  if (ipInt < 0) return false;
  for (const cidr of CF_IPV4_RANGES) {
    const [base, bitsStr] = cidr.split('/');
    const baseInt = _ipv4ToInt(base);
    const bits = parseInt(bitsStr, 10);
    const mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
    if ((ipInt & mask) === (baseInt & mask)) return true;
  }
  return false;
}
async function dialOut(cfg, overrides, host, port) {
  const outboundStr = (overrides.outbound || cfg.outbound || '').trim();
  const mode = cfg.outboundMode || 'proxy-first';
  const proxyip = (overrides.proxyip || cfg.proxyip || '').trim();
  const direct = async () => {
    const sock = await withTimeout(connect({ hostname: host, port }), DIAL_TIMEOUT_MS, 'dial timeout');
    return { sock, leftover: new Uint8Array(0) };
  };
  // SOCKS5/HTTP 出站代理
  if (outboundStr) {
    const viaProxy = async () => {
      const p = parseProxyUrl(outboundStr);
      if (!p) throw new Error('bad outbound proxy');
      if (p.scheme === 'socks5') {
        const sock = await connectViaSocks5(p, host, port);
        return { sock, leftover: new Uint8Array(0) };
      }
      if (p.scheme === 'http') return connectViaHttp(p, host, port);
      throw new Error('unsupported proxy scheme (仅支持 socks5/http)');
    };
    if (mode === 'proxy-only') return viaProxy();
    if (mode === 'direct-first') {
      try { return await direct(); } catch { return viaProxy(); }
    }
    try { return await viaProxy(); } catch { return direct(); } // proxy-first
  }
  // ProxyIP: 仅当目标为 Cloudflare IP 段时使用
  // 原理: CF 官方限制 Worker 不能直连 CF 自有 IP 段 (TCP sockets to CF ranges blocked),
  // 需经第三方 ProxyIP 跳板: Worker -> ProxyIP(非CF) -> CF目标。
  // 跳板机从客户端 TLS ClientHello 明文 SNI 识别目标, 盲转发字节到 CF 边缘。
  // 非 CF 目标走直连 (更快)。Worker 全程只做 TCP 管道, 不参与 TLS 握手。
  // 参考: https://github.com/suprev/CF-Workers-CheckProxyIP
  if (proxyip && TLS_PORTS.includes(port)) {
    let targetIsCF = false;
    try {
      if (_isIPAddr(host)) {
        targetIsCF = isCloudflareIP(host);
      } else {
        // 域名: DoH 查 A 记录判断是否为 CF IP
        const dohUrl = cfg.doh || 'https://cloudflare-dns.com/dns-query';
        const aRecs = await withTimeout(_dohQuery(dohUrl, host, 'A'), 2500, 'doh timeout');
        targetIsCF = aRecs.some(isCloudflareIP);
      }
    } catch (e) { /* 解析失败则默认直连 */ }
    if (targetIsCF) {
      try {
        const ips = await resolveProxyIPs(cfg, proxyip);
        for (const [ph, pp] of ips) {
          try {
            const sock = await withTimeout(connect({ hostname: ph, port: pp }), DIAL_TIMEOUT_MS, 'proxyip dial timeout');
            return { sock, leftover: new Uint8Array(0) };
          } catch (e) { /* 换下一个 IP */ }
        }
      } catch (e) { /* 解析失败, 回退直连 */ }
      // ProxyIP 全失败则回退直连 (尽力而为)
    }
  }
  return direct();
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

