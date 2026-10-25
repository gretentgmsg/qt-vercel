#!/usr/bin/env node
'use strict';

/*
 * 精简加固版：仅保留 VLESS + Trojan (WebSocket)。
 * 已移除：哪吒探针、AUTO_ACCESS 保活上报、SS 节点(无认证)、第三方 IP/ISP 查询、调试日志。
 * 唯一依赖：ws
 *
 * 环境变量：
 *   UUID          必填，合法 UUID（8-4-4-4-12 十六进制）
 *   SUB_PATH      订阅路径，建议 ≥16 位随机串；未设置/过短则关闭订阅接口
 *   DOMAIN        订阅里使用的域名（不设置则取请求的 Host）
 *   NAME          节点名称，默认 Proxy
 *   WSPATH        可选，WebSocket 路径；默认由 UUID 派生的 16 位十六进制串
 *   PORT          监听端口，默认 3000
 *   MAX_CONN      最大并发隧道数，默认 100
 *   IDLE_TIMEOUT  单连接空闲超时(秒)，默认 300
 *   ALLOWED_HOSTS 可选，逗号分隔的 Host 白名单（注意：看到的是 Vercel 收到的 Host）
 */

const http = require('http');
const net = require('net');
const dns = require('dns');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const wsLib = require('ws');
const WebSocketServer = wsLib.WebSocketServer || wsLib.Server;
const createWebSocketStream = wsLib.createWebSocketStream;

// ========================== 配置 ==========================
const env = (k, d = '') => (process.env[k] === undefined ? d : String(process.env[k]).trim());

const UUID = env('UUID').toLowerCase();
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
if (!UUID_RE.test(UUID)) {
  console.error('[FATAL] 环境变量 UUID 缺失或格式不合法，需为 8-4-4-4-12 位十六进制 UUID。');
  process.exit(1);
}

const DOMAIN = env('DOMAIN');
const NAME = env('NAME', 'Proxy');
const PORT = parseInt(env('PORT', '3000'), 10) || 3000;
const MAX_CONN = parseInt(env('MAX_CONN', '100'), 10) || 100;
const IDLE_MS = (parseInt(env('IDLE_TIMEOUT', '300'), 10) || 300) * 1000;

const WSPATH = (env('WSPATH') ||
  crypto.createHash('sha256').update('ws:' + UUID).digest('hex').slice(0, 16)).replace(/^\/+/, '');
if (!/^[A-Za-z0-9._~-]+$/.test(WSPATH)) {
  console.error('[FATAL] WSPATH 只能包含字母、数字及 . _ ~ -');
  process.exit(1);
}
const WS_PATH = '/' + WSPATH;

const SUB_PATH = env('SUB_PATH').replace(/^\/+/, '');
const SUB_ENABLED = SUB_PATH.length >= 12 && /^[A-Za-z0-9._~-]+$/.test(SUB_PATH);

const ALLOWED_HOSTS = env('ALLOWED_HOSTS').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);

const UUID_BUF = Buffer.from(UUID.replace(/-/g, ''), 'hex');
const TROJAN_HASH = Buffer.from(crypto.createHash('sha224').update(UUID).digest('hex')); // 56 字节 ASCII

const BLOCKED_PORTS = new Set([25, 135, 137, 138, 139, 445]);
const BLOCKED_DOMAINS = [
  'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
  'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org'
];

const FAIL_LIMIT = 10;                 // 窗口内允许的认证失败次数
const FAIL_WINDOW = 10 * 60 * 1000;    // 失败计数窗口
const FIRST_MSG_TIMEOUT = 10 * 1000;   // 握手后必须在此时间内发出首包
const CONNECT_TIMEOUT = 10 * 1000;     // 出站连接超时

// ========================== 页面与响应 ==========================
const PAGE_HTML = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">' +
  '<meta name="viewport" content="width=device-width,initial-scale=1"><title>Welcome</title>' +
  '<style>body{font-family:system-ui,sans-serif;margin:15vh auto;max-width:32rem;padding:0 1rem;color:#333}' +
  'h1{font-weight:500}</style></head><body><h1>Welcome</h1>' +
  '<p>This site is under construction. Please check back later.</p></body></html>';
const NOT_FOUND_HTML = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>404 Not Found</title></head>' +
  '<body><h1>404 Not Found</h1></body></html>';

let INDEX_HTML = PAGE_HTML;
try { INDEX_HTML = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8'); } catch (e) { /* 使用默认页 */ }

const COMMON_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Cache-Control': 'no-store'
};

function send(res, code, type, body) {
  res.writeHead(code, { ...COMMON_HEADERS, 'Content-Type': type, 'Content-Length': Buffer.byteLength(body) });
  res.end(res.req && res.req.method === 'HEAD' ? undefined : body);
}

function rejectUpgrade(socket) {
  try {
    socket.write('HTTP/1.1 404 Not Found\r\nContent-Type: text/html; charset=utf-8\r\n' +
      'Content-Length: ' + Buffer.byteLength(NOT_FOUND_HTML) + '\r\nConnection: close\r\n\r\n' + NOT_FOUND_HTML);
  } catch (e) { /* ignore */ }
  socket.destroy();
}

// ========================== 限流 / 封禁 ==========================
const buckets = new Map();
function hit(key, limit, windowMs) {
  const now = Date.now();
  const b = buckets.get(key);
  if (!b || now - b.t > windowMs) { buckets.set(key, { t: now, n: 1 }); return false; }
  b.n++;
  return b.n > limit;
}
function isBanned(ip) {
  const b = buckets.get('fail:' + ip);
  return !!b && Date.now() - b.t <= FAIL_WINDOW && b.n > FAIL_LIMIT;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, b] of buckets) if (now - b.t > 3600 * 1000) buckets.delete(k);
}, 10 * 60 * 1000).unref();

function clientIP(req) {
  const h = req.headers;
  const v = h['cf-connecting-ip'] || h['x-real-ip'] || (h['x-forwarded-for'] || '').split(',')[0].trim();
  return String(v || req.socket.remoteAddress || 'unknown');
}

function hostAllowed(req) {
  if (!ALLOWED_HOSTS.length) return true;
  const h = (req.headers.host || '').split(':')[0].toLowerCase();
  return ALLOWED_HOSTS.includes(h);
}

// ========================== 目标地址校验（防 SSRF / 内网访问） ==========================
function v6groups(ip) {
  let s = ip.toLowerCase().split('%')[0];
  const v4 = s.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    const p = v4[1].split('.').map(Number);
    s = s.slice(0, -v4[1].length) + ((p[0] << 8) | p[1]).toString(16) + ':' + ((p[2] << 8) | p[3]).toString(16);
  }
  const idx = s.indexOf('::');
  if (idx === -1) return s.split(':').map(x => parseInt(x, 16));
  const head = s.slice(0, idx) ? s.slice(0, idx).split(':') : [];
  const tail = s.slice(idx + 2) ? s.slice(idx + 2).split(':') : [];
  const fill = new Array(Math.max(0, 8 - head.length - tail.length)).fill(0);
  return [...head.map(x => parseInt(x, 16)), ...fill, ...tail.map(x => parseInt(x, 16))];
}

function isPrivateIP(ip) {
  if (net.isIPv4(ip)) {
    const [a, b, c] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 0 && c === 0) ||
      (a === 192 && b === 168) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a >= 224;
  }
  if (net.isIPv6(ip)) {
    const g = v6groups(ip);
    if (g.length !== 8 || g.some(x => Number.isNaN(x))) return true;
    const v4of = (hi, lo) => `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
    if (g.slice(0, 5).every(x => x === 0)) {
      if (g[5] === 0xffff) return isPrivateIP(v4of(g[6], g[7])); // ::ffff:a.b.c.d
      if (g[5] === 0) return true;                                // ::, ::1, ::/96
    }
    if (g[0] === 0x64 && g[1] === 0xff9b) return isPrivateIP(v4of(g[6], g[7])); // NAT64
    if (g[0] === 0x2002) return isPrivateIP(v4of(g[1], g[2]));                  // 6to4
    if ((g[0] & 0xfe00) === 0xfc00) return true;  // fc00::/7
    if ((g[0] & 0xffc0) === 0xfe80) return true;  // fe80::/10
    if ((g[0] >> 8) === 0xff) return true;        // ff00::/8
    return false;
  }
  return true; // 无法识别 → 拦截
}

function isBlockedDomain(host) {
  const h = host.toLowerCase();
  return BLOCKED_DOMAINS.some(d => h === d || h.endsWith('.' + d));
}

function isBlockedTarget(host, port) {
  if (!host || host.length > 253 || !port) return true;
  if (BLOCKED_PORTS.has(port)) return true;
  if (isBlockedDomain(host)) return true;
  if (net.isIP(host) && isPrivateIP(host)) return true;
  return false;
}

// 解析后再校验 IP（域名解析到内网地址、DNS 重绑定同样会被拦截）
function safeLookup(hostname, options, cb) {
  dns.lookup(hostname, options, (err, address, family) => {
    if (err) return cb(err);
    if (Array.isArray(address)) {
      const ok = address.filter(a => !isPrivateIP(a.address));
      if (!ok.length) return cb(new Error('blocked'));
      return cb(null, ok);
    }
    if (isPrivateIP(address)) return cb(new Error('blocked'));
    cb(null, address, family);
  });
}

// ========================== 协议解析 ==========================
function ipv6From(buf, i) {
  const parts = [];
  for (let k = 0; k < 8; k++) parts.push(buf.readUInt16BE(i + k * 2).toString(16));
  return parts.join(':');
}

// VLESS: 版本1 + UUID16 + 附加信息长度1 + 附加信息 + 命令1 + 端口2 + 地址类型1 + 地址
function parseVless(msg) {
  if (msg.length < 22) return null;
  let i = 18 + msg[17];
  if (msg.length < i + 4) return null;
  if (msg[i++] !== 1) return null;                 // 仅支持 TCP
  const port = msg.readUInt16BE(i); i += 2;
  const atyp = msg[i++];
  let host;
  if (atyp === 1) {
    if (msg.length < i + 4) return null;
    host = `${msg[i]}.${msg[i + 1]}.${msg[i + 2]}.${msg[i + 3]}`; i += 4;
  } else if (atyp === 2) {
    const l = msg[i++];
    if (!l || msg.length < i + l) return null;
    host = msg.toString('utf8', i, i + l); i += l;
  } else if (atyp === 3) {
    if (msg.length < i + 16) return null;
    host = ipv6From(msg, i); i += 16;
  } else return null;
  return { host, port, payload: msg.subarray(i), version: msg[0] };
}

// Trojan: SHA224(密码)hex(56) + CRLF + 命令1 + 地址类型1 + 地址 + 端口2 + CRLF + 数据
function parseTrojan(msg) {
  if (msg.length < 62) return null;
  if (!crypto.timingSafeEqual(msg.subarray(0, 56), TROJAN_HASH)) return null;
  let i = 56;
  if (msg[i] === 0x0d && msg[i + 1] === 0x0a) i += 2;
  if (msg[i++] !== 1) return null;                 // 仅支持 CONNECT
  const atyp = msg[i++];
  let host;
  if (atyp === 1) {
    if (msg.length < i + 4) return null;
    host = `${msg[i]}.${msg[i + 1]}.${msg[i + 2]}.${msg[i + 3]}`; i += 4;
  } else if (atyp === 3) {
    const l = msg[i++];
    if (!l || msg.length < i + l) return null;
    host = msg.toString('utf8', i, i + l); i += l;
  } else if (atyp === 4) {
    if (msg.length < i + 16) return null;
    host = ipv6From(msg, i); i += 16;
  } else return null;
  if (msg.length < i + 2) return null;
  const port = msg.readUInt16BE(i); i += 2;
  if (msg[i] === 0x0d && msg[i + 1] === 0x0a) i += 2;
  return { host, port, payload: msg.subarray(i) };
}

// ========================== 隧道 ==========================
let activeConns = 0;

function openTunnel(ws, t, isVless) {
  const duplex = createWebSocketStream(ws);   // 先创建，缓冲连接建立期间到达的数据
  duplex.on('error', () => {});
  if (isVless) ws.send(Buffer.from([t.version, 0]));

  const socket = net.connect({ host: t.host, port: t.port, lookup: safeLookup });
  socket.setNoDelay(true);
  socket.setTimeout(IDLE_MS, () => socket.destroy());
  const ct = setTimeout(() => socket.destroy(), CONNECT_TIMEOUT);

  socket.once('connect', () => {
    clearTimeout(ct);
    if (t.payload.length) socket.write(t.payload);
    duplex.pipe(socket);
    socket.pipe(duplex);
  });
  socket.on('error', () => { clearTimeout(ct); socket.destroy(); duplex.destroy(); });
  socket.on('close', () => { clearTimeout(ct); if (!duplex.writableEnded) duplex.end(); });
  ws.on('close', () => { clearTimeout(ct); socket.destroy(); });
}

function fail(ws, ip) {
  hit('fail:' + ip, FAIL_LIMIT, FAIL_WINDOW);
  setTimeout(() => { try { ws.terminate(); } catch (e) { /* ignore */ } }, 1000 + Math.random() * 3000);
}

function onConnection(ws, ip) {
  activeConns++;
  ws.on('close', () => { activeConns--; });
  ws.on('error', () => {});

  const timer = setTimeout(() => { try { ws.terminate(); } catch (e) { /* ignore */ } }, FIRST_MSG_TIMEOUT);

  ws.once('message', data => {
    clearTimeout(timer);
    const msg = Buffer.isBuffer(data) ? data : Buffer.from(data);

    let target = null, isVless = false;
    if (msg.length > 17 && msg[0] === 0 && crypto.timingSafeEqual(msg.subarray(1, 17), UUID_BUF)) {
      target = parseVless(msg);
      isVless = true;
    } else {
      target = parseTrojan(msg);
    }

    if (!target) return fail(ws, ip);                        // 认证/解析失败：计入失败次数
    if (isBlockedTarget(target.host, target.port)) {         // 已认证但目标被禁止：直接断开
      try { ws.close(); } catch (e) { /* ignore */ }
      return;
    }
    openTunnel(ws, target, isVless);
  });
}

// ========================== HTTP / WebSocket 服务 ==========================
function buildSubscription(req) {
  const domain = DOMAIN || (req.headers.host || '').split(':')[0];
  if (!/^[A-Za-z0-9.-]+$/.test(domain)) return null;
  const name = encodeURIComponent(NAME);
  const q = `security=tls&sni=${domain}&fp=chrome&type=ws&host=${domain}&path=${encodeURIComponent(WS_PATH)}`;
  const vless = `vless://${UUID}@${domain}:443?encryption=none&${q}#${name}`;
  const trojan = `trojan://${UUID}@${domain}:443?${q}#${name}`;
  return Buffer.from(vless + '\n' + trojan).toString('base64') + '\n';
}

const httpServer = http.createServer((req, res) => {
  req.on('error', () => {});
  const ip = clientIP(req);
  const pathname = (req.url || '/').split('?')[0];

  if ((req.method !== 'GET' && req.method !== 'HEAD') || !hostAllowed(req)) {
    return send(res, 404, 'text/html; charset=utf-8', NOT_FOUND_HTML);
  }
  if (pathname === '/' || pathname === '/index.html') {
    return send(res, 200, 'text/html; charset=utf-8', INDEX_HTML);
  }
  if (SUB_ENABLED && pathname === '/' + SUB_PATH && !hit('sub:' + ip, 30, 10 * 60 * 1000)) {
    const body = buildSubscription(req);
    if (body) return send(res, 200, 'text/plain; charset=utf-8', body);
  }
  return send(res, 404, 'text/html; charset=utf-8', NOT_FOUND_HTML);
});

const wss = new WebSocketServer({ noServer: true, maxPayload: 8 * 1024 * 1024 });

httpServer.on('upgrade', (req, socket, head) => {
  socket.on('error', () => {});
  const ip = clientIP(req);
  const pathname = (req.url || '').split('?')[0];
  // 路径不对、来源被封禁、并发已满：与普通 404 完全一致，不做 WebSocket 升级
  if (pathname !== WS_PATH || !hostAllowed(req) || isBanned(ip) || activeConns >= MAX_CONN) {
    return rejectUpgrade(socket);
  }
  wss.handleUpgrade(req, socket, head, ws => onConnection(ws, ip));
});

process.on('uncaughtException', e => console.error('uncaught:', e && e.message));
process.on('unhandledRejection', e => console.error('unhandled:', e && e.message));

httpServer.listen(PORT, () => {
  console.log(`Server is running on ${PORT}`);
  if (!SUB_ENABLED) console.warn('[WARN] SUB_PATH 未设置或少于 12 位，订阅接口已关闭');
});
