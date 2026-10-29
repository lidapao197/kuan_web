'use strict';
/**
 * 网页版酷安 —— 本地后端
 * 1) 每个请求实时生成 X-App-Token（v3 签名）
 * 2) 把 /api/* 代理到 https://api.coolapk.com/*
 * 3) 把 /image?url= 代理到酷安图床（补 Referer 防盗链）
 * 4) 托管 public/ 下的静态前端
 */
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { getTokenV3, encodeDevice } = require('./lib/token');
const { generateDuid, validDuid: validGuestDuid } = require('./lib/shuzilm');
const logger = require('./lib/logger');

const PORT = process.env.PORT || 9002;
const API_HOST = 'https://api.coolapk.com';
const API2_HOST = 'https://api2.coolapk.com';

// 上游会话 Cookie 罐：酷安会通过 Set-Cookie 下发 SESSID 等会话，
// 后续请求必须带回，否则部分接口（如评论列表）会要求验证码
const cookieJar = new Map();
// 接口风控验证码凭证。协议来源：c001apk captcha_challenge.dart / interceptor.dart（MIT）
//   空 captchaField -> Cookie 协议，值形如 validate=NEC:<captchaId 前8位>:<validate>（整体 URL 编码）
//   非空 captchaField -> 以该字段名作为查询参数回传
// 有效期 24 小时，且与登录会话绑定（换号后必须重新验证）
// 本地数据统一放在 data/ 下（账号、验证码凭证、日志）
const DATA_DIR = path.join(__dirname, 'data');
try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch { /* ignore */ }
const CAPTCHA_FILE = path.join(DATA_DIR, 'captcha.json');
const CAPTCHA_TTL = 24 * 3600 * 1000;
let captchaProof = null; // { proof, field, captchaId, capturedAt }
try {
  const saved = JSON.parse(fs.readFileSync(CAPTCHA_FILE, 'utf8'));
  if (saved && saved.proof && saved.captchaId) captchaProof = saved;
} catch { /* 无历史凭证 */ }
function captchaFresh() {
  return !!(captchaProof && Date.now() - (captchaProof.capturedAt || 0) < CAPTCHA_TTL);
}

function absorbCookies(upstream) {
  for (const c of upstream.headers.getSetCookie?.() || []) {
    const pair = c.split(';')[0];
    const eq = pair.indexOf('=');
    if (eq > 0) cookieJar.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
  }
}
function cookieHeader() {
  return [...cookieJar].map(([k, v]) => `${k}=${v}`).join('; ');
}

// 固定一个仿真安卓设备信息（Windows/PC 等字样会触发酷安风控验证码）
const ANDROID_DEVICE = {
  brand: 'Xiaomi',
  model: 'M2012K11AC', // Redmi K40
  build: 'TKQ1.220829.002',
  sdk: '33',
};

const VERSION_NAME = '16.2.0';
const VERSION_CODE = '2604201';
const API_VERSION = '16';
const SDK_INT = ANDROID_DEVICE.sdk;

// 常见机型预设：营销名 -> 请求头所需的设备参数
const DEVICE_PRESETS = {
  '荣耀X50': { brand: 'HONOR', model: 'REP-AN00', build: 'HONORREP-AN00', sdk: '33', android: '13' },
  '荣耀X50 Pro': { brand: 'HONOR', model: 'REP-AN10', build: 'HONORREP-AN10', sdk: '33', android: '13' },
  'Redmi K40': { brand: 'Xiaomi', model: 'M2012K11AC', build: 'TKQ1.220829.002', sdk: '33', android: '13' },
  '小米14': { brand: 'Xiaomi', model: '23127PN0CC', build: 'UKQ1.230804.001', sdk: '34', android: '14' },
  '小米13': { brand: 'Xiaomi', model: '2211133C', build: 'TKQ1.220829.002', sdk: '33', android: '13' },
  '华为Mate60 Pro': { brand: 'HUAWEI', model: 'ALN-AL10', build: 'HUAWEIALN-AL10', sdk: '34', android: '14' },
  '一加Ace 3': { brand: 'OnePlus', model: 'PHK110', build: 'UKQ1.230924.001', sdk: '34', android: '14' },
  'iPhone 15 Pro': { brand: 'Apple', model: 'iPhone15,2', build: '21E236', sdk: '34', android: '14' },
};

// 根据账号配置的自定义机型生成设备信息与 UA（未配置时用默认设备）
function buildDeviceProfile(acc) {
  const name = (acc && acc.deviceModel || '').trim();
  const p = (name && DEVICE_PRESETS[name]) ||
    (name ? { brand: 'HONOR', model: name, build: 'HONOR' + name, sdk: '33', android: '13' } :
      ANDROID_DEVICE);
  const info = [
    'com.coolapk.market',
    crypto.createHash('md5').update(p.model + 'coolapk-web').digest('hex').slice(0, 16),
    'WIFI', p.brand, p.brand, p.model, p.android,
  ].join(';');
  return {
    device: encodeDevice(info),
    ua: `Dalvik/2.1.0 (Linux; U; Android ${p.android}; ${p.model} Build/${p.build}) +CoolMarket/${VERSION_NAME}-${VERSION_CODE}`,
    sdk: p.sdk,
  };
}

const DEFAULT_DEVICE = buildDeviceProfile(null);
const X_APP_DEVICE = DEFAULT_DEVICE.device;
const DEFAULT_UA = DEFAULT_DEVICE.ua;

// 同一台设备、同一秒内生成的 token 完全相同；缓存后避免每个请求都跑一次 bcrypt
const tokenCache = new Map();
function appToken(device, appCode = Number(VERSION_CODE)) {
  const sec = Math.floor(Date.now() / 1000);
  const key = device + '|' + appCode;
  const hit = tokenCache.get(key);
  if (hit && hit.sec === sec) return hit.token;
  const token = getTokenV3(device, sec, appCode);
  if (tokenCache.size > 24) tokenCache.clear(); // 设备/版本变体很少，防止无限增长
  tokenCache.set(key, { sec, token });
  return token;
}

// ---------- 游客设备身份（公开读接口用，避开登录设备触发的风控验证码） ----------
const GUEST_FILE = path.join(DATA_DIR, 'guest.json');
const GUEST_APP_VERSION = '16.6.5';
const GUEST_APP_CODE = 2610162;
const GUEST_SDK_INT = '36';
const GUEST_MODEL = '23113RKC6C';
const GUEST_BUILD = 'AQ3A.250226.002';
const GUEST_UA = `Dalvik/2.1.0 (Linux; U; Android 16; ${GUEST_MODEL} Build/${GUEST_BUILD}) ` +
  `(#Build; Redmi; ${GUEST_MODEL}; ${GUEST_BUILD}; 16) +CoolMarket/${GUEST_APP_VERSION}-${GUEST_APP_CODE}-universal`;

let guestIdentity = null;   // { duid, deviceCode }
let guestLoading = null;
let guestFailedAt = 0;

function buildGuestDeviceCode(duid) {
  // 官方标准 9 段格式：{DUID}; ; ; ; 厂商; 品牌; 机型; Build; OAID
  return encodeDevice(`${duid}; ; ; ; Xiaomi; Redmi; ${GUEST_MODEL}; ${GUEST_BUILD}; `);
}

function readGuestIdentity() {
  if (guestIdentity) return guestIdentity;
  try {
    const saved = JSON.parse(fs.readFileSync(GUEST_FILE, 'utf8'));
    if (validGuestDuid(saved.duid)) {
      guestIdentity = { duid: saved.duid, deviceCode: buildGuestDeviceCode(saved.duid) };
      return guestIdentity;
    }
  } catch { /* 首次使用 */ }
  return null;
}

/** 懒加载游客 DUID：成功写入 data/guest.json，失败后 60 秒内不再重试 */
async function ensureGuestIdentity() {
  const cached = readGuestIdentity();
  if (cached) return cached;
  if (Date.now() - guestFailedAt < 60_000) return null;
  if (!guestLoading) {
    guestLoading = (async () => {
      try {
        const duid = await generateDuid();
        if (!validGuestDuid(duid)) throw new Error('DUID 格式无效');
        const identity = { duid, deviceCode: buildGuestDeviceCode(duid) };
        guestIdentity = identity;
        try { fs.writeFileSync(GUEST_FILE, JSON.stringify(identity, null, 2)); } catch { /* ignore */ }
        return identity;
      } catch (err) {
        guestFailedAt = Date.now();
        logger.warn('guest_identity_failed', { error: err.message });
        return null;
      } finally {
        guestLoading = null;
      }
    })();
  }
  return guestLoading;
}

function guestHeaders(identity) {
  return {
    'User-Agent': GUEST_UA,
    'X-Requested-With': 'XMLHttpRequest',
    'X-Sdk-Int': GUEST_SDK_INT,
    'X-Sdk-Locale': 'zh-CN',
    'X-App-Id': 'com.coolapk.market',
    'X-App-Token': appToken(identity.deviceCode, GUEST_APP_CODE),
    'X-App-Version': GUEST_APP_VERSION,
    'X-App-Code': String(GUEST_APP_CODE),
    'X-Api-Version': API_VERSION,
    'X-App-Device': identity.deviceCode,
    'X-Dark-Mode': '0',
    'X-App-Channel': 'coolapk',
    'X-App-Mode': 'universal',
    'X-App-Supported': String(GUEST_APP_CODE),
  };
}

function clientHeaders(acc) {
  // 配置了设备信息时完全模拟用户手机：device 与 token 绑定，UA 与 device 一致
  const profile = buildDeviceProfile(acc) || DEFAULT_DEVICE;
  const device = (acc && acc.device) ? acc.device : profile.device;
  const ua = (acc && acc.ua) ? acc.ua : profile.ua;
  return {
    'User-Agent': ua,
    'X-Requested-With': 'XMLHttpRequest',
    'X-Sdk-Int': (acc && acc.device) ? SDK_INT : profile.sdk,
    'X-Sdk-Locale': 'zh-CN',
    'X-App-Id': 'com.coolapk.market',
    'X-App-Token': appToken(device),
    'X-App-Version': VERSION_NAME,
    'X-App-Code': VERSION_CODE,
    'X-Api-Version': API_VERSION,
    'X-App-Device': device,
    'X-Dark-Mode': '0',
    'X-App-Channel': 'coolapk',
    'X-App-Mode': 'universal',
    'X-App-Supported': VERSION_CODE,
  };
}

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'), {
  etag: true,
  lastModified: true,
  setHeaders: (res, filePath) => {
    // 表情图与图标不会变，长缓存；其余静态资源保持协商缓存，改完刷新即生效
    const immutable = /[\\/]emotions[\\/]/.test(filePath) || /[\\/]logo\.ico$/.test(filePath);
    res.setHeader('Cache-Control', immutable ? 'public, max-age=604800, immutable' : 'no-cache');
  },
}));

// ---------- 账号配置（本地文件存储，用于解除评论等接口的匿名风控） ----------
const ACCOUNT_FILE = path.join(DATA_DIR, 'account.json');
// 账号文件按 mtime 缓存：每个 API 请求都要读，避免每次都做同步读盘 + JSON.parse
let accountCache = { mtime: -1, data: null };
function readAccount() {
  try {
    const st = fs.statSync(ACCOUNT_FILE);
    if (accountCache.mtime === st.mtimeMs) return accountCache.data;
    const data = JSON.parse(fs.readFileSync(ACCOUNT_FILE, 'utf8'));
    accountCache = { mtime: st.mtimeMs, data };
    return data;
  } catch {
    accountCache = { mtime: -1, data: null };
    return null;
  }
}
/** 写账号配置并立即失效内存缓存（避免同一毫秒内 mtime 未变导致读到旧值） */
function writeAccount(data) {
  fs.writeFileSync(ACCOUNT_FILE, JSON.stringify(data, null, 2));
  accountCache = { mtime: -1, data: null };
}

// ---------- 最近登录账号（退出登录只清当前会话，账号仍留在列表里） ----------
const ACCOUNTS_FILE = path.join(DATA_DIR, 'accounts.json');
const RECENT_LIMIT = 8;

function readRecentAccounts() {
  try {
    const j = JSON.parse(fs.readFileSync(ACCOUNTS_FILE, 'utf8'));
    return Array.isArray(j.accounts) ? j.accounts : [];
  } catch { return []; }
}
function writeRecentAccounts(list) {
  try {
    fs.writeFileSync(ACCOUNTS_FILE, JSON.stringify({ accounts: list }, null, 2));
  } catch (err) {
    logger.error('accounts_write_failed', { error: err.message });
  }
}
/** 记住账号（不改变当前登录态）；touch=false 用于启动迁移，不刷新时间 */
function rememberAccount(acc, touch = true) {
  if (!acc || !acc.uid || !acc.token) return;
  const list = readRecentAccounts();
  const idx = list.findIndex(a => String(a.uid) === String(acc.uid));
  const base = {
    uid: String(acc.uid),
    username: acc.username || '',
    token: acc.token,
    device: acc.device || '',
    ua: acc.ua || '',
    deviceModel: acc.deviceModel || '',
  };
  if (idx >= 0) {
    const prev = list[idx] || {};
    const same = ['username', 'token', 'device', 'ua', 'deviceModel']
      .every(k => String(prev[k] || '') === String(base[k] || ''));
    if (!touch && same) return;
    list[idx] = { ...prev, ...base, lastUsedAt: touch ? Date.now() : (prev.lastUsedAt || Date.now()) };
  } else {
    list.unshift({ ...base, lastUsedAt: Date.now() });
  }
  list.sort((a, b) => (b.lastUsedAt || 0) - (a.lastUsedAt || 0));
  writeRecentAccounts(list.slice(0, RECENT_LIMIT));
}

// 启动迁移：把旧的单账号配置补进最近登录
try {
  const active = readAccount();
  if (active?.uid && active?.token) rememberAccount(active, false);
} catch { /* ignore */ }

app.get('/account', (req, res) => {
  const a = readAccount();
  if (!a || !a.uid || !a.token) return res.json({ configured: false, deviceModel: a?.deviceModel || '' });
  // token 只回传尾号用于展示，不回传全文
  res.json({
    configured: true,
    uid: a.uid,
    username: a.username,
    tokenTail: a.token.slice(-4),
    deviceModel: a.deviceModel || '',
  });
});

app.post('/account', (req, res) => {
  const { uid, username, token, device, ua, deviceModel } = req.body || {};
  // 留空的字段沿用已保存的值（方便只补充设备信息而无需重输 token）
  const old = readAccount() || {};
  const val = (v, o) => String(v || '').trim() || String(o || '').trim();
  const nextToken = val(token, old.token).replace(/\s+/g, '');
  // token 变了说明换了账号或重新登录：旧设备串与 token 绑定，必须丢弃重新生成
  const tokenChanged = nextToken !== String(old.token || '');
  const merged = {
    uid: val(uid, old.uid).replace(/[^0-9]/g, ''),
    username: (() => {
      let un = val(username, old.username);
      if (/%[0-9A-Fa-f]{2}/.test(un)) { try { un = decodeURIComponent(un); } catch { /* 保持原样 */ } }
      return un;
    })(),
    token: nextToken,
    device: tokenChanged ? String(device || '').trim() : val(device, old.device),
    ua: tokenChanged ? String(ua || '').trim() : val(ua, old.ua),
    deviceModel: val(deviceModel, old.deviceModel),
  };
  if (!merged.uid || !merged.token) {
    return res.status(400).json({ error: 'uid 和 token 不能为空' });
  }
  writeAccount(merged);
  rememberAccount(merged);
  res.json({ ok: true });
});

/** 最近登录列表（不含 token，只用于切换账号） */
app.get('/accounts', (req, res) => {
  const active = readAccount();
  const accounts = readRecentAccounts().map(a => ({
    uid: a.uid,
    username: a.username || '',
    deviceModel: a.deviceModel || '',
    lastUsedAt: a.lastUsedAt || 0,
  }));
  res.json({ activeUid: active?.uid || '', accounts });
});

/** 切换到最近登录里的某个账号（写入当前账号配置，不重新登录） */
app.post('/accounts/activate', (req, res) => {
  const uid = String(req.body?.uid || '').trim();
  if (!uid) return res.status(400).json({ error: '缺少 uid' });
  const entry = readRecentAccounts().find(a => String(a.uid) === uid);
  if (!entry || !entry.token) return res.status(404).json({ error: '账号不存在或凭证已失效' });
  const acc = {
    uid: entry.uid,
    username: entry.username || '',
    token: entry.token,
    device: entry.device || '',
    ua: entry.ua || '',
    deviceModel: entry.deviceModel || '',
  };
  writeAccount(acc);
  rememberAccount(acc);
  res.json({ ok: true, username: acc.username });
});

/** 退出登录：只移除当前会话，账号仍保留在最近登录列表 */
app.post('/logout', (req, res) => {
  const active = readAccount();
  try { fs.unlinkSync(ACCOUNT_FILE); } catch { /* 未登录也算成功 */ }
  accountCache = { mtime: -1, data: null };
  res.json({ ok: true });
});

/** 删除当前账号：同时从最近登录列表移除 */
app.delete('/account', (req, res) => {
  const active = readAccount();
  try { fs.unlinkSync(ACCOUNT_FILE); } catch { /* 文件不存在也算成功 */ }
  accountCache = { mtime: -1, data: null };
  if (active?.uid) {
    writeRecentAccounts(readRecentAccounts().filter(a => String(a.uid) !== String(active.uid)));
  }
  res.json({ ok: true });
});

// ---------- 本地关注（未登录时使用，登录后前端改走账号接口） ----------
const FOLLOWS_FILE = path.join(DATA_DIR, 'follows.json');

function readFollows() {
  try {
    const j = JSON.parse(fs.readFileSync(FOLLOWS_FILE, 'utf8'));
    return {
      topics: Array.isArray(j.topics) ? j.topics : [],
      apks: Array.isArray(j.apks) ? j.apks : [],
    };
  } catch {
    return { topics: [], apks: [] };
  }
}
function writeFollows(data) {
  fs.writeFileSync(FOLLOWS_FILE, JSON.stringify(data, null, 2));
}
function cleanLocalTopic(t) {
  const title = String(t?.title || '').trim();
  if (!title) return null;
  return {
    title,
    description: String(t?.description || '').trim(),
    logo: String(t?.logo || '').trim(),
    follownum: t?.follownum,
    commentnum: t?.commentnum,
    hot_num: t?.hot_num,
  };
}
function cleanLocalApk(a) {
  const id = String(a?.id || '').trim();
  const apkname = String(a?.apkname || a?.apkname2 || '').trim();
  if (!id && !apkname) return null;
  return {
    id,
    apkname,
    title: String(a?.title || '').trim(),
    logo: String(a?.logo || '').trim(),
    apkversionname: String(a?.apkversionname || '').trim(),
    apksize: String(a?.apksize || '').trim(),
    downCount: a?.downCount,
    commentnum: a?.commentnum,
  };
}

app.get('/follows/topics', (req, res) => {
  res.json({ data: readFollows().topics });
});

app.post('/follows/topic', (req, res) => {
  const title = String(req.body?.title || '').trim();
  if (!title) return res.status(400).json({ error: '缺少话题名' });
  const follow = !!req.body?.follow;
  const data = readFollows();
  if (follow) {
    const topic = cleanLocalTopic({ ...(req.body.topic || {}), title });
    data.topics = topic ? [topic, ...data.topics.filter(x => x.title !== title)] : data.topics;
  } else {
    data.topics = data.topics.filter(x => x.title !== title);
  }
  try {
    writeFollows(data);
  } catch (err) {
    logger.error('local_follow_write_failed', { error: err.message });
    return res.status(500).json({ error: '本地关注保存失败' });
  }
  res.json({ data: data.topics, following: follow });
});

app.get('/follows/apks', (req, res) => {
  res.json({ data: readFollows().apks });
});

app.post('/follows/apk', (req, res) => {
  const app = cleanLocalApk(req.body?.app);
  if (!app) return res.status(400).json({ error: '缺少应用信息' });
  const follow = !!req.body?.follow;
  const data = readFollows();
  const same = x => (app.id && String(x.id) === app.id) || (app.apkname && String(x.apkname) === app.apkname);
  data.apks = follow
    ? [app, ...data.apks.filter(x => !same(x))]
    : data.apks.filter(x => !same(x));
  try {
    writeFollows(data);
  } catch (err) {
    logger.error('local_follow_write_failed', { error: err.message });
    return res.status(500).json({ error: '本地关注保存失败' });
  }
  res.json({ data: data.apks, following: follow });
});

// ---------- 网易易盾代理 ----------
// 易盾 captchaId 绑定了 account.coolapk.com 域名（校验 Referer），
// 本地页面无法直连，由后端代理并补上官方域名的 Referer/Origin
const YIDUN_HOSTS = ['c.dun.163.com', 'c.dun.163yun.com', 'necaptcha.nos.netease.com', 'necaptcha.nosdn.127.net'];
app.use('/yd', async (req, res) => {
  // 挂载在 /yd 下，req.url 已去掉前缀：/c.dun.163.com/api/v2/getconf
  const m = String(req.url).match(/^\/([a-z0-9.-]+)(\/.*)$/i);
  if (!m || !YIDUN_HOSTS.includes(m[1])) return res.status(403).end();
  // 易盾 captchaId 绑定官方域名：请求里的本地 referer 参数会被校验拒绝，
  // 重写为官方登录页 URL（这正是滑块怎么滑都 result:false 的原因）
  let upstreamUrl = m[2].replace(/([?&]referer=)https?%3A%2F%2F[^&]*/i,
    '$1https%3A%2F%2Faccount.coolapk.com%2Fauth%2FloginByCoolApk');
  const target = `https://${m[1]}${upstreamUrl}`;
  try {
    const upstream = await fetch(target, {
      method: req.method,
      headers: {
        'User-Agent': DEFAULT_UA,
        'Referer': 'https://account.coolapk.com/auth/loginByCoolApk',
        'Origin': 'https://account.coolapk.com',
        'Content-Type': req.headers['content-type'] || 'application/x-www-form-urlencoded',
        'X-Requested-With': 'XMLHttpRequest',
      },
      body: ['GET', 'HEAD'].includes(req.method) ? undefined : req,
      duplex: 'half',
    });
    res.status(upstream.status);
    res.setHeader('content-type', upstream.headers.get('content-type') || 'application/json');
    const buf = Buffer.from(await upstream.arrayBuffer());
    res.send(buf);
  } catch (err) {
    logger.error('yd_proxy_failed', { error: err.message });
    res.status(502).json({ error: err.message });
  }
});

// 查询是否已有可用的接口风控凭证
app.get('/captcha/status', (req, res) => {
  res.json({
    has: captchaFresh(),
    captchaId: captchaFresh() ? (captchaProof.captchaId || '').slice(0, 8) : '',
    capturedAt: captchaProof?.capturedAt || 0,
  });
});

// 前端 JS 报错上报（用于分析“点击无反应”等问题）
app.post('/client-log', (req, res) => {
  logger.error('client_error', req.body || {});
  res.json({ ok: true });
});

// 前端完成人机验证后上报 validate：拼成酷安要求的凭证并持久化
app.post('/captcha/validate', (req, res) => {
  const v = String(req.body?.validate || '').trim();
  const captchaId = String(req.body?.captchaId || '').trim();
  const rawField = String(req.body?.field || '').trim();
  if (!v) return res.status(400).json({ error: '缺少 validate' });
  if (!/^[a-zA-Z0-9]{16,64}$/.test(captchaId)) return res.status(400).json({ error: '缺少 captchaId' });
  // 凭证值 = NEC:<captchaId 前8位>:<validate>，整体 URL 编码（与 c001apk 一致）
  captchaProof = {
    proof: encodeURIComponent(`NEC:${captchaId.slice(0, 8)}:${v}`),
    field: /^_[a-zA-Z0-9_]{1,63}$/.test(rawField) ? rawField : '',
    captchaId,
    capturedAt: Date.now(),
  };
  try { fs.writeFileSync(CAPTCHA_FILE, JSON.stringify(captchaProof)); } catch { /* ignore */ }
  res.json({ ok: true });
});

// ---------- 官方登录页代理 ----------
// 把 account.coolapk.com 的登录页代理到本地：页面自带完整的滑块验证逻辑，
// 代理层负责 1) 补官方域名的 Referer/Origin 2) 往 HTML 注入 URL 重写补丁
//（易盾请求改走 /yd 代理）3) 登录成功时截获 Set-Cookie 里的新凭证存入 account.json
function pickCookie(setCookies, name) {
  const c = setCookies.map(x => x.split(';')[0]).find(x => x.startsWith(name + '='));
  return c || '';
}
function injectPatch(html) {
  const patch = `<script>(function(){
  var hosts=['c.dun.163.com','c.dun.163yun.com','necaptcha.nos.netease.com','necaptcha.nosdn.127.net'];
  function rw(u){try{var x=new URL(u,location.origin);if(hosts.indexOf(x.hostname)>=0){return '/yd/'+x.hostname+x.pathname+x.search;}}catch(e){}return u;}
  function report(s){try{fetch('/client-log',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({msg:s})}).catch(function(){});}catch(e){}}
  function patchWin(w){if(!w||w.__rwPatched){return;}try{w.__rwPatched=true;
    // 让被改写的函数在 toString 检测下显示为原生代码（易盾防护脚本会检查）
    var ots=w.Function.prototype.toString;
    w.Function.prototype.toString=function(){try{if(this&&this.__nativeStr){return this.__nativeStr;}}catch(e){}return ots.call(this);};
    function nat(f,name){try{f.__nativeStr='function '+name+'() { [native code] }';}catch(e){}}
    var oo=w.XMLHttpRequest.prototype.open;nat(oo,'open');
    w.XMLHttpRequest.prototype.open=function(){arguments[1]=rw(arguments[1]);return oo.apply(this,arguments);};nat(w.XMLHttpRequest.prototype.open,'open');
    var os=w.XMLHttpRequest.prototype.send;nat(os,'send');
    w.XMLHttpRequest.prototype.send=function(){var x=this;x.addEventListener('load',function(){try{var u=x.responseURL||'';if(u.indexOf('/yd/')===0&&(x.status!==200||u.indexOf('check')>=0||u.indexOf('verify')>=0)){report('yd '+x.status+' '+u.slice(0,140)+' '+String(x.responseText||'').slice(0,180));}}catch(e){}});return os.apply(this,arguments);};nat(w.XMLHttpRequest.prototype.send,'send');
    var of=w.fetch;nat(of||{},'fetch');if(of){w.fetch=function(i,n){if(typeof i==='string'){i=rw(i);}return of.call(this,i,n);};nat(w.fetch,'fetch');}
  }catch(e){}}
  patchWin(window);
  var oc=document.createElement.bind(document);
  document.createElement=function(t){var e=oc(t);var tag=String(t).toLowerCase();if(tag==='script'||tag==='iframe'){var proto=tag==='iframe'?HTMLIFrameElement.prototype:HTMLScriptElement.prototype;var d=Object.getOwnPropertyDescriptor(proto,'src');if(d&&d.set){Object.defineProperty(e,'src',{set:function(v){d.set.call(this,rw(String(v)));},get:function(){return d.get.call(this);}});}}return e;};
  try{document.createElement.__nativeStr='function createElement() { [native code] }';}catch(e){}
  var osa=Element.prototype.setAttribute;
  Element.prototype.setAttribute=function(n,v){if((this.tagName==='SCRIPT'||this.tagName==='IFRAME')&&String(n).toLowerCase()==='src'){v=rw(String(v));}return osa.call(this,n,v);};
  try{Element.prototype.setAttribute.__nativeStr='function setAttribute() { [native code] }';}catch(e){}
  // SDK 会用 document.write 动态写挑战 iframe，其内部请求也要打补丁：
  // 监听新增 iframe，加载后向其 contentWindow 注入同样的重写逻辑
  setInterval(function(){
    var fs=document.querySelectorAll('iframe');
    for(var i=0;i<fs.length;i++){try{if(!fs[i].src||fs[i].src.indexOf('/yd/')===0||fs[i].src.indexOf('about:')===0){patchWin(fs[i].contentWindow);}}catch(e){}}
  },300);
})();</script>`;
  // 登录自动驾驶：捕获凭证、监听滑块结果，直接在本页内完成提交
  const autopilot = `<script>(function(){
  if (window.__autopilot) return; window.__autopilot = true;
  var creds = { a: '', p: '', c: '' };
  function grab() {
    var a = document.querySelector('#loginInput');
    var p = document.querySelector('#passwordInput');
    var c = document.querySelector('#codeInput');
    if (a && a.value) creds.a = a.value;
    if (p && p.value) creds.p = p.value;
    if (c && c.value) creds.c = c.value;
  }
  function bind() {
    var btn = document.getElementById('button-login');
    if (!btn) return false;
    btn.addEventListener('click', grab, true);
    return true;
  }
  var bindTimer = setInterval(function () { if (bind()) clearInterval(bindTimer); }, 300);
  var t = setInterval(function () {
    try {
      grab();
      var vi = document.querySelector('.yidun_input');
      if (!(vi && vi.value && creds.a && creds.p)) return;
      clearInterval(t);
      var rh = document.body.getAttribute('data-request-hash') || '';
      var fd = new URLSearchParams();
      fd.append('submit', '1');
      fd.append('requestHash', rh);
      fd.append('login', creds.a);
      fd.append('password', creds.p);
      fd.append('code', creds.c);
      fd.append('yidunCaptcha', vi.value);
      fetch('/auth/loginByCoolApk', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: fd.toString()
      }).then(function (r) { return r.json(); }).then(function (j) {
        var tip = document.createElement('div');
        tip.style.cssText = 'position:fixed;top:10px;left:0;right:0;text-align:center;z-index:99999;padding:10px;font-size:14px;' +
          (j.ok ? 'background:#e8f7f0;color:#00875a;' : 'background:#fdeaea;color:#d03050;');
        tip.textContent = (j.status === 1) ? '登录成功，凭证已自动保存，窗口即将关闭' : ('登录失败：' + (j.message || '未知错误'));
        document.body.append(tip);
        if (j.status === 1) setTimeout(function () { try { window.top.postMessage({ type: 'coolapk-login-ok' }, '*'); } catch (e) {} }, 600);
      }).catch(function (e) {
        var tip = document.createElement('div');
        tip.style.cssText = 'position:fixed;top:10px;left:0;right:0;text-align:center;z-index:99999;padding:10px;background:#fdeaea;color:#d03050;font-size:14px';
        tip.textContent = '提交异常：' + e.message;
        document.body.append(tip);
      });
    } catch (e) { /* ignore */ }
  }, 400);
})();</script>`;
  return html.replace(/<head[^>]*>/i, (m) => m + patch + autopilot);
}

app.use('/auth', async (req, res) => {
  // app.use 挂载会剥掉 /auth 前缀，上游真实路径需要补回
  const target = `https://account.coolapk.com/auth${req.url}`;
  const isLoginPost = req.method === 'POST' && req.url.startsWith('/loginByCoolApk');
  try {
    const headers = {
      'User-Agent': DEFAULT_UA,
      'Referer': `https://account.coolapk.com/auth${req.url}`,
      'Origin': 'https://account.coolapk.com',
      'X-Requested-With': req.method === 'POST' ? 'XMLHttpRequest' : 'com.coolapk.market',
      'Accept': req.headers.accept ||
        (req.method === 'POST' ? '*/*' : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'),
      'Accept-Language': 'zh-CN,zh;q=0.9',
    };
    if (req.headers['content-type']) headers['Content-Type'] = req.headers['content-type'];
    if (req.headers.cookie) headers['Cookie'] = req.headers.cookie; // 透传浏览器侧 SESSID 等

    const upstream = await fetch(target, {
      method: req.method,
      headers,
      body: ['GET', 'HEAD'].includes(req.method) ? undefined : req,
      duplex: 'half',
      redirect: 'follow',
    });
    absorbCookies(upstream);

    // 把上游 Cookie 转存到浏览器（去掉 account.coolapk.com 的 Domain 限定）
    const sc = upstream.headers.getSetCookie?.() || [];
    if (sc.length) {
      res.setHeader('set-cookie', sc.map(c => c.replace(/;\s*domain=[^;]+/i, '')));
    }

    // 登录成功：从 Set-Cookie 截获 uid/username/token 写入配置
    if (isLoginPost) {
      const body = await upstream.text();
      const uid = pickCookie(sc, 'uid').slice(4);
      const rawUsername = pickCookie(sc, 'username').slice(9);
      const token = pickCookie(sc, 'token').slice(6);
      if (uid && token) {
        const old = readAccount() || {};
        const acc = {
          uid,
          username: decodeURIComponent(rawUsername || old.username || ''),
          token,
          device: '',   // 新 token 与本机生成的设备配套
          ua: '',
          deviceModel: old.deviceModel || '',
        };
        writeAccount(acc);
        rememberAccount(acc);
      } else {
        try {
          const j = JSON.parse(body);
          if (j.status !== 1) logger.error('login_failed', { message: j.message || '' });
        } catch { /* 非 JSON 忽略 */ }
      }
      res.status(upstream.status).type(upstream.headers.get('content-type') || 'application/json');
      res.send(body);
      return;
    }

    const type = upstream.headers.get('content-type') || '';
    if (type.includes('text/html')) {
      const html = await upstream.text();
      res.status(upstream.status).type('text/html; charset=utf-8').send(injectPatch(html));
    } else {
      const buf = Buffer.from(await upstream.arrayBuffer());
      res.status(upstream.status).type(type || 'application/octet-stream');
      res.send(buf);
    }
  } catch (err) {
    logger.error('auth_proxy_failed', { url: req.url, error: err.message });
    res.status(502).json({ error: '官方登录页加载失败：' + err.message });
  }
});

// ---------- API 代理（/api -> api.coolapk.com, /api2 -> api2.coolapk.com） ----------
function makeProxy(host) {
  return async (req, res) => {
    let target = host + req.url;
    try {
      const acc = readAccount();
      // 评论列表是公开读接口：优先用游客设备身份且不带登录 Cookie，
      // 避免登录设备被风控要求验证码（与 coolapk-desktop 的做法一致）。
      const isPublicRead = req.method === 'GET' &&
        /^\/v6\/feed\/(?:replyList|hotReplyList)(?:\?|$)/.test(req.url);
      const guest = isPublicRead ? await ensureGuestIdentity() : null;
      const headers = guest ? guestHeaders(guest) : clientHeaders(acc);
      const cookieParts = [];
      if (!guest) {
        // 登录 Cookie（uid/username/token）优先，其后是会话 Cookie 罐
        if (acc?.uid && acc?.token) {
          cookieParts.push(
            `uid=${acc.uid}`,
            `username=${encodeURIComponent(acc.username || '')}`,
            `token=${acc.token}`
          );
        }
        const jar = cookieHeader();
        if (jar) cookieParts.push(jar);
      }
      // 接口风控凭证（空 field 走 Cookie，非空 field 作为查询参数回传）：
      // 游客请求同样带上，作为 DUID 失效时的兜底
      const sentProof = captchaFresh() ? captchaProof.proof : '';
      if (sentProof) {
        if (captchaProof.field) {
          target += (target.includes('?') ? '&' : '?') + captchaProof.field + '=' + sentProof;
        } else {
          cookieParts.push('validate=' + sentProof);
        }
      }
      if (cookieParts.length) headers['Cookie'] = cookieParts.join('; ');
      // 支持 POST（关注话题 /v6/feed/followTag 等写操作），参数走 query，通常无请求体
      const isBodyless = ['GET', 'HEAD'].includes(req.method);
      const hasBody = !isBodyless && req.headers['content-length'] && req.headers['content-length'] !== '0';
      if (hasBody && req.headers['content-type']) headers['Content-Type'] = req.headers['content-type'];
      const upstream = await fetch(target, {
        method: req.method,
        headers,
        body: hasBody ? req : undefined,
        duplex: 'half',
        redirect: 'follow',
        signal: AbortSignal.timeout(15000), // 上游卡死时不要一直挂住前端
      });
      if (!guest) absorbCookies(upstream); // 游客响应不污染账号会话 Cookie 罐
      const body = await upstream.text();
      // 只记录上游 5xx；鉴权/风控/业务错误由页面提示，不写日志
      if (!upstream.ok && upstream.status >= 500) {
        logger.error('api_http_error', {
          url: target.replace(/^https?:\/\/[^/]+/, '').slice(0, 200),
          status: upstream.status,
        });
      } else if (upstream.ok) {
        try {
          const j = JSON.parse(body);
          // 易盾 validate 实际有效期由服务端决定，一旦被拒立刻作废
          if ((j.messageStatus ?? j.status) === 'err_request_captcha_v2' && sentProof) {
            captchaProof = null;
            try { fs.unlinkSync(CAPTCHA_FILE); } catch { /* 已不存在 */ }
            logger.warn('captcha_proof_rejected', {});
          }
        } catch { /* 非 JSON 响应不记录 */ }
      }
      res.status(upstream.status).type(upstream.headers.get('content-type') || 'application/json');
      res.send(body);
    } catch (err) {
      const timedOut = err.name === 'TimeoutError' || err.name === 'AbortError';
      console.error('[api]', target, err.message);
      logger.error('api_request_failed', {
        url: target.replace(/^https?:\/\/[^/]+/, '').slice(0, 200),
        error: err.message,
        timeout: timedOut,
      });
      res.status(timedOut ? 504 : 502).json({
        error: timedOut ? '上游请求超时，请稍后重试' : '上游请求失败',
        detail: err.message,
      });
    }
  };
}
app.use('/api2', makeProxy(API2_HOST));
app.use('/api', makeProxy(API_HOST));

// ---------- 图床代理（防盗链：带 Referer 回源） ----------
/** 只允许公网目标，避免图床代理被当成访问本机/内网的跳板 */
function isPrivateHost(hostname) {
  const h = hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (h === 'localhost' || h === '0.0.0.0' || h === '::1') return true;
  if (/^127\./.test(h) || /^10\./.test(h) || /^192\.168\./.test(h) || /^169\.254\./.test(h)) return true;
  const m = h.match(/^172\.(\d+)\./);
  if (m && Number(m[1]) >= 16 && Number(m[1]) <= 31) return true;
  if (/^f[cd][0-9a-f]{2}:/i.test(h)) return true; // fc00::/7
  return false;
}

app.get('/image', async (req, res) => {
  const raw = String(req.query.url || '');
  let target;
  try { target = new URL(raw); } catch { return res.status(400).end(); }
  if (!/^https?:$/.test(target.protocol) || isPrivateHost(target.hostname)) {
    return res.status(400).end();
  }
  try {
    const upstream = await fetch(target, {
      headers: {
        'User-Agent':
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36',
        Referer: 'https://www.coolapk.com/',
        Accept: 'image/*,*/*;q=0.8',
      },
      signal: AbortSignal.timeout(15000),
    });
    if (!upstream.ok) return res.status(upstream.status).end();
    res.setHeader('content-type', upstream.headers.get('content-type') || 'image/jpeg');
    res.setHeader('cache-control', 'public, max-age=86400');
    const buf = Buffer.from(await upstream.arrayBuffer());
    res.send(buf);
  } catch (err) {
    const timedOut = err.name === 'TimeoutError' || err.name === 'AbortError';
    console.error('[image]', raw, err.message);
    res.status(timedOut ? 504 : 502).end();
  }
});

const server = app.listen(PORT, () => {
  logger.info('server_started', { port: PORT });
  console.log(`Server running: http://localhost:${PORT}`);
});
server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    logger.error('server_start_failed', { error: `端口 ${PORT} 被占用` });
    console.error(`[ERROR] Port ${PORT} is already in use.`);
    console.error('Close the previous Coolapk Web window (or kill node.exe) and try again.');
  } else {
    logger.error('server_start_failed', { error: err.message });
    console.error('[ERROR] Failed to start:', err.message);
  }
  process.exit(1);
});

// 后台预热游客 DUID，减少第一次打开评论的等待；失败不影响启动
setTimeout(() => { ensureGuestIdentity().catch(() => {}); }, 1500);

// 未捕获异常也留痕，便于事后分析
process.on('uncaughtException', (err) => {
  logger.error('uncaught_exception', { error: err.stack || err.message });
});
process.on('unhandledRejection', (err) => {
  logger.error('unhandled_rejection', { error: String(err && err.stack || err).slice(0, 500) });
});
