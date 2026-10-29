'use strict';
/**
 * 数盟 DUID 生成（游客设备标识）。
 *
 * 协议参考 coolapk-desktop 的 shuzilm.rs（MIT）：
 * 只提交随机生成的合成设备数据，不读取本机硬件信息，也不携带酷安账号/Cookie。
 * DUID 仅用于公开只读接口的游客设备身份；接口来自第三方，可能随时失效。
 */
const crypto = require('crypto');
const zlib = require('zlib');

const ENDPOINT =
  'https://auni.telecome.cn/a/mdna/report?v=8.7&t=m&p=F9BD0FBDACFE80FCF34370FBCFEE1A98' +
  '&r=5bb7efdd4c794f0e9563317b7802b995&n=0&l=2&h=0';
const KEY = Buffer.from('xp7j@&!v5]2k#+3z{n9$q^r%[8f1*d4e:c>0l?m/6)yb-=w}');
const MAX_RESPONSE = 64 * 1024;
const DUID_RE = /^DU[0-9A-Za-z_-]{8,127}$/;

function xor(buf) {
  return Buffer.from(buf.map((b, i) => b ^ KEY[i % KEY.length]));
}

function validDuid(id) {
  return typeof id === 'string' && DUID_RE.test(id);
}

function buildPayload() {
  const random = crypto.randomBytes(96);
  const now = process.hrtime.bigint();
  const sec = Math.floor(Date.now() / 1000);
  const nano = Number(now % 1000000000n);
  return {
    DUv: 'com.coolapk.market',
    '3mS': 'v9.0.1',
    AAA: 'v1.0',
    '75c': '11e7b222083a4b732b4b14811f6fc05995a01415eb',
    sfOo: random.subarray(0, 4).toString('hex').toUpperCase().slice(0, 7),
    foO: random.subarray(4, 12).toString('hex').slice(0, 15),
    '2cO': `${sec}.${String(nano).padStart(9, '0')}`,
    w91: random.subarray(12, 28).toString('hex').toUpperCase(),
    gEd: random.subarray(28, 44).toString('hex'),
    '6yY': random.subarray(44, 76).toString('hex'),
  };
}

function encodeRequest(payload) {
  const raw = JSON.stringify(payload).replace(/\//g, '\\/');
  return xor(zlib.deflateSync(Buffer.from(raw, 'utf8'), { level: 6 }));
}

function decodeResponse(raw) {
  if (raw.length > MAX_RESPONSE) throw new Error('数盟响应过大');
  const decoded = xor(raw);
  let jsonBytes;
  try {
    jsonBytes = zlib.inflateSync(decoded, { maxOutputLength: MAX_RESPONSE });
  } catch {
    jsonBytes = decoded;
  }
  if (jsonBytes.length > MAX_RESPONSE) throw new Error('数盟响应过大');
  const json = JSON.parse(jsonBytes.toString('utf8'));
  const id = json && json.n_a;
  if (!validDuid(id)) throw new Error('数盟未返回有效设备 ID');
  return id;
}

/** 申请一个新的游客 DUID（DU 开头），失败时抛出可读错误 */
async function generateDuid() {
  const res = await fetch(ENDPOINT, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 8.1; TK Watch Build/OPM2.171019.012)',
      'Accept-Encoding': 'identity',
    },
    body: encodeRequest(buildPayload()),
    signal: AbortSignal.timeout(12000),
  });
  if (!res.ok) throw new Error('数盟服务 HTTP ' + res.status);
  const buf = Buffer.from(await res.arrayBuffer());
  return decodeResponse(buf);
}

module.exports = { generateDuid, validDuid };
