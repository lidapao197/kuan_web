'use strict';
/**
 * 酷安 X-App-Token 生成（v2 / v3）
 * v3 算法移植自 c001apk (MIT) apps/flutter/lib/utils/token_util.dart，
 * 协议查找数据来自 coolapk-desktop auth.rs。
 */
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const AUTH_BLOB = Buffer.from(
  JSON.parse(fs.readFileSync(path.join(__dirname, 'token_v3_data.json'), 'utf8')),
  'base64'
);

const APP_ID = 'com.coolapk.market';
const APP_LABEL = 'token://com.coolapk.market/dcf01e569c1e3db93a3d0fcf191a622c';
const ALPHABET =
  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const SALT_RE = /^[./A-Za-z0-9]{22}$/;

function md5(input) {
  return crypto.createHash('md5').update(input, 'utf8').digest('hex');
}

function base64NoPad(input) {
  return Buffer.from(input, 'utf8').toString('base64').replace(/=+$/, '');
}

/**
 * v3 签名：c001apk / coolapk-desktop 当前使用的算法。
 * @param {string} deviceCode X-App-Device 值
 * @param {number} [timestamp] Unix 秒
 * @param {number} [appCode] 版本代号
 */
function getTokenV3(deviceCode, timestamp, appCode = 2604201) {
  const bcrypt = require('bcryptjs');
  const now = timestamp ?? Math.floor(Date.now() / 1000);
  for (let offset = 0; offset <= 15; offset++) {
    const time = now + offset;
    const index = ((time + appCode) % 100) * 4 + 0x80;
    const segment = Buffer.from(AUTH_BLOB.subarray(index, index + 0x80).toString('latin1'), 'base64').toString('utf8');
    const plain = `${APP_ID}&${segment}&${md5(deviceCode)}&${time}&${appCode}`;
    const password = md5(Buffer.from(plain, 'utf8').toString('base64'));
    const source = base64NoPad(`${time.toString(16)}/${md5(plain)}`);
    const salt =
      source.substring(0, 21) +
      ALPHABET[(ALPHABET.indexOf(source[21]) - 5 + 64) % 64];
    if (!SALT_RE.test(salt)) continue;
    let hash = bcrypt.hashSync(password, `$2a$04$${salt}`);
    hash = '$2y' + hash.slice(3);
    return 'v3' + base64NoPad(hash);
  }
  throw new Error('无法生成请求签名，请检查系统时间');
}

/** v2 签名：旧版回退方案 */
function getTokenV2(deviceCode) {
  const bcrypt = require('bcryptjs');
  const timeStamp = String(Math.floor(Date.now() / 1000));
  const base64TimeStamp = base64NoPad(timeStamp);
  const md5TimeStamp = md5(timeStamp);
  const md5DeviceCode = md5(deviceCode);
  const token = `${APP_LABEL}?${md5TimeStamp}$${md5DeviceCode}&${APP_ID}`;
  const md5Base64Token = md5(Buffer.from(token, 'utf8').toString('base64'));
  const md5Token = md5(token);
  const bcryptSalt = `$2a$10$${base64TimeStamp}/${md5Token}`.substring(0, 31) + 'u';
  let hash = bcrypt.hashSync(md5Base64Token, bcryptSalt);
  hash = '$2y' + hash.slice(3);
  return 'v2' + Buffer.from(hash, 'utf8').toString('base64').replace(/=+$/, '');
}

/**
 * X-App-Device：设备信息字符串 Base64 后反转、去 = / 换行。
 * @param {string} deviceInfo 用分号拼接的设备信息
 */
function encodeDevice(deviceInfo) {
  return Buffer.from(deviceInfo, 'utf8')
    .toString('base64')
    .split('')
    .reverse()
    .join('')
    .replace(/[\r\n=]/g, '');
}

module.exports = { getTokenV3, getTokenV2, encodeDevice, md5, base64NoPad };
