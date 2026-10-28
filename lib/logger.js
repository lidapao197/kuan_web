'use strict';
/**
 * 轻量日志：按日期写入 log/YYYY-MM-DD.log（本地时区），追加模式。
 * 失败静默忽略，绝不影响主服务。
 */
const fs = require('fs');
const path = require('path');

const LOG_DIR = path.join(__dirname, '..', 'log');
const pad = (n) => String(n).padStart(2, '0');

function log(level, event, detail) {
  try {
    if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });
    const d = new Date();
    const date = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
    const time = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    let tail = '';
    if (detail !== undefined && detail !== null && detail !== '') {
      tail = typeof detail === 'string' ? ` ${detail}` : ` ${JSON.stringify(detail)}`;
    }
    fs.appendFileSync(path.join(LOG_DIR, `${date}.log`), `[${date} ${time}] [${level}] ${event}${tail}\n`);
  } catch { /* ignore */ }
}

module.exports = {
  info: (event, detail) => log('INFO', event, detail),
  warn: (event, detail) => log('WARN', event, detail),
  error: (event, detail) => log('ERROR', event, detail),
};
