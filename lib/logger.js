'use strict';
/**
 * 最简诊断日志：只记录错误和少量关键事件，按日期写入 log/YYYY-MM-DD.log。
 * - 页面负责给用户友好提示，这里保留排查用的上下文；
 * - 只保留最近 3 天，单条 detail 截断，避免日志无限增长；
 * - 写失败静默忽略，绝不影响主服务。
 */
const fs = require('fs');
const path = require('path');

const LOG_DIR = path.join(__dirname, '..', 'log');
const KEEP_DAYS = 3;
const MAX_DETAIL = 400;
const pad = (n) => String(n).padStart(2, '0');

/** 启动时清理超过保留期的日志（按文件名日期，不依赖文件 mtime） */
function pruneOldLogs() {
  try {
    const cutoff = Date.now() - KEEP_DAYS * 86400 * 1000;
    for (const name of fs.readdirSync(LOG_DIR)) {
      const m = /^(\d{4})-(\d{2})-(\d{2})\.log$/.exec(name);
      if (!m) continue;
      const day = new Date(Number(m[1]), Number(m[2]) - 1, Number(m[3])).getTime();
      if (day < cutoff) {
        try { fs.unlinkSync(path.join(LOG_DIR, name)); } catch { /* ignore */ }
      }
    }
  } catch { /* 目录不存在等 */ }
}

function log(level, event, detail) {
  try {
    if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });
    const d = new Date();
    const date = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
    const time = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
    let tail = '';
    if (detail !== undefined && detail !== null && detail !== '') {
      tail = typeof detail === 'string' ? detail : JSON.stringify(detail);
      tail = tail.replace(/\s+/g, ' ');
      if (tail.length > MAX_DETAIL) tail = tail.slice(0, MAX_DETAIL) + '…';
      tail = ' ' + tail;
    }
    fs.appendFileSync(path.join(LOG_DIR, `${date}.log`), `[${date} ${time}] [${level}] ${event}${tail}\n`);
  } catch { /* ignore */ }
}

pruneOldLogs();

module.exports = {
  info: (event, detail) => log('INFO', event, detail),
  warn: (event, detail) => log('WARN', event, detail),
  error: (event, detail) => log('ERROR', event, detail),
};
