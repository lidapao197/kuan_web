'use strict';

// 前端报错上报到后端日志，便于排查“点击无反应”这类问题
window.addEventListener('error', (e) => {
  fetch('/client-log', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ msg: String(e.message).slice(0, 300), src: (e.filename || '').split('/').pop() + ':' + e.lineno }),
  }).catch(() => {});
});

/* ---------- 人机验证：解除评论等接口的验证码拦截 ---------- */
const YIDUN_HOSTS = ['c.dun.163.com', 'c.dun.163yun.com', 'necaptcha.nos.netease.com', 'necaptcha.nosdn.127.net'];
function rewriteYidunUrl(u) {
  try {
    const x = new URL(u, location.origin);
    if (YIDUN_HOSTS.includes(x.hostname)) return '/yd/' + x.hostname + x.pathname + x.search;
  } catch { /* 保持原样 */ }
  return u;
}
function patchForYidun() {
  if (window.__yidunPatched) return;
  window.__yidunPatched = true;
  const oo = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (...a) { a[1] = rewriteYidunUrl(a[1]); return oo.apply(this, a); };
  const of = window.fetch;
  window.fetch = function (input, init) {
    if (typeof input === 'string') input = rewriteYidunUrl(input);
    else if (input instanceof Request) input = new Request(rewriteYidunUrl(input.url), input);
    return of.call(this, input, init);
  };
  const oc = document.createElement.bind(document);
  document.createElement = function (tag, ...rest) {
    const el = oc(tag, ...rest);
    const tagL = String(tag).toLowerCase();
    if (tagL === 'script' || tagL === 'iframe') {
      const proto = tagL === 'iframe' ? HTMLIFrameElement.prototype : HTMLScriptElement.prototype;
      const d = Object.getOwnPropertyDescriptor(proto, 'src');
      if (d && d.set) Object.defineProperty(el, 'src', { set(v) { d.set.call(this, rewriteYidunUrl(String(v))); }, get() { return d.get.call(this); } });
    }
    return el;
  };
  const osa = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (n, v) {
    if ((this.tagName === 'SCRIPT' || this.tagName === 'IFRAME') && String(n).toLowerCase() === 'src') v = rewriteYidunUrl(String(v));
    return osa.call(this, n, v);
  };
  // SDK 动态写的挑战 iframe 内部也要打补丁
  setInterval(() => {
    document.querySelectorAll('iframe').forEach(f => {
      try {
        if (!f.src || f.src.indexOf('/yd/') === 0 || f.src.indexOf('about:') === 0) {
          const w = f.contentWindow;
          if (w && !w.__rwPatched) {
            w.__rwPatched = true;
            const oo = w.XMLHttpRequest.prototype.open;
            w.XMLHttpRequest.prototype.open = function (...a) { a[1] = rewriteYidunUrl(a[1]); return oo.apply(this, a); };
            const of2 = w.fetch;
            if (of2) w.fetch = function (i) { if (typeof i === 'string') i = rewriteYidunUrl(i); return of2.call(this, i); };
          }
        }
      } catch { /* 跨域忽略 */ }
    });
  }, 300);
}
function loadScript(src) {
  return new Promise((ok, fail) => {
    const s = document.createElement('script');
    s.src = src; s.onload = ok; s.onerror = () => fail(new Error('脚本加载失败'));
    document.head.append(s);
  });
}
// 接口风控验证码的兜底 captchaId（服务端没下发时用）
const DEFAULT_CAPTCHA_ID = '5fc4c10eccd64d178982bc560da43a91';

/**
 * 从 err_request_captcha_v2 响应里解析验证码挑战。
 * 协议来源：c001apk captcha_challenge.dart（MIT）——captchaId 必须用接口下发的那个，
 * 用登录页的 captchaId 过的滑块对接口无效。
 */
function parseCaptchaChallenge(json) {
  if (!json || String(json.messageStatus) !== 'err_request_captcha_v2') return null;
  let extra = json.messageExtra ?? json.extra;
  if (typeof extra === 'string') {
    try { extra = JSON.parse(extra); } catch { extra = null; }
  }
  if (!extra || typeof extra !== 'object') extra = json;
  const id = String(extra.captchaId || '');
  const field = typeof extra.captchaField === 'string' ? extra.captchaField.trim() : '';
  return {
    captchaId: /^[a-zA-Z0-9]{16,64}$/.test(id) ? id : DEFAULT_CAPTCHA_ID,
    // 空 field = validate 走 Cookie 协议；非空则作为该名字的查询参数回传
    field: /^_[a-zA-Z0-9_]{1,63}$/.test(field) ? field : '',
  };
}

let sdkPromise = null;
function ensureCaptchaSdk() {
  if (!sdkPromise) {
    sdkPromise = (async () => {
      patchForYidun();
      try { await loadScript('https://static.coolapk.com/yidun/YiDunProtector/YiDunProtector-Web-2.1.7.js'); } catch { /* 失败不阻塞 */ }
      await loadScript('https://cstaticdun.126.net/load.min.js');
      if (!window.initNECaptcha) throw new Error('人机验证组件加载失败');
    })().catch(e => { sdkPromise = null; throw e; });
  }
  return sdkPromise;
}

// 一个 captchaId 对应一个实例：接口风控的 captchaId 与登录页不同，不能复用
const captchaCache = new Map();
async function ensureCaptcha(captchaId) {
  const hit = captchaCache.get(captchaId);
  if (hit) return hit.promise.then(() => hit.instance);
  const entry = { instance: null, promise: null };
  entry.promise = (async () => {
    await ensureCaptchaSdk();
    let box = document.getElementById('global-captcha');
    if (!box) { box = document.createElement('div'); box.id = 'global-captcha'; document.body.append(box); }
    await new Promise((ok, fail) => {
      window.initNECaptcha({
        element: '#global-captcha',
        captchaId,
        protocol: 'https',
        lang: 'zh-CN',
        width: '320px', mode: 'popup', apiVersion: 2,
        popupStyles: { position: 'fixed', top: '20%', left: '50%', transform: 'translateX(-50%)', zIndex: 300 },
        onVerify: (err, data) => {
          if (!err && data && data.validate) {
            const w = window.__validateWaiter;
            window.__validateWaiter = null;
            if (w) w(data.validate);
          }
        },
      }, (i) => { entry.instance = i; ok(); }, fail);
    });
  })().catch(e => { captchaCache.delete(captchaId); throw e; });
  captchaCache.set(captchaId, entry);
  return entry.promise.then(() => entry.instance);
}

/** 弹出滑块，成功后把 validate 连同 captchaId 上报后端并返回 */
async function solveCaptcha(challenge) {
  const instance = await ensureCaptcha(challenge.captchaId);
  const validate = await new Promise((resolve, reject) => {
    window.__validateWaiter = resolve;
    try { instance.verify(); } catch (e) { window.__validateWaiter = null; reject(e); }
  });
  const res = await fetch('/captcha/validate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ validate, captchaId: challenge.captchaId, field: challenge.field }),
  });
  if (!res.ok) throw new Error('凭证上报失败');
  return validate;
}
window.addEventListener('unhandledrejection', (e) => {
  fetch('/client-log', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ msg: 'rejection: ' + String(e.reason).slice(0, 300) }),
  }).catch(() => {});
});

/* ---------- 工具 ---------- */

const $ = (sel) => document.querySelector(sel);

function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function proxyImg(url) {
  if (!url) return '';
  return '/image?url=' + encodeURIComponent(url);
}

/** 酷安缩略图是在原图地址后加 .s.jpg，去掉即得原图 */
function originalImg(url) {
  return url ? url.replace(/\.s\.jpg(?=\?|$)/, '') : url;
}

/* ---------- 图片灯箱（原界面内预览，不跳转） ---------- */

let lightboxUrls = [];
let lightboxIndex = 0;
function openLightbox(urls, index = 0) {
  lightboxUrls = Array.isArray(urls) ? urls : [urls];
  lightboxIndex = Math.max(0, Math.min(index, lightboxUrls.length - 1));
  $('#lightbox').hidden = false;
  showLightboxAt(lightboxIndex);
}
function showLightboxAt(i) {
  lightboxIndex = (i + lightboxUrls.length) % lightboxUrls.length;
  $('#lightbox-img').src = lightboxUrls[lightboxIndex];
  const multi = lightboxUrls.length > 1;
  $('#lightbox-prev').hidden = !multi;
  $('#lightbox-next').hidden = !multi;
  $('#lightbox-counter').hidden = !multi;
  $('#lightbox-counter').textContent = (lightboxIndex + 1) + ' / ' + lightboxUrls.length;
}
function lightboxNav(dir) {
  if (lightboxUrls.length < 2) return;
  showLightboxAt(lightboxIndex + dir);
}
function closeLightbox() {
  $('#lightbox').hidden = true;
  $('#lightbox-img').src = '';
  lightboxUrls = [];
}

function relTime(ts) {
  const t = Number(ts) * 1000;
  if (!t) return '';
  const diff = (Date.now() - t) / 1000;
  if (diff < 60) return '刚刚';
  if (diff < 3600) return Math.floor(diff / 60) + '分钟前';
  if (diff < 86400) return Math.floor(diff / 3600) + '小时前';
  const d = new Date(t);
  const sameYear = d.getFullYear() === new Date().getFullYear();
  return sameYear
    ? `${d.getMonth() + 1}月${d.getDate()}日`
    : `${d.getFullYear()}年${d.getMonth() + 1}月${d.getDate()}日`;
}

/* ---------- 酷安表情 ---------- */

// 方括号表情名 -> 本地图片（public/emotions/c-<id>.png），未收录的保持原文
const EMOTE_DIR = '/emotions/';
const EMOTES = {
  '耶': 'ye', '流泪': 'liulei', 'nb': 'nb', '发怒': 'fanu', '白眼': 'baiyan', '喵喵': 'miaomiao',
  '难过': 'nanguo', '色': 'se', '鄙视': 'bishi', '红药丸': 'hongyaowan', '皱眉': 'zhoumei', '流汗滑稽': 'liuhanhuaji',
  '捂脸': 'wulian', '喷': 'pen', '火把': 'huoba', '绿药丸': 'lvyaowan', 'qq狗头': 'qqdoge', '狗头原谅他': 'dogeyuanliangta',
  '斗鸡眼滑稽': 'doujiyanhuaji', '无奈': 'wunai', '酷币': 'coolb', '黑线': 'heixian', '微微一笑': 'weiweiyixiao', '坏笑': 'huaixiao',
  '睡': 'shui', '再见': 'zaijian', '呲牙': 'ciya', '受虐滑稽': 'shounuehuaji', '无嘴笑': 'wuzuixiao', '玫瑰': 'meigui',
  '黑哈': 'heiha', '我最美': 'wozuimei', '托腮': 'tuosai', '亲亲': 'qinqin', '吃瓜': 'chigua', '无语': 'wuyu',
  '哈哈哈': 'hahaha', '发呆': 'fadai', '机智': 'jizhi', '害羞': 'haixiu', '吐血': 'tushe', '汗': 'han',
  '撇嘴': 'piezui', '滑稽': 'huaji', '欢呼': 'huanhu', '抠鼻': 'koubi', '二哈': 'erha', '傲慢': 'aoman',
  '呵呵': 'hehe', '强': 'qiang', '奶可醉': 'naikezui', '弱': 'ruo', '委屈': 'weiqu', 'cos滑稽': 'coshuaji',
  '疑问': 'yiwen', '可怜': 'kelian', '小哭': 'xiaoku', 'oy': 'oy', 'ok': 'ok', 'py交易': 'pyjiaoyi',
  '可爱': 'keai', '狗头': 'doge', 'doge': 'doge', '微笑': 'weixiao', '阴险': 'yinxian', '惊讶': 'jingya',
  '墨镜滑稽': 'mojinghuaji', '喷血': 'penxue', '心碎': 'xinsui', '抱拳': 'baoquan', '宽': 'kuan', '狗头小哭': 'dogexiaoku',
  '调戏': 'diaoxie', '菜刀': 'caidao', '宽绿帽': 'kuanlvmao', '绿帽': 'lvmao', '爱心': 'aixin', '噗': 'pu',
  '喝酒': 'hejiu', '酷': 'ku',
};

/** 文本节点转 DOM，把 [表情名] 换成表情图 */
function appendTextWithEmotes(parent, text) {
  const re = /\[([^\[\]\s]{1,10})\]/g;
  let last = 0;
  let m;
  while ((m = re.exec(text))) {
    const id = EMOTES[m[1].toLowerCase()];
    if (!id) continue;
    if (m.index > last) parent.append(text.slice(last, m.index));
    const img = document.createElement('img');
    img.className = 'emote';
    img.src = EMOTE_DIR + 'c-' + id + '.png';
    img.alt = m[0];
    img.title = m[0];
    img.loading = 'lazy';
    parent.append(img);
    last = m.index + m[0].length;
  }
  if (last < text.length) parent.append(text.slice(last));
}

// 图片缺失/加载失败时退回原文，避免出现破图
document.addEventListener('error', (e) => {
  const el = e.target;
  if (el instanceof HTMLImageElement && el.classList.contains('emote')) {
    el.replaceWith(document.createTextNode(el.alt || ''));
  }
}, true);

/** 白名单净化动态/评论正文：只保留 a / br / 文本，全部重建 DOM，无 XSS 面 */
function sanitizeMessage(html, hideTag) {
  if (!html) return '';
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const div = document.createElement('div');
  function walk(node) {
    if (node.nodeType === Node.TEXT_NODE) {
      appendTextWithEmotes(div, node.textContent.replace(/\u00a0/g, ' '));
      return;
    }
    if (node.nodeType !== Node.ELEMENT_NODE) return;
    if (node.tagName === 'BR') { div.append('\n'); return; }
    if (node.tagName === 'A') {
      if (hideTag && node.textContent.includes(hideTag)) return; // 话题页内隐藏当前话题标签
      // 长文被服务端截断时，末尾会带一个 <a href="">查看更多</a>，本地不展示这个空链接
      if (/^(查看更多|展开全文|阅读全文|点击查看全文)$/.test(node.textContent.trim())) return;
      const href = node.getAttribute('href') || '';
      if (!href || href.startsWith('javascript:')) { node.childNodes.forEach(walk); return; }
      // 话题标签（/t/xxx 或 #话题#）只做展示，不跳转
      if (/\/t\//.test(href) || /^#[^#]+#$/.test(node.textContent.trim())) {
        const tag = document.createElement('span');
        tag.className = 'topic-tag';
        tag.textContent = node.textContent;
        div.append(tag, ' ');
        return;
      }
      const a = document.createElement('a');
      a.href = href.startsWith('http') ? href : 'https://www.coolapk.com' + href;
      a.target = '_blank';
      a.rel = 'noopener';
      a.textContent = node.textContent;
      div.append(a, ' ');
      return;
    }
    node.childNodes.forEach(walk);
  }
  doc.body.childNodes.forEach(walk);
  return div.innerHTML;
}

// 话题标签只做展示：连卡片点击也拦掉，点标签没有任何反应
document.addEventListener('click', (e) => {
  if (e.target instanceof Element && e.target.closest('.topic-tag')) e.stopPropagation();
}, true);

/* ---------- 视图状态 ---------- */

// currentView:
//   { kind: 'list', tab }           普通列表页（首页/热门/全站/酷图/排行榜/分类）
//   { kind: 'topics' }              话题列表
//   { kind: 'topicFeed', tag, sort } 某话题下的动态（sort: dateline_desc 最新 | popular 热门）
let currentTab = 'main';
let currentView = { kind: 'list', tab: 'main' };
let page = 1;
let loading = false;
let noMore = false;
let loadGen = 0; // 请求代数：视图切换后旧请求的结果作废

const ENDPOINTS = {
  // 首页 = 酷安快讯（官方 Tab：V11_HOME_TAB_NEWS）
  main: '/api/v6/page/dataList?url=V11_HOME_TAB_NEWS',
  // 头条 = 热榜页（榜单入口 + 热搜 + 今日热门动态流）
  headline: '/api/v6/page/dataList?url=V9_HOME_TAB_RANKING',
  picture: '/api/v6/picture/list',
  // 应用 = 应用排行榜（可搜索）
  apk: '/api/v6/apk/realRankList',
};
const PAGED = new Set(['main', 'headline', 'picture', 'digital', 'apk']);

// 酷图分类（酷图接口按 tag 过滤，实测有效）
const PIC_CATS = ['全部', '壁纸', '手机壁纸', '二次元', '风景', '动漫壁纸', '景深壁纸', '艺术'];

// 数码分类：优先用官方 /v6/product/categoryList，拉不到时用这份兜底
let digitalCats = [
  { id: 0, title: '热门' }, { id: 1000, title: '手机' }, { id: 1001, title: '平板' },
  { id: 1037, title: '耳机' }, { id: 1005, title: '穿戴设备' }, { id: 1006, title: '数码配件' },
  { id: 1038, title: '电脑·外设' }, { id: 1004, title: '智能家居' },
];
let digitalCatsLoaded = false;

function viewUrl(view, p) {
  // 话题热门列表：酷安官方"热门"标签的真实数据源（薅羊毛小分队等大话题都在这里）
  if (view.kind === 'topics') {
    return '/api/v6/page/dataList?url=V11_VERTICL_TOPIIC_HOT_TAB&title=' +
      encodeURIComponent('热门') + '&page=' + p;
  }
  if (view.kind === 'topicSearch') {
    // 全站话题搜索：不再局限热门话题，直接按关键词查
    return '/api/v6/feed/searchTag?q=' + encodeURIComponent(view.keyword) + '&page=' + p;
  }
  if (view.kind === 'topicFeed') {
    return '/api/v6/topic/tagFeedList?tag=' + encodeURIComponent(view.tag) +
      '&listType=' + view.sort + '&page=' + p;
  }
  // 应用评论：listType = dateline_desc（最新评论）/ popular（热门评论）
  if (view.kind === 'apkReplies') {
    return '/api/v6/apk/commentList?id=' + encodeURIComponent(view.pkg) +
      '&listType=' + (view.sort || 'dateline_desc') + '&page=' + p;
  }
  // 应用：有关键词走搜索，否则是排行榜
  if (view.kind === 'list' && view.tab === 'apk') {
    return view.keyword
      ? '/api/v6/apk/search?q=' + encodeURIComponent(view.keyword) + '&page=' + p
      : '/api/v6/apk/realRankList?page=' + p;
  }
  // 酷图：按标签过滤
  if (view.kind === 'list' && view.tab === 'picture' && view.tag) {
    return '/api/v6/picture/list?tag=' + encodeURIComponent(view.tag) + '&page=' + p;
  }
  // 数码：分类 + 排序（sortField = hot_num 热度 / release_time 最新）
  if (view.kind === 'list' && view.tab === 'digital') {
    const inner = '/product/categoryDetailList?id=' + (view.catId || 1000) +
      '&isSecondCategory=0&sortField=' + (view.sort || 'hot_num') + '&showMode=0';
    return '/api/v6/page/dataList?url=' + encodeURIComponent(inner) + '&page=' + p;
  }
  // 数码产品下的酷友讨论
  if (view.kind === 'productFeeds') {
    return '/api/v6/page/dataList?url=' +
      encodeURIComponent('/product/feedList?id=' + view.pid) + '&page=' + p;
  }
  let url = ENDPOINTS[view.tab];
  if (PAGED.has(view.tab)) url += (url.includes('?') ? '&' : '?') + 'page=' + p;
  return url;
}

/** 官方配置页接口返回若干 card，话题实体在 entities 里，需要拍平 */
function flattenCards(items) {
  const out = [];
  for (const it of items) {
    if (it.entityType === 'card' && Array.isArray(it.entities) && it.entities.length) {
      out.push(...it.entities);
    } else {
      out.push(it);
    }
  }
  return out;
}

async function fetchItems(view, p) {
  const url = viewUrl(view, p);
  // 头条榜服务端会偶发返回空数组（实测 5 次里有 2 次为空），首页第一页空结果重试两次
  const tries = (view.kind === 'list' && view.tab === 'headline' && p === 1) ? 3 : 1;
  let json = {};
  for (let i = 0; i < tries; i++) {
    const res = await fetch(url);
    json = await res.json();
    if (!Array.isArray(json.data) || json.data.length || i === tries - 1) break;
    await new Promise((s) => setTimeout(s, 400));
  }
  if (json.messageStatus && json.messageStatus !== 0 && !Array.isArray(json.data)) {
    throw new Error(json.message || json.messageStatus);
  }
  const data = Array.isArray(json.data) ? json.data : [];
  if (view.kind === 'topics') {
    await loadFollowedTopics();
    return flattenCards(data).filter(x => x.entityType === 'topic' && !isTopicFollowed(x.title));
  }
  // 应用列表：排行榜返回 card 包裹，搜索返回裸 apk，统一拍平后只留应用
  if (view.kind === 'list' && view.tab === 'apk') {
    return flattenCards(data).filter(x => x.entityType === 'apk');
  }
  // 数码列表：去掉"品牌""排序规则"这类卡片，只留产品
  if (view.kind === 'list' && view.tab === 'digital') {
    return flattenCards(data).filter(x => x.entityType === 'product');
  }
  // 产品讨论：只留动态，"版本配置""同价位"等卡片丢掉
  if (view.kind === 'productFeeds') {
    return flattenCards(data).filter(x => x.entityType === 'feed');
  }
  return data;
}

/* ---------- 列表渲染 ---------- */

function renderItems(items, reset) {
  const list = $('#content');
  if (reset) list.innerHTML = '';
  let lastTemplate = null;
  for (const item of items) {
    // 热榜页的横排卡片：热搜话题 / 热搜词 / "今日热门"小标题
    if (item.entityType === 'card' && item.entityTemplate === 'iconMiniGridCard') {
      list.append(chipRowNode(item.entities || [], '热搜话题'));
      lastTemplate = null;
      continue;
    }
    if (item.entityType === 'card' && item.entityTemplate === 'capsuleListCard') {
      list.append(chipRowNode(item.entities || [], '热搜'));
      lastTemplate = null;
      continue;
    }
    if (item.entityType === 'card' && item.entityTemplate === 'selectorLinkCard') {
      list.append(sectionNode('今日热门'));
      lastTemplate = null;
      continue;
    }
    if (isGridCard(item)) {
      const nodes = gridNodes(item);
      const cells = nodes.filter(n => n.classList.contains('g-item'));
      if (!cells.length) {
        nodes.forEach(n => list.append(n));
        lastTemplate = null;
        continue;
      }
      const grid = document.createElement('div');
      grid.className = 'grid';
      cells.forEach(c => grid.append(c));
      if (lastTemplate === item.entityTemplate && list.lastElementChild?.classList.contains('grid')) {
        grid.remove();
        list.lastElementChild.append(...cells);
      } else {
        list.append(nodes[0].classList.contains('section-title') ? nodes[0] : document.createDocumentFragment());
        list.append(grid);
      }
      lastTemplate = item.entityTemplate;
      continue;
    }
    lastTemplate = null;
    // 应用评论页：接口返回的是 feed 结构，按普通动态卡片渲染，点开可看该条的评论
    if (item.entityType === 'feed') list.append(feedNode(item));
    else if (item.entityType === 'product') list.append(productNode(item));
    else if (item.entityType === 'apk') list.append(apkNode(item));
    else if (item.entityType === 'topic' || (item.title && item.logo && item.follownum !== undefined)) list.append(topicNode(item));
    else if (item.entityType === 'card' && item.entityTemplate === 'imageCarouselCard_1') list.append(carouselNode(item));
    else if (item.entityType === 'card' && item.titleCard?.title) list.append(sectionNode(item.titleCard.title));
    else if (item.entityType === 'category') list.append(categoryNode(item));
  }
}

const GRID_TEMPLATES = new Set([
  'iconLinkGridCard', 'iconMiniGridCard', 'iconMiniScrollCard', 'iconScrollCard',
  'imageTextScrollCard', 'iconTabLinkGridCard', 'iconMiniListCard', 'titleCard',
]);
function isGridCard(item) {
  return item.entityType === 'card' && GRID_TEMPLATES.has(item.entityTemplate || '');
}

function gridNodes(card) {
  const nodes = [];
  if (card.titleCard?.title) nodes.push(sectionNode(card.titleCard.title));
  for (const d of card.data || []) {
    const el = document.createElement('div');
    el.className = 'g-item';
    const img = d.icon || d.pic || d.logo;
    if (img) {
      const im = document.createElement('img');
      im.loading = 'lazy';
      im.src = proxyImg(img);
      el.append(im);
    }
    const t = document.createElement('div');
    t.className = 't';
    t.textContent = d.title || '';
    el.append(t);
    el.onclick = () => openByEntity(d);
    nodes.push(el);
  }
  return nodes;
}

function carouselNode(card) {
  const el = document.createElement('div');
  el.className = 'carousel';
  for (const d of card.data || []) {
    const a = document.createElement('a');
    const img = document.createElement('img');
    img.loading = 'lazy';
    img.src = proxyImg(d.pic || d.url);
    a.append(img);
    if (d.title) {
      const cap = document.createElement('span');
      cap.className = 'cap';
      cap.textContent = d.title;
      a.append(cap);
    }
    if (d.url) {
      a.href = d.url.startsWith('http') ? d.url : 'https://www.coolapk.com' + d.url;
      a.target = '_blank';
      a.rel = 'noopener';
      if (!d.url.startsWith('http')) a.onclick = (e) => { e.preventDefault(); openByEntity(d); };
    }
    el.append(a);
  }
  return el;
}

function sectionNode(title) {
  const el = document.createElement('div');
  el.className = 'section-title';
  el.textContent = title;
  return el;
}

/** 热榜页的横排词条（热搜话题 / 热搜词），点击进对应话题 */
function chipRowNode(entities, title) {
  const wrap = document.createElement('div');
  wrap.className = 'rank-chips';
  if (title) wrap.append(sectionNode(title));
  const row = document.createElement('div');
  row.className = 'chip-row';
  for (const e of entities) {
    const b = document.createElement('button');
    b.className = 'chip';
    b.textContent = e.title || '';
    const tag = String(e.url || '').replace(/^\/t\//, '');
    b.onclick = () => {
      const name = tag ? decodeURIComponent(tag) : (e.title || '');
      if (name) openTopicFeed(name);
    };
    row.append(b);
  }
  wrap.append(row);
  return wrap;
}

/** 构建动态卡片主体（列表与详情共用） */
function feedBody(f, opts = {}) {
  const hideTag = opts.hideTag || null;
  const el = document.createDocumentFragment();

  const row = document.createElement('div');
  row.className = 'feed-row';
  const main = document.createElement('div');
  main.className = 'feed-main';

  const head = document.createElement('div');
  head.className = 'feed-head';
  const av = document.createElement('img');
  av.className = 'avatar';
  av.loading = 'lazy';
  av.src = proxyImg(f.userAvatar || f.avatar);
  const info = document.createElement('div');
  const u = document.createElement('div');
  u.className = 'feed-user';
  u.textContent = f.username || '';
  const t = document.createElement('div');
  t.className = 'feed-time';
  t.textContent = [relTime(f.dateline), f.device_title && '来自 ' + f.device_title].filter(Boolean).join(' · ');
  info.append(u, t);
  head.append(av, info);
  main.append(head);

  const msg = document.createElement('div');
  msg.className = 'feed-msg';
  msg.innerHTML = sanitizeMessage(f.message, hideTag);
  main.append(msg);
  row.append(main);

  // 列表模式：右侧一张缩略图，作者与正文在左
  if (opts.thumb) {
    const first = (f.picArr || [])[0];
    if (first) {
      const orig = originalImg(first);
      const th = document.createElement('img');
      th.className = 'feed-thumb';
      th.loading = 'lazy';
      th.src = proxyImg(orig + '.s.jpg');
      th.onerror = () => { th.onerror = null; th.src = proxyImg(orig); };
      row.append(th);
    }
    el.append(row);
    return el;
  }
  el.append(row);

  const picCap = opts.bigPics ? 20 : 6;      // 列表最多 6 张（两行）
  const allPics = (f.picArr || []);
  const overflow = Math.max(0, allPics.length - picCap);
  const pics = allPics.slice(0, picCap);
  if (pics.length) {
    const box = document.createElement('div');
    box.className = 'feed-pics ' + (pics.length === 1 ? 'n1' : 'n3');
    for (let i = 0; i < pics.length; i++) {
      const orig = originalImg(pics[i]);
      const im = document.createElement('img');
      im.loading = 'lazy';
      im.src = proxyImg(orig + '.s.jpg');
      im.onerror = () => { im.onerror = null; im.src = proxyImg(orig); };
      im.dataset.orig = proxyImg(orig);
      im.onclick = (e) => {
        e.stopPropagation();
        const urls = [...box.querySelectorAll('img')].map(x => x.dataset.orig);
        openLightbox(urls, Math.max(0, urls.indexOf(im.dataset.orig)));
      };
      if (i === picCap - 1 && overflow > 0) {
        // 最后一张带 +N 蒙层，点击进入详情查看全部图片
        const wrap = document.createElement('div');
        wrap.className = 'pic-wrap';
        const more = document.createElement('div');
        more.className = 'pic-more';
        more.textContent = '+' + overflow;
        more.onclick = (e) => { e.stopPropagation(); showDetail(f); };
        wrap.append(im, more);
        box.append(wrap);
      } else {
        box.append(im);
      }
    }
    el.append(box);
  }
  return el;
}

function feedNode(f) {
  const el = document.createElement('article');
  el.className = 'feed-card';
  el.append(feedBody(f, { hideTag: currentTopicTag, thumb: true }));

  const msgEl = el.querySelector('.feed-msg');
  msgEl.classList.add('clamp');

  const foot = document.createElement('div');
  foot.className = 'feed-foot';
  const like = document.createElement('span');
  like.textContent = `👍 ${f.likenum || 0}`;
  const reply = document.createElement('span');
  reply.textContent = `💬 ${f.replynum || 0}`;
  foot.append(like, reply);
  el.append(foot);

  el.onclick = () => showDetail(f);

  // 正文超过 5 行时显示"...查看更多"，点击打开右侧详情
  requestAnimationFrame(() => {
    if (msgEl.scrollHeight > msgEl.clientHeight + 2) {
      const more = document.createElement('span');
      more.className = 'more-link';
      more.textContent = '...查看更多';
      more.onclick = (e) => { e.stopPropagation(); showDetail(f); };
      msgEl.after(more);
    }
  });
  return el;
}

function topicNode(t) {
  if (t.title) topicsCache.set(t.title, t);
  const el = document.createElement('article');
  el.className = 'topic-card feed-card';
  const logo = document.createElement('img');
  logo.className = 'topic-logo';
  logo.loading = 'lazy';
  logo.src = proxyImg(t.logo);
  const main = document.createElement('div');
  main.className = 'topic-main';
  const name = document.createElement('div');
  name.className = 'topic-name';
  name.textContent = '# ' + (t.title || '');
  const desc = document.createElement('div');
  desc.className = 'topic-desc';
  desc.textContent = t.description || '';
  const meta = document.createElement('div');
  meta.className = 'topic-meta';
  meta.textContent = [
    t.follownum !== undefined && t.follownum + ' 关注',
    t.commentnum !== undefined && t.commentnum + ' 讨论',
    t.hot_num !== undefined && '热度 ' + t.hot_num,
  ].filter(Boolean).join(' · ');
  main.append(name, desc, meta);
  el.append(logo, main);

  // 关注 / 已关注：状态以账号为准（/v6/user/followTagList），点击调真实接口
  const fb = document.createElement('button');
  const paint = (on) => {
    fb.className = 'follow-btn' + (on ? ' on' : '');
    fb.textContent = on ? '已关注' : '+ 关注';
  };
  paint(isTopicFollowed(t.title));
  fb.onclick = async (e) => {
    e.stopPropagation();
    if (fb.disabled) return;
    fb.disabled = true;
    try {
      paint(await toggleTopicFollow(t.title));
      renderPinnedTopics(); // 置顶区随关注变化
    } catch (err) {
      fb.textContent = '操作失败';
      setTimeout(() => paint(isTopicFollowed(t.title)), 1200);
    } finally {
      fb.disabled = false;
    }
  };
  el.append(fb);

  el.onclick = () => openTopicFeed(t.title || '');
  return el;
}

/* ---------- 应用关注（以账号为准，不写本地） ---------- */

function apkPkg(a) { return String(a.apkname || a.apkname2 || ''); }
function apkId(a) { return String(a.id || ''); }

let followedApks = [];      // 账号关注的应用（/v6/user/apkFollowList）
let apkFollowLoaded = false;

async function loadFollowedApks(force = false) {
  if (apkFollowLoaded && !force) return followedApks;
  try {
    const res = await fetch('/api/v6/user/apkFollowList?page=1');
    const json = await res.json();
    followedApks = Array.isArray(json.data) ? json.data.filter(x => x && (x.id || x.apkname)) : [];
    apkFollowLoaded = true;
  } catch { /* 失败保留旧值 */ }
  return followedApks;
}

function isApkFollowed(a) {
  const id = apkId(a);
  const pkg = apkPkg(a);
  return followedApks.some(x => String(x.id) === id || (pkg && apkPkg(x) === pkg));
}

/** 关注 / 取消关注应用：调酷安接口（需要数字 id），成功后刷新账号列表 */
async function toggleApkFollow(a) {
  const id = apkId(a);
  if (!id) throw new Error('缺少应用 id');
  const on = isApkFollowed(a);
  const res = await fetch('/api/v6/apk/' + (on ? 'unFollow' : 'follow') + '?id=' + encodeURIComponent(id),
    { method: 'POST' });
  const json = await res.json().catch(() => ({}));
  if (!json.data || typeof json.data !== 'object') throw new Error(json.message || '操作失败');
  await loadFollowedApks(true);
  return !on;
}

/** 我关注的应用置顶展示（仅应用列表页，数据来自账号） */
async function renderPinnedApks() {
  const box = $('#pinned-apks');
  const onApkList = currentView.kind === 'list' && currentView.tab === 'apk';
  if (!onApkList) { box.innerHTML = ''; return; }
  await loadFollowedApks();
  if (!(currentView.kind === 'list' && currentView.tab === 'apk')) { box.innerHTML = ''; return; }
  box.innerHTML = '';
  if (!followedApks.length) return;
  const label = document.createElement('div');
  label.className = 'section-title';
  label.textContent = '我关注的应用';
  box.append(label);
  for (const it of followedApks) box.append(apkNode(it));
}

function apkNode(a) {
  const el = document.createElement('article');
  el.className = 'apk-card';
  const logo = document.createElement('img');
  logo.className = 'apk-logo';
  logo.loading = 'lazy';
  logo.src = proxyImg(a.logo);

  const main = document.createElement('div');
  main.className = 'apk-main';
  const name = document.createElement('div');
  name.className = 'apk-name';
  name.append(a.title || a.name || '');
  const score = Number(a.score || a.rating);
  if (score) {
    const b = document.createElement('span');
    b.className = 'badge-score';
    b.textContent = score.toFixed(1);
    name.append(b);
  }
  const desc = document.createElement('div');
  desc.className = 'apk-desc';
  desc.textContent = a.brief || a.description || '';
  const meta = document.createElement('div');
  meta.className = 'apk-meta';
  meta.textContent = [
    a.apkversionname && 'v' + a.apkversionname,
    a.apksize,
    a.downCount && a.downCount + ' 下载',
    a.commentnum && a.commentnum + ' 评论',
  ].filter(Boolean).join(' · ');
  main.append(name, desc, meta);

  // 关注 / 已关注：状态以账号为准（/v6/user/apkFollowList）
  const follow = document.createElement('button');
  const paint = (on) => {
    follow.className = 'apk-follow' + (on ? ' on' : '');
    follow.textContent = on ? '已关注' : '+ 关注';
  };
  paint(isApkFollowed(a));
  follow.onclick = async (e) => {
    e.stopPropagation();
    if (follow.disabled) return;
    follow.disabled = true;
    try {
      paint(await toggleApkFollow(a));
      renderPinnedApks();
    } catch (err) {
      follow.textContent = '操作失败';
      setTimeout(() => paint(isApkFollowed(a)), 1200);
    } finally {
      follow.disabled = false;
    }
  };

  el.append(logo, main, follow);
  el.onclick = () => openApkReplies(a);
  return el;
}

/** 应用评论页：中栏替换成该应用的评论列表 */
function openApkReplies(a) {
  const pkg = apkPkg(a);
  if (!pkg) return;
  currentView = { kind: 'apkReplies', pkg, title: a.title || pkg, sort: 'dateline_desc' };
  scrollListTop();
  updateToolbar();
  load(true);
}

/* ---------- 数码产品卡片 ---------- */

function fmtNum(n) {
  const v = Number(n);
  if (!v) return '0';
  if (v >= 100000000) return (v / 100000000).toFixed(1) + '亿';
  if (v >= 10000) return (v / 10000).toFixed(1) + '万';
  return String(v);
}

function priceText(p) {
  const cur = p.price_currency || '¥';
  const min = Number(p.price_min);
  const max = Number(p.price_max);
  if (!min && !max) return '';
  if (min && max && min !== max) return `${cur}${min} - ${cur}${max}`;
  return `${cur}${min || max}`;
}

function productNode(p) {
  const el = document.createElement('article');
  el.className = 'product-card';

  const logo = document.createElement('img');
  logo.className = 'product-logo';
  logo.loading = 'lazy';
  logo.src = proxyImg(p.logo);

  const main = document.createElement('div');
  main.className = 'product-main';
  const name = document.createElement('div');
  name.className = 'product-name';
  name.append(p.title || '');
  const star = Number(p.star_average_score);
  if (star) {
    const b = document.createElement('span');
    b.className = 'badge-score';
    b.textContent = star.toFixed(1);
    name.append(b);
  }
  const meta = document.createElement('div');
  meta.className = 'product-meta';
  meta.textContent = [
    p.hot_num && '热度 ' + fmtNum(p.hot_num),
    p.star_total_count && p.star_total_count + ' 人评分',
    p.release_time,
  ].filter(Boolean).join(' · ');
  main.append(name, meta);

  const price = priceText(p);
  if (price) {
    const pr = document.createElement('div');
    pr.className = 'product-price';
    pr.textContent = price;
    main.append(pr);
  }

  el.append(logo, main);
  el.onclick = () => openProductFeeds(p);
  return el;
}

/** 产品详情：中栏切换成该产品的酷友讨论 */
let lastDigitalView = null;
function openProductFeeds(p) {
  lastDigitalView = (currentView.kind === 'list' && currentView.tab === 'digital')
    ? { ...currentView }
    : null;
  currentView = { kind: 'productFeeds', pid: p.id, title: p.title || '产品' };
  scrollListTop();
  updateToolbar();
  load(true);
}

/* ---------- 数码分类 ---------- */

async function ensureDigitalCats() {
  if (digitalCatsLoaded) return;
  try {
    const res = await fetch('/api/v6/product/categoryList');
    const json = await res.json();
    const list = (Array.isArray(json.data) ? json.data : [])
      .filter(x => x && x.id !== undefined && x.title)
      .map(x => ({ id: x.id, title: x.title }));
    if (list.length) digitalCats = list;
  } catch { /* 保留兜底分类 */ }
  digitalCatsLoaded = true;
}

function renderDigitalCats(view) {
  const box = $('#digital-cats');
  box.innerHTML = '';
  for (const c of digitalCats) {
    const b = document.createElement('button');
    b.className = 'chip' + (String(c.id) === String(view.catId) ? ' active' : '');
    b.textContent = c.title;
    b.onclick = () => {
      currentView = { kind: 'list', tab: 'digital', catId: c.id, catTitle: c.title, sort: view.sort || 'hot_num' };
      scrollListTop();
      updateToolbar();
      load(true);
    };
    box.append(b);
  }
  updateDigitalNav();
}

/** 分类太多时显示左右滑动按钮 */
function updateDigitalNav() {
  const row = $('#digital-cats');
  const prev = $('#digital-prev');
  const next = $('#digital-next');
  if (!row || !prev || !next) return;
  const overflow = row.scrollWidth > row.clientWidth + 4;
  prev.hidden = !overflow;
  next.hidden = !overflow;
  if (!overflow) return;
  prev.disabled = row.scrollLeft <= 2;
  next.disabled = row.scrollLeft >= row.scrollWidth - row.clientWidth - 2;
}

function categoryNode(c) {
  const el = document.createElement('div');
  el.className = 'g-item';
  if (c.logo) {
    const im = document.createElement('img');
    im.loading = 'lazy';
    im.src = proxyImg(c.logo);
    el.append(im);
  }
  const t = document.createElement('div');
  t.className = 't';
  t.textContent = c.name || '';
  el.append(t);
  return el;
}

/* ---------- 右栏：动态详情 + 评论 ---------- */

// 注意：不能带 listType=feed——酷安会把它当成别的列表类型，返回空数组（实测 9 条变 0 条）
const COMMENT_PARAMS = 'discussMode=0&feedType=feed&blockStatus=0&fromFeedAuthor=0';
let detailFeedId = null;
let commentPage = 1;
let commentLoading = false;

// 列表里的长动态是服务端截断版（末尾带"查看更多"），详情改用 detail 接口的全文
const TRUNCATED_RE = /查看更多|展开全文|阅读全文/;

async function fetchFullMessage(id) {
  try {
    const res = await fetch('/api/v6/feed/detail?id=' + encodeURIComponent(id));
    const json = await res.json();
    const m = json?.data?.message;
    return (typeof m === 'string' && m && !TRUNCATED_RE.test(m)) ? m : '';
  } catch { return ''; }
}

async function showDetail(f) {
  detailFeedId = f.id;
  const col = $('#detail-col');
  const box = $('#detail-content');
  box.innerHTML = '';
  col.hidden = false;
  col.scrollTop = 0;

  const card = document.createElement('article');
  card.className = 'feed-card';
  card.append(feedBody(f, { bigPics: true, hideTag: currentTopicTag }));

  // 截断版先渲染，拿到全文后原地替换（详情接口受风控限制，失败就保持截断版）
  if (TRUNCATED_RE.test(f.message || '')) {
    fetchFullMessage(f.id).then((full) => {
      if (!full || detailFeedId !== f.id) return;
      const msgEl = card.querySelector('.feed-msg');
      if (msgEl) msgEl.innerHTML = sanitizeMessage(full, currentTopicTag);
    });
  }

  const stats = document.createElement('div');
  stats.className = 'feed-foot';
  stats.textContent = [
    f.likenum !== undefined && `👍 ${f.likenum}`,
    f.replynum !== undefined && `💬 ${f.replynum} 评论`,
    '发布于 ' + relTime(f.dateline),
  ].filter(Boolean).join('    ');
  card.append(stats);
  box.append(card);

  const title = document.createElement('div');
  title.className = 'detail-section-title';
  title.textContent = '评论';
  box.append(title);

  const cbox = document.createElement('div');
  cbox.id = 'comment-box';
  box.append(cbox);

  commentPage = 1;
  commentMode = 'hot';
  await loadComments(f, 0, 'hot');
}

/** 右栏默认占位：未选择动态时显示 */
function showDetailPlaceholder() {
  detailFeedId = null;
  const col = $('#detail-col');
  const box = $('#detail-content');
  box.innerHTML = '';
  col.hidden = false;

  const wrap = document.createElement('div');
  wrap.className = 'detail-placeholder';
  const logo = document.createElement('img');
  logo.src = 'logo.ico';
  const t = document.createElement('div');
  t.className = 'ph-title';
  t.textContent = '动态详情';
  const d = document.createElement('div');
  d.className = 'ph-desc';
  d.textContent = '点击左侧任意动态，这里会展示完整内容与评论';
  wrap.append(logo, t, d);
  box.append(wrap);
}

// 评论两种来源（参考 FuckCoolapkFeeds 的做法）：
//   hot  —— /v6/feed/hotReplyList：免登录、免验证码，但只给"热门评论"（一般就 1 页）
//   full —— /v6/feed/replyList：完整评论，受风控保护，需要滑块凭证
let commentMode = 'hot';

/** 没有热门评论时的入口：点了才加载完整评论（这一步才可能弹滑块） */
function renderCommentGate(f, cbox) {
  cbox.innerHTML = '';
  const gate = document.createElement('button');
  gate.className = 'comment-gate';
  gate.textContent = f.replynum ? `查看评论（共 ${f.replynum} 条）` : '查看评论';
  gate.onclick = () => {
    commentMode = 'full';
    commentPage = 1;
    cbox.innerHTML = '';
    loadComments(f, 0, 'full');
  };
  cbox.append(gate);
}

async function loadComments(f, attempt = 0, mode = commentMode) {
  if (commentLoading || detailFeedId !== f.id) return;
  commentLoading = true;
  const cbox = $('#comment-box');
  cbox.querySelector('.comment-more')?.remove();
  cbox.querySelector('.comment-hint')?.remove();
  let tip = cbox.querySelector('.comment-empty');
  if (!tip) {
    tip = document.createElement('div');
    tip.className = 'comment-empty';
    tip.textContent = '评论加载中…';
    cbox.append(tip);
  }
  try {
    const url = mode === 'hot'
      ? `/api2/v6/feed/hotReplyList?id=${encodeURIComponent(f.id)}&page=1&discussMode=0`
      : `/api2/v6/feed/replyList?id=${encodeURIComponent(f.id)}&page=${commentPage}&${COMMENT_PARAMS}`;
    const res = await fetch(url);
    const json = await res.json();
    if (!Array.isArray(json.data)) {
      // 风控要求人机验证：用接口下发的 captchaId 弹滑块，通过后凭证存后端并自动重试
      const challenge = parseCaptchaChallenge(json);
      if (challenge && attempt < 3) {
        if (attempt === 0) {
          // 先用已保存的凭证静默重试一次，可能仍然有效
          const st = await fetch('/captcha/status').then(r => r.json()).catch(() => ({ has: false }));
          if (st.has) {
            commentLoading = false;
            return loadComments(f, attempt + 1, mode);
          }
        }
        tip.textContent = '酷安要求人机验证，请完成滑块（通过后自动加载评论）…';
        await solveCaptcha(challenge);
        commentLoading = false;
        return loadComments(f, attempt + 1, mode);
      }
      throw new Error(json.message || '加载失败');
    }
    // 没有热门评论时不再自动走完整列表（会立刻弹滑块），改为显示一个入口按钮
    if (mode === 'hot' && !json.data.length) {
      commentLoading = false;
      tip.remove();
      renderCommentGate(f, cbox);
      return;
    }
    tip.remove();
    if (!json.data.length && commentPage === 1) {
      const empty = document.createElement('div');
      empty.className = 'comment-empty';
      empty.textContent = '还没有评论';
      cbox.append(empty);
    }
    for (const r of json.data) cbox.append(replyNode(r, false));
    if (mode === 'hot') {
      // 热门评论只覆盖一部分，给一个"查看全部"入口（点它才走验证码）
      const hint = document.createElement('div');
      hint.className = 'comment-hint';
      const txt = document.createElement('span');
      txt.textContent = '以上为热门评论' + (f.replynum ? `（共 ${f.replynum} 条）` : '');
      const btn = document.createElement('button');
      btn.textContent = '查看全部评论';
      btn.onclick = () => {
        commentMode = 'full';
        commentPage = 1;
        hint.remove();
        cbox.querySelectorAll('.reply-item').forEach((n) => n.remove());
        loadComments(f, 0, 'full');
      };
      hint.append(txt, btn);
      cbox.append(hint);
    } else if (json.data.length >= 20) {
      const more = document.createElement('button');
      more.className = 'comment-more';
      more.textContent = '加载更多评论';
      more.onclick = () => { loadComments(f, 0, 'full'); }; // commentPage 已在成功后自增
      cbox.append(more);
    }
    commentPage++;
  } catch (err) {
    tip.innerHTML = '';
    tip.textContent = '暂时无法获取评论：' + err.message + '。';
    const a = document.createElement('a');
    a.href = 'https://www.coolapk.com/feed/' + f.id;
    a.target = '_blank';
    a.rel = 'noopener';
    a.textContent = ' ↗ 打开原文查看评论';
    tip.append(a);
  }
  commentLoading = false;
}

function replyNode(r, nested) {
  const el = document.createElement('div');
  el.className = 'reply-item';

  const av = document.createElement('img');
  av.className = 'avatar';
  av.loading = 'lazy';
  av.src = proxyImg(r.userAvatar);
  el.append(av);

  const main = document.createElement('div');
  main.className = 'reply-main';
  const user = document.createElement('div');
  user.className = 'reply-user';
  user.textContent = r.username || '';
  const time = document.createElement('span');
  time.className = 'reply-time';
  time.textContent = relTime(r.dateline);
  user.append(time);

  const msg = document.createElement('div');
  msg.className = 'reply-msg';
  msg.innerHTML = sanitizeMessage(r.message);

  main.append(user, msg);

  // 楼中楼回复
  const sub = r.reply_rows || r.replyRows;
  if (sub?.length) {
    const box = document.createElement('div');
    box.className = 'reply-nested';
    for (const s of sub.slice(0, 3)) box.append(replyNode(s, true));
    main.append(box);
  }
  el.append(main);

  if (!nested && r.likenum) {
    const like = document.createElement('div');
    like.className = 'reply-like';
    like.textContent = '👍 ' + r.likenum;
    el.append(like);
  }
  return el;
}

function closeDetail() {
  showDetailPlaceholder();
}

/* ---------- 话题关注（以账号为准，不写本地） ---------- */

const topicsCache = new Map(); // title -> 话题数据

let followedTopics = [];       // 账号关注的话题（来自 /v6/user/followTagList）
let followedLoaded = false;

async function loadFollowedTopics(force = false) {
  if (followedLoaded && !force) return followedTopics;
  try {
    const res = await fetch('/api/v6/user/followTagList?page=1');
    const json = await res.json();
    const list = Array.isArray(json.data) ? json.data.filter(x => x && x.title) : [];
    followedTopics = list;
    followedLoaded = true;
  } catch { /* 拉取失败时保留上一次结果 */ }
  return followedTopics;
}

function isTopicFollowed(title) {
  return followedTopics.some(x => x.title === title);
}

/** 关注 / 取消关注：调酷安接口，成功后刷新账号关注列表 */
async function toggleTopicFollow(title) {
  const on = isTopicFollowed(title);
  const url = '/api/v6/feed/' + (on ? 'unFollowTag' : 'followTag') +
    '?tag=' + encodeURIComponent(title);
  const res = await fetch(url, { method: 'POST' });
  const json = await res.json().catch(() => ({}));
  if (json.status !== 1) throw new Error(json.message || '操作失败');
  await loadFollowedTopics(true);
  return !on;
}

/** 我关注的话题置顶展示（仅话题列表页，数据直接来自账号） */
async function renderPinnedTopics() {
  const box = $('#pinned-topics');
  if (currentView.kind !== 'topics') { box.innerHTML = ''; return; }
  await loadFollowedTopics();
  if (currentView.kind !== 'topics') { box.innerHTML = ''; return; }
  box.innerHTML = '';
  if (!followedTopics.length) return;
  const label = document.createElement('div');
  label.className = 'section-title';
  label.textContent = '我关注的话题';
  box.append(label);
  for (const t of followedTopics) box.append(topicNode(t));
}

/* ---------- 话题视图 ---------- */

let currentTopicTag = null; // 话题动态页中要隐藏的话题名

function openTopicFeed(tag) {
  currentTopicTag = tag;
  currentView = { kind: 'topicFeed', tag, sort: 'dateline_desc' };
  scrollListTop();
  updateToolbar();
  load(true);
}

function backToList() {
  if (currentView.kind === 'apkReplies') {
    currentView = { kind: 'list', tab: 'apk' };
  } else if (currentView.kind === 'productFeeds') {
    currentView = lastDigitalView || { kind: 'list', tab: 'digital', catId: 1000, catTitle: '手机', sort: 'hot_num' };
  } else {
    currentTopicTag = null;
    currentView = { kind: 'topics' };
  }
  scrollListTop();
  updateToolbar();
  load(true);
}

function updateToolbar() {
  const bar = $('#toolbar');
  const search = $('#topic-search');
  const picBar = $('#pic-bar');
  const apkBar = $('#apk-bar');
  const v = currentView;

  // 固定顶部栏：话题动态 / 应用评论 / 产品讨论 共用，标题与排序文案按场景切换
  const isTopicFeed = v.kind === 'topicFeed';
  const isApkReplies = v.kind === 'apkReplies';
  const isProductFeeds = v.kind === 'productFeeds';
  bar.hidden = !(isTopicFeed || isApkReplies || isProductFeeds);
  if (isTopicFeed || isApkReplies || isProductFeeds) {
    $('#toolbar-title').textContent = isProductFeeds
      ? (v.title || '')
      : (isApkReplies ? (v.title || '') : '# ' + (v.tag || ''));
    // 产品讨论接口不支持排序，隐藏排序按钮
    const group = bar.querySelector('.tb-group');
    group.hidden = isProductFeeds;
    if (!isProductFeeds) {
      const labels = isApkReplies
        ? { dateline_desc: '最新评论', popular: '热门评论' }
        : { dateline_desc: '最新动态', popular: '热门动态' };
      bar.querySelectorAll('.tb-sort').forEach(b => {
        b.textContent = labels[b.dataset.sort] || b.textContent;
        b.classList.toggle('active', b.dataset.sort === v.sort);
      });
    }
  }

  // 话题列表 / 搜索结果 显示话题搜索框
  search.hidden = !(v.kind === 'topics' || v.kind === 'topicSearch');
  if (v.kind === 'topics') $('#topic-search-input').value = '';

  // 酷图：分类 + 搜索
  const isPic = v.kind === 'list' && v.tab === 'picture';
  picBar.hidden = !isPic;
  if (isPic) renderPicCats(v.tag || '');

  // 应用：搜索
  const isApkList = v.kind === 'list' && v.tab === 'apk';
  apkBar.hidden = !isApkList;
  if (isApkList) renderPinnedApks(); else $('#pinned-apks').innerHTML = '';

  // 数码：分类 + 排序
  const isDigital = v.kind === 'list' && v.tab === 'digital';
  const digitalBar = $('#digital-bar');
  digitalBar.hidden = !isDigital;
  if (isDigital) {
    ensureDigitalCats().then(() => {
      if (currentView.kind === 'list' && currentView.tab === 'digital') renderDigitalCats(currentView);
    });
    renderDigitalCats(v);
    document.querySelectorAll('#digital-sorts .sort-btn').forEach(b =>
      b.classList.toggle('active', b.dataset.sort === (v.sort || 'hot_num')));
  }
  // 关注话题列表只属于话题列表页
  if (v.kind !== 'topics') $('#pinned-topics').innerHTML = '';
}

/** 酷图分类 chips */
function renderPicCats(activeTag) {
  const box = $('#pic-cats');
  box.innerHTML = '';
  for (const c of PIC_CATS) {
    const b = document.createElement('button');
    const on = c === '全部' ? !activeTag : c === activeTag;
    b.className = 'chip' + (on ? ' active' : '');
    b.textContent = c;
    b.onclick = () => {
      currentView = { kind: 'list', tab: 'picture', tag: c === '全部' ? '' : c };
      $('#pic-search-input').value = c === '全部' ? '' : c;
      scrollListTop();
      updateToolbar();
      load(true);
    };
    box.append(b);
  }
}

/* ---------- 主题色切换（右上角） ---------- */

const THEMES = {
  green: '酷安绿',
  blue: '晴空蓝',
  purple: '星河紫',
  teal: '松石青',
  orange: '落日橙',
  pink: '樱花粉',
  dark: '暗黑',
};

const themeBtn = $('#theme-btn');
const themeMenu = $('#theme-menu');

/** 应用主题（不做持久化：每次进入由 index.html 随机选色） */
function applyTheme(name) {
  const theme = THEMES[name] ? name : 'green';
  document.documentElement.setAttribute('data-theme', theme);
  $('#theme-name').textContent = THEMES[theme];
  document.querySelectorAll('.theme-swatch').forEach(b => {
    const on = b.dataset.theme === theme;
    b.classList.toggle('active', on);
    b.setAttribute('aria-pressed', on ? 'true' : 'false');
  });
}

function setThemeMenu(open) {
  themeMenu.hidden = !open;
  themeBtn.setAttribute('aria-expanded', open ? 'true' : 'false');
}

themeBtn.onclick = (e) => {
  e.stopPropagation();
  setThemeMenu(themeMenu.hidden);
};

document.querySelectorAll('.theme-swatch').forEach(b => {
  b.onclick = () => {
    applyTheme(b.dataset.theme);
    setThemeMenu(false);
  };
});

// 点击面板外部 / 按 Esc 收起
document.addEventListener('click', (e) => {
  if (!themeMenu.hidden && !e.target.closest('#theme-picker')) setThemeMenu(false);
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !themeMenu.hidden) setThemeMenu(false);
});

// 首屏主题已由 index.html 内联脚本随机决定，这里同步面板的选中态
applyTheme(document.documentElement.getAttribute('data-theme'));

$('#account-btn').onclick = openAccountModal;

/* ---------- 应用详情弹窗 ---------- */

async function openApk(pkg, fallbackTitle) {
  showModal('<div class="status">加载中…</div>');
  try {
    const res = await fetch('/api/v6/apk/detail?id=' + encodeURIComponent(pkg));
    const json = await res.json();
    const d = json.data || {};
    if (!d.title && fallbackTitle) d.title = fallbackTitle;
    const body = document.createElement('div');

    const head = document.createElement('div');
    head.className = 'app-head';
    const logo = document.createElement('img');
    logo.src = proxyImg(d.logo);
    const hd = document.createElement('div');
    const h2 = document.createElement('h2');
    h2.textContent = d.title || '';
    const ver = document.createElement('div');
    ver.className = 'ver';
    ver.textContent = [d.apkversionname && 'v' + d.apkversionname, d.apksize].filter(Boolean).join(' · ');
    hd.append(h2, ver);
    head.append(logo, hd);
    body.append(head);

    const score = Number(d.score || d.rating);
    const stats = [
      score && ['评分', score.toFixed(1)],
      d.downCount && ['下载', d.downCount],
      d.commentnum && ['评论', d.commentnum],
    ].filter(Boolean);
    if (stats.length) {
      const box = document.createElement('div');
      box.className = 'app-stats';
      for (const [label, val] of stats) {
        const cell = document.createElement('div');
        const b = document.createElement('b');
        b.textContent = val;
        const s = document.createElement('span');
        s.textContent = label;
        cell.append(b, s);
        box.append(cell);
      }
      body.append(box);
    }

    const desc = document.createElement('div');
    desc.className = 'app-desc';
    desc.textContent = d.description || d.intro || '暂无介绍';
    body.append(desc);

    const link = document.createElement('p');
    link.style.marginTop = '16px';
    const a = document.createElement('a');
    a.href = 'https://www.coolapk.com/apk/' + encodeURIComponent(d.apkname || pkg);
    a.target = '_blank';
    a.rel = 'noopener';
    a.textContent = '在酷安官网查看 / 下载 →';
    link.append(a);
    body.append(link);

    showModal('');
    $('#modal-content').append(body);
  } catch (err) {
    showModal('');
    const e = document.createElement('div');
    e.className = 'status error';
    e.textContent = '加载失败：' + err.message;
    $('#modal-content').append(e);
  }
}

function openByEntity(d) {
  const url = d.url || '';
  const m = url.match(/^\/(?:apk|game)\/([\w.]+)/);
  if (m) return openApk(m[1]);
  if (url) window.open(url.startsWith('http') ? url : 'https://www.coolapk.com' + url, '_blank');
}

/* ---------- 账号登录 ---------- */

let loginPollTimer = null; // 本机登录页的后备轮询
let loginFrameEl = null;   // 当前展示的本机登录 iframe

function clearLoginPoll() {
  if (loginPollTimer) { clearInterval(loginPollTimer); loginPollTimer = null; }
}

/** 关闭本机登录框并清掉轮询（关闭弹窗时也要调用，避免定时器泄漏） */
function closeLoginFrame() {
  clearLoginPoll();
  loginFrameEl?.remove();
  loginFrameEl = null;
}

function setLoginMsg(text, ok = false) {
  const el = $('#login-msg');
  if (!el) return;
  el.textContent = text || '';
  el.classList.toggle('ok', !!ok);
}

/** 登录成功后的统一收尾：收起登录框、更新头像、刷新列表 */
function afterLogin(msg) {
  closeLoginFrame();
  setLoginMsg(msg || '登录成功，凭证已保存', true);
  updateAccountBtn();
  showDetailPlaceholder();
  load(true);
}

/** 从整段 Cookie（或仅 token/uid 片段）里识别凭证 */
function parseAccountCookie(raw) {
  const out = {};
  const re = /(?:^|[;\s])(uid|username|token)=([^;]*)/gi;
  let m;
  while ((m = re.exec(String(raw || '')))) {
    let val = m[2].trim().replace(/^["']|["']$/g, '');
    if (!val) continue;
    try { val = decodeURIComponent(val); } catch { /* 保留原文 */ }
    out[m[1].toLowerCase()] = val;
  }
  return out;
}

/** 保存账号配置，失败时抛出可展示的错误 */
async function saveAccount(payload) {
  const res = await fetch('/account', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const j = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(j.error || '保存失败');
  return j;
}

/** 本机登录页提交后由注入脚本 postMessage；只接受当前登录框的同源消息 */
window.addEventListener('message', (ev) => {
  if (ev.origin !== location.origin) return;
  if (!ev.data || ev.data.type !== 'coolapk-login-ok') return;
  if (!loginFrameEl || ev.source !== loginFrameEl.contentWindow) return;
  afterLogin('登录成功，凭证已保存');
});

/** 后备方案：定时查询账号是否已变化（postMessage 丢失时兜底） */
function startLoginPoll(known) {
  clearLoginPoll();
  loginPollTimer = setInterval(async () => {
    if (!document.querySelector('#login-msg')) { clearLoginPoll(); return; } // 弹窗已关闭
    try {
      const st = await (await fetch('/account')).json();
      if (!st.configured) return;
      if (`${st.uid}:${st.tokenTail}` === known) return;
      afterLogin(`登录成功：${st.username || ''}，凭证已保存`);
    } catch { /* 忽略轮询失败 */ }
  }, 2000);
}

async function openAccountModal() {
  closeLoginFrame(); // 重新打开时清掉上一次的登录框与轮询
  showModal('<div class="status">加载中…</div>');
  let status = { configured: false };
  try {
    const res = await fetch('/account');
    status = await res.json();
  } catch { /* 保持未配置 */ }
  if ($('#modal').hidden) return; // 用户已关闭弹窗，不再渲染

  const body = document.createElement('div');
  const h2 = document.createElement('h2');
  h2.textContent = '账号设置';
  body.append(h2);

  const st = document.createElement('div');
  st.className = 'account-status';
  st.textContent = status.configured
    ? `已配置：uid=${status.uid}，用户名=${status.username || '（空）'}，token 尾号 ${status.tokenTail}`
    : '未配置。配置后可查看动态评论（匿名会话评论接口受酷安风控限制）。';
  body.append(st);

  // ---- 登录（官网 + Cookie 粘贴免手填） ----
  const loginSec = document.createElement('div');
  loginSec.className = 'login-section';
  loginSec.style.borderTop = 'none';
  loginSec.style.marginTop = '12px';
  loginSec.style.paddingTop = '0';
  const lt = document.createElement('h3');
  lt.textContent = '登录';
  const lh = document.createElement('div');
  lh.className = 'account-hint';
  lh.innerHTML = '推荐：点按钮在酷安官网完成登录（正常域名下滑块更容易通过），回到这里把 <b>account.coolapk.com 的 Cookie 整段粘贴</b>到下面，会自动识别 uid / username / token 并保存。凭证只保存在本机。';
  const loginBtn = document.createElement('button');
  loginBtn.id = 'login-submit';
  loginBtn.textContent = '打开酷安官网登录页';
  const localBtn = document.createElement('button');
  localBtn.id = 'login-local';
  localBtn.className = 'btn-secondary';
  localBtn.textContent = '在本机登录（备用，滑块可能较难）';

  const pasteWrap = document.createElement('div');
  pasteWrap.className = 'account-form';
  const pasteField = document.createElement('div');
  const pasteLabel = document.createElement('label');
  pasteLabel.htmlFor = 'cookie-paste';
  pasteLabel.textContent = '粘贴 Cookie（自动识别 uid / username / token）';
  const pasteRow = document.createElement('div');
  pasteRow.className = 'cookie-row';
  const pasteInput = document.createElement('input');
  pasteInput.id = 'cookie-paste';
  pasteInput.placeholder = 'uid=123456; username=xxx; token=xxx';
  pasteInput.autocomplete = 'off';
  const pasteBtn = document.createElement('button');
  pasteBtn.id = 'cookie-apply';
  pasteBtn.type = 'button';
  pasteBtn.textContent = '识别并保存';
  pasteRow.append(pasteInput, pasteBtn);
  pasteField.append(pasteLabel, pasteRow);
  pasteWrap.append(pasteField);

  const loginMsg = document.createElement('div');
  loginMsg.className = 'login-msg';
  loginMsg.id = 'login-msg';

  loginSec.append(lt, lh, loginBtn, localBtn, pasteWrap, loginMsg);
  body.append(loginSec);

  // ---- 手动配置（备用） ----
  const manualSec = document.createElement('div');
  manualSec.className = 'login-section';
  const mt = document.createElement('h3');
  mt.textContent = '手动配置';
  const hint = document.createElement('div');
  hint.className = 'account-hint';
  hint.innerHTML = '也可以直接填写 uid / username / token。<b>X-App-Device 和 User-Agent 留空即可</b>，后端会按机型自动生成配套设备；留空的字段沿用已保存的值，配置只保存在本机。';
  manualSec.append(mt, hint);

  const form = document.createElement('div');
  form.className = 'account-form';
  const fields = [
    ['deviceModel', '显示机型（评论会显示“来自 X”；如 荣耀X50 / 小米14）', status.deviceModel || ''],
    ['uid', 'uid（用户ID，纯数字）', status.uid || ''],
    ['username', 'username（用户名，URL 编码或原文均可）', ''],
    ['token', 'token（登录凭证，最长的一串）', ''],
  ];
  const inputs = {};
  for (const [key, label, val] of fields) {
    const wrap = document.createElement('div');
    const lab = document.createElement('label');
    lab.htmlFor = 'account-' + key;
    lab.textContent = label;
    const input = document.createElement('input');
    input.id = 'account-' + key;
    input.value = val;
    wrap.append(lab, input);
    form.append(wrap);
    inputs[key] = input;
  }
  // 进阶字段默认折叠，避免普通用户被设备串/UA 吓到
  const adv = document.createElement('details');
  adv.className = 'account-advanced';
  const advSum = document.createElement('summary');
  advSum.textContent = '高级选项（手机抓包时填写）';
  const advFields = document.createElement('div');
  advFields.className = 'account-form';
  for (const [key, label] of [
    ['device', 'X-App-Device（仅手机抓包需要，留空自动生成）'],
    ['ua', 'User-Agent（仅手机抓包需要，留空自动生成）'],
  ]) {
    const wrap = document.createElement('div');
    const lab = document.createElement('label');
    lab.htmlFor = 'account-' + key;
    lab.textContent = label;
    const input = document.createElement('input');
    input.id = 'account-' + key;
    wrap.append(lab, input);
    advFields.append(wrap);
    inputs[key] = input;
  }
  adv.append(advSum, advFields);
  form.append(adv);

  const actions = document.createElement('div');
  actions.className = 'account-actions';
  const save = document.createElement('button');
  save.id = 'account-save';
  save.textContent = '保存并刷新';
  const clear = document.createElement('button');
  clear.id = 'account-clear';
  clear.textContent = '清除配置';
  actions.append(save, clear);

  const manualMsg = document.createElement('div');
  manualMsg.className = 'login-msg';
  manualMsg.id = 'manual-msg';
  form.append(actions, manualMsg);
  manualSec.append(form);
  body.append(manualSec);

  const knownAccount = status.configured ? `${status.uid}:${status.tokenTail}` : '';

  // 推荐：打开真实官网登录页（正常域名下滑块更容易通过）
  loginBtn.onclick = () => {
    window.open('https://account.coolapk.com/auth/loginByCoolApk', 'coolapk_real_login', 'noopener');
    setLoginMsg('已打开官网登录页；登录完成后把 account.coolapk.com 的 Cookie 整段粘贴到上面，点「识别并保存」');
    pasteInput.focus();
  };

  // 备用：本机代理登录页（同源 iframe，滑块通过后由注入脚本自动提交）
  localBtn.onclick = () => {
    if (loginFrameEl) {
      closeLoginFrame();
      setLoginMsg('已收起本机登录页');
      return;
    }
    const f = document.createElement('iframe');
    f.id = 'login-frame';
    f.className = 'login-frame';
    f.src = '/auth/loginByCoolApk';
    f.title = '酷安登录';
    loginFrameEl = f;
    loginSec.append(f);
    setLoginMsg('正在加载本机登录页…');
    f.onload = () => {
      if (loginFrameEl === f) setLoginMsg('请在下方登录页完成登录，通过滑块后会自动保存');
    };
    startLoginPoll(knownAccount);
  };

  // 粘贴整段 Cookie：自动识别 uid / username / token 并保存
  pasteBtn.onclick = async () => {
    const parsed = parseAccountCookie(pasteInput.value);
    if (!parsed.uid || !parsed.token) {
      setLoginMsg('没识别到 uid 或 token，请粘贴完整的 Cookie（形如 uid=...; username=...; token=...）');
      pasteInput.focus();
      return;
    }
    pasteBtn.disabled = true;
    pasteBtn.textContent = '保存中…';
    try {
      await saveAccount({
        uid: parsed.uid,
        username: parsed.username || status.username || '',
        token: parsed.token,
        deviceModel: inputs.deviceModel.value.trim(),
        device: '',
        ua: '',
      });
      closeModal();
      updateAccountBtn();
      showDetailPlaceholder();
      load(true);
    } catch (err) {
      setLoginMsg('保存失败：' + err.message);
    } finally {
      pasteBtn.disabled = false;
      pasteBtn.textContent = '识别并保存';
    }
  };

  save.onclick = async () => {
    const uid = inputs.uid.value.trim();
    const token = inputs.token.value.trim();
    if (!/^\d+$/.test(uid)) { manualMsg.textContent = 'uid 应为纯数字'; inputs.uid.focus(); return; }
    if (!token) { manualMsg.textContent = '请填写 token'; inputs.token.focus(); return; }
    manualMsg.textContent = '';
    save.disabled = true;
    save.textContent = '保存中…';
    try {
      await saveAccount({
        uid,
        username: inputs.username.value.trim(),
        token,
        device: inputs.device.value.trim(),
        ua: inputs.ua.value.trim(),
        deviceModel: inputs.deviceModel.value.trim(),
      });
      closeModal();
      updateAccountBtn();
      showDetailPlaceholder();
      load(true);
    } catch (err) {
      manualMsg.textContent = '保存失败：' + err.message;
      save.disabled = false;
      save.textContent = '保存并刷新';
    }
  };

  clear.onclick = async () => {
    if (!confirm('确定清除本机保存的账号凭证？')) return;
    clear.disabled = true;
    await fetch('/account', { method: 'DELETE' }).catch(() => {});
    closeLoginFrame();
    updateAccountBtn();
    openAccountModal(); // 重新渲染为未配置状态
  };

  showModal('');
  $('#modal-content').append(body);
}

let accountAvatarSeq = 0;

/** 左下角账号卡：头像 + 昵称 + 说明 */
async function updateAccountBtn() {
  const name = $('#account-name');
  const seq = ++accountAvatarSeq;
  try {
    const res = await fetch('/account');
    const st = await res.json();
    if (!st.configured) {
      name.textContent = '账号设置';
      setAccountAvatar('');
      return;
    }
    name.textContent = st.username || ('UID ' + st.uid);
    const url = await fetchAccountAvatar(st);
    if (seq !== accountAvatarSeq) return; // 期间账号已变更，丢弃旧结果
    setAccountAvatar(url);
  } catch {
    name.textContent = '账号设置';
    setAccountAvatar('');
  }
}

/** 从酷安用户空间接口取头像；失败返回空串（显示占位图标） */
async function fetchAccountAvatar(st) {
  const q = st.uid
    ? 'uid=' + encodeURIComponent(st.uid)
    : 'username=' + encodeURIComponent(st.username || '');
  try {
    const res = await fetch('/api/v6/user/space?' + q);
    const json = await res.json();
    const u = json.data || {};
    return u.userAvatar || u.userBigAvatar || u.userSmallAvatar || '';
  } catch {
    return '';
  }
}

/** url 为空或加载失败时回退到 👤 占位 */
function setAccountAvatar(url) {
  const img = $('#account-avatar');
  const fallback = $('#account-avatar-fallback');
  if (!url) {
    img.hidden = true;
    img.removeAttribute('src');
    fallback.hidden = false;
    return;
  }
  img.onload = () => { img.hidden = false; fallback.hidden = true; };
  img.onerror = () => { img.hidden = true; fallback.hidden = false; };
  img.src = proxyImg(url); // 图床有防盗链，统一走本地代理
}

function showModal(html) {
  const box = $('#modal-content');
  box.innerHTML = html;
  $('#modal').hidden = false;
  document.body.style.overflow = 'hidden';
}
function closeModal() {
  $('#modal').hidden = true;
  document.body.style.overflow = '';
  closeLoginFrame(); // 关闭弹窗时一并停掉登录轮询/iframe，避免定时器泄漏
}
// Esc 关闭弹窗（与灯箱、主题面板的行为保持一致）
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !$('#modal').hidden) closeModal();
});
/* ---------- 状态栏 / 分页 ---------- */

function setStatus(text, cls, onClick) {
  const el = $('#status');
  el.hidden = !text;
  el.textContent = text || '';
  el.className = 'status ' + (cls || '');
  el.onclick = onClick || null;
  el.style.cursor = onClick ? 'pointer' : '';
}

// 列表栏是滚动容器（页面外壳不滚动）
const listCol = $('#list-col');
function scrollListTop() { listCol.scrollTop = 0; }

/* ---------- 主流程 ---------- */

async function load(reset = true) {
  const gen = ++loadGen;
  if (reset) {
    page = 1; noMore = false; loading = false;
    $('#content').innerHTML = '';
  } else if (loading) {
    return;
  }
  if (noMore) return;
  loading = true;
  setStatus('加载中…');
  try {
    let items = await fetchItems(currentView, page);
    if (gen !== loadGen) return; // 期间视图已切换，丢弃本次结果
    renderItems(items, reset);
    const paged = currentView.kind === 'topics' || currentView.kind === 'topicFeed' ||
      currentView.kind === 'topicSearch' || currentView.kind === 'apkReplies' ||
      currentView.kind === 'productFeeds' ||
      (currentView.kind === 'list' && PAGED.has(currentView.tab));
    if (!items.length) {
      noMore = true;
      const emptyHeadline = currentView.kind === 'list' && currentView.tab === 'headline';
      if (reset && emptyHeadline) {
        setStatus('头条榜暂时为空（酷安侧偶发），点这里重试', '', () => load(true));
      } else {
        setStatus(reset ? (currentView.kind.startsWith('topic') ? '没有找到相关话题' : '暂无内容') : '— 到底了 —');
      }
    }
    else if (!paged) { noMore = true; setStatus(''); }
    else setStatus('');
    page++;
    if (currentView.kind === 'topics') renderPinnedTopics();
  } catch (err) {
    if (gen === loadGen) {
      setStatus('加载失败：' + err.message + '（该接口可能受酷安风控限制，可稍后重试）', 'error');
    }
  }
  if (gen === loadGen) loading = false;
}

$('#tabs').addEventListener('click', (e) => {
  const btn = e.target.closest('button[data-tab]');
  if (!btn) return;
  document.querySelectorAll('#tabs button').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  currentTab = btn.dataset.tab;
  currentTopicTag = null;
  if (currentTab === 'topic') currentView = { kind: 'topics' };
  else if (currentTab === 'digital') currentView = { kind: 'list', tab: 'digital', catId: 1000, catTitle: '手机', sort: 'hot_num' };
  else currentView = { kind: 'list', tab: currentTab };
  if (currentTab === 'apk') $('#apk-search-input').value = '';
  if (currentTab === 'picture') $('#pic-search-input').value = '';
  scrollListTop();
  updateToolbar();
  load(true);
});

// 顶部固定栏：返回 / 刷新 / 排序（话题动态、应用评论共用）
$('#btn-back').onclick = backToList;
$('#btn-refresh').onclick = () => load(true);
document.querySelectorAll('.tb-sort').forEach(b => {
  b.onclick = () => {
    const k = currentView.kind;
    if ((k !== 'topicFeed' && k !== 'apkReplies') || currentView.sort === b.dataset.sort) return;
    currentView.sort = b.dataset.sort;
    updateToolbar();
    scrollListTop();
    load(true);
  };
});

$('#detail-close').onclick = closeDetail;

// 话题搜索
function doTopicSearch() {
  const kw = $('#topic-search-input').value.trim();
  if (!kw) { // 清空搜索则回到热门话题列表
    currentView = { kind: 'topics' };
    updateToolbar();
    load(true);
    return;
  }
  currentView = { kind: 'topicSearch', keyword: kw };
  scrollListTop();
  updateToolbar();
  load(true);
}
$('#topic-search-btn').onclick = doTopicSearch;
$('#topic-search-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') doTopicSearch();
});

// 酷图：按标签搜索
function doPicSearch() {
  const kw = $('#pic-search-input').value.trim();
  currentView = { kind: 'list', tab: 'picture', tag: kw };
  scrollListTop();
  updateToolbar();
  load(true);
}
$('#pic-search-btn').onclick = doPicSearch;
$('#pic-search-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') doPicSearch();
});

// 应用：搜索（空关键词回到排行榜）
function doApkSearch() {
  const kw = $('#apk-search-input').value.trim();
  currentView = { kind: 'list', tab: 'apk', keyword: kw };
  scrollListTop();
  updateToolbar();
  load(true);
}
$('#apk-search-btn').onclick = doApkSearch;
$('#apk-search-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') doApkSearch();
});

// 数码：分类左右滑动 + 热度/最新排序
$('#digital-prev').onclick = () => {
  const row = $('#digital-cats');
  row.scrollBy({ left: -180, behavior: 'smooth' });
  setTimeout(updateDigitalNav, 260);
};
$('#digital-next').onclick = () => {
  const row = $('#digital-cats');
  row.scrollBy({ left: 180, behavior: 'smooth' });
  setTimeout(updateDigitalNav, 260);
};
$('#digital-cats').addEventListener('scroll', updateDigitalNav, { passive: true });
window.addEventListener('resize', updateDigitalNav);
document.querySelectorAll('#digital-sorts .sort-btn').forEach(b => {
  b.onclick = () => {
    if (currentView.kind !== 'list' || currentView.tab !== 'digital') return;
    if ((currentView.sort || 'hot_num') === b.dataset.sort) return;
    currentView.sort = b.dataset.sort;
    updateToolbar();
    scrollListTop();
    load(true);
  };
});

// 图片灯箱：点遮罩、点关闭按钮或按 Esc 关闭
$('#lightbox-close').onclick = closeLightbox;
$('#lightbox .lightbox-mask').onclick = closeLightbox;
$('#lightbox-prev').onclick = () => lightboxNav(-1);
$('#lightbox-next').onclick = () => lightboxNav(1);
document.addEventListener('keydown', (e) => {
  if ($('#lightbox').hidden) return;
  if (e.key === 'Escape') closeLightbox();
  if (e.key === 'ArrowLeft') lightboxNav(-1);
  if (e.key === 'ArrowRight') lightboxNav(1);
});

// 无限滚动 + 返回顶部：都基于列表栏内部滚动
const backtop = $('#backtop');
listCol.addEventListener('scroll', () => {
  backtop.hidden = false;
  backtop.classList.toggle('show', listCol.scrollTop > 400);
  if (!loading && !noMore &&
      listCol.scrollTop + listCol.clientHeight >= listCol.scrollHeight - 600) {
    load(false);
  }
}, { passive: true });
backtop.onclick = () => { listCol.scrollTo({ top: 0, behavior: 'smooth' }); };

showDetailPlaceholder();
updateAccountBtn();
load(true);
