/*******************************************************
 * 极简版：只用最基础 Gmail 功能的验证码查询后端
 * - 筛选：时间窗 2 分钟内 + 发件人白名单 + 标题前缀
 * - 只从标题提取最后 6 个数字
 *******************************************************/

/* ===== 你需要填写/确认的参数 ===================== */

const SHARED_SECRET = ;   // 与前端 SHARED_SECRET 相同
const TARGET_FROM = [  ]; // 白名单发件人
const SUBJECT_PREFIXES = [ 'Your ChatGPT code is' ];        // 标题必须以这些前缀开头
const WINDOW_SEC_DEFAULT = 120;                 // 时间窗秒数
const GMAIL_COARSE_RANGE = 'newer_than:10m';     // 初筛范围
const SEARCH_LIMIT = 20;                       // 一次最多取多少线程

/* ===================================================== */

/**
 * doGet
 * 用途：用于测试 WebApp 是否存活。
 * 返回：固定 JSON `{ ok: true, service: 'gmail-otp-min' }`
 * 调用关系：不会被其他函数调用；仅浏览器 GET 测试。
 */
function doGet(e) {
  return ContentService.createTextOutput(JSON.stringify({ ok: true, service: 'gmail-otp-min' }))
    .setMimeType(ContentService.MimeType.JSON);
}

/**
 * doPost
 * 用途：主入口，根据 action 区分 "verify" / "check"
 * 返回：
 *   - action=verify → 返回当前服务器时间戳
 *   - action=check  → 返回查询结果（是否找到邮件+payload）
 * 调用关系：直接由前端请求触发；内部会调用 parseJson_、assertSecret_、findCodeInWindow_
 */
function doPost(e) {
  try {
    const payload = parseJson_(e);
    assertSecret_(payload);

    const action = String(payload.action || '').toLowerCase();

    if (action === 'verify') { // 条件成立：请求参数 action=verify
      const nowSec = Math.floor(Date.now() / 1000);
      return jsonOut_({ ok: true, since_epoch: nowSec });
    }

    if (action === 'check') { // 条件成立：请求参数 action=check
      const sinceEpoch = Number(payload.since_epoch || 0);
      if (!sinceEpoch || !isFinite(sinceEpoch)) { // 条件成立：未提供合法的时间戳
        return jsonOut_({ ok: false, error: 'since_epoch is required' }, 400);
      }
      const winSec = Number(payload.window_sec || WINDOW_SEC_DEFAULT);
      const res = findCodeInWindow_(sinceEpoch, winSec);
      return jsonOut_(res);
    }

    return jsonOut_({ ok: false, error: 'Unknown action' }, 400); // 条件成立：action 既不是 verify 也不是 check
  } catch (err) {
    return jsonOut_({ ok: false, error: String(err && err.message || err) }, 500);
  }
}

/**
 * findCodeInWindow_
 * 用途：在 [sinceEpoch, sinceEpoch+winSec] 窗口内查找符合条件的邮件
 * 返回：
 *   - 找到 → { ok:true, found:true, payload:{id,subject,received_at,extracted} }
 *   - 未找到 → { ok:true, found:false }
 * 调用关系：由 doPost(action=check) 调用
 */
function findCodeInWindow_(sinceEpoch, winSec) {
  const startSec = sinceEpoch - winSec; // 条件成立时：以“查询节点”为中心，窗口起点 = 节点往前 winSec 秒
  const endSec   = sinceEpoch + winSec; // 条件成立时：窗口终点 = 节点往后 winSec 秒

  const fromPart = TARGET_FROM.length
    ? '(' + TARGET_FROM.map(a => `from:"${a.replace(/"/g, '\\"')}"`).join(' OR ') + ')'
    : '';
  const coarseQuery = [GMAIL_COARSE_RANGE, fromPart].filter(Boolean).join(' ').trim();

  const threads = GmailApp.search(coarseQuery || GMAIL_COARSE_RANGE, 0, SEARCH_LIMIT);

  let best = null;

  for (const th of threads) {
    const msgs = th.getMessages();
    for (const m of msgs) {
      const ts = Math.floor(m.getDate().getTime() / 1000);

      if (ts < startSec || ts > endSec) continue; 
      // 条件成立：邮件时间不在 [sinceEpoch - winSec, sinceEpoch + winSec] → 跳过

      if (TARGET_FROM.length && !emailInList_(m.getFrom(), TARGET_FROM)) continue; 
      // 条件成立：配置了发件人白名单，但当前邮件发件人不在其中 → 跳过

      const subject = m.getSubject() || '';
      if (!hasAnyPrefix_(subject, SUBJECT_PREFIXES)) continue; 
      // 条件成立：邮件标题没有以指定前缀开头 → 跳过

      const code = lastSixDigitsFromSubject_(subject);
      if (!code) continue; 
      // 条件成立：标题里没有足够的数字来提取 6 位验证码 → 跳过

      if (!best || ts > best.received_at) { 
        // 条件成立：目前还没记录 best，或这封邮件比之前找到的更新 → 更新 best
        best = {
          id: m.getId(),
          subject: subject,
          received_at: ts,
          extracted: code
        };
      }
    }
  }

  if (best) return { ok: true, found: true, payload: best }; // 条件成立：至少找到一封 → 返回 found=true
  return { ok: true, found: false };                         // 条件成立：没有任何符合条件的邮件 → 返回 found=false
}

/* ======================== 工具函数 ======================== */

/**
 * parseJson_
 * 用途：解析请求体 JSON
 * 返回：JS 对象
 * 调用关系：doPost 内部调用
 */
function parseJson_(e) {
  if (!e || !e.postData || !e.postData.contents) return {};
  try { return JSON.parse(e.postData.contents); }
  catch (_) { throw new Error('Invalid JSON payload'); }
}

/**
 * assertSecret_
 * 用途：检查 secret 是否正确
 * 返回：无；错误时抛出异常
 * 调用关系：doPost 内部调用
 */
function assertSecret_(payload) {
  if (!payload || payload.secret !== SHARED_SECRET) { // 条件成立：secret 缺失或不匹配
    const err = new Error('Unauthorized'); err.code = 401; throw err;
  }
}

/**
 * jsonOut_
 * 用途：把对象包装成 JSON 响应
 * 返回：ContentService 输出
 * 调用关系：doPost、findCodeInWindow_ 调用
 */
function jsonOut_(obj, code) {
  const out = ContentService.createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
  if (code) { try { out.setHeader('X-Status-Code', String(code)); } catch (_) {} }
  return out;
}

/**
 * emailInList_
 * 用途：检查邮件发件人是否在白名单中
 * 返回：true/false
 * 调用关系：findCodeInWindow_ 调用
 */
function emailInList_(fromField, list) {
  const s = (fromField || '').toLowerCase();
  return list.some(addr => {
    const a = String(addr || '').toLowerCase();
    return s === a || s.endsWith('<' + a + '>') || s.includes(' ' + a + '>') || s.includes('<' + a + '>');
  });
}

/**
 * hasAnyPrefix_
 * 用途：判断标题是否以任一前缀开头
 * 返回：true/false
 * 调用关系：findCodeInWindow_ 调用
 */
function hasAnyPrefix_(subject, prefixes) {
  const s = (subject || '').trim().toLowerCase();
  if (!prefixes || !prefixes.length) return false; // 条件成立：未设置前缀 → 永远 false
  return prefixes.some(p => s.startsWith(String(p || '').trim().toLowerCase())); 
  // 条件成立：标题开头匹配任意一个前缀 → 返回 true
}

/**
 * lastSixDigitsFromSubject_
 * 用途：提取标题里的最后 6 位数字
 * 返回：6 位字符串或 null
 * 调用关系：findCodeInWindow_ 调用
 */
function lastSixDigitsFromSubject_(subject) {
  const digits = (subject || '').replace(/\D+/g, '');
  return digits.length >= 6 ? digits.slice(-6) : null; 
  // 条件成立：标题中有 ≥6 位数字 → 返回最后 6 位，否则 null
}



/* ===================================================== */
/* ============= 本地调试辅助（仅开发期使用） ============ */
/* ===================================================== */

/**
 * makeEvent_
 * 用途：构造一个“伪造的 doPost 事件对象”，用于在 IDE 中直接调用 doPost 进行调试（模拟前端 POST）。
 * 返回：形如 { postData: { contents: 'JSON 字符串', type: 'application/json' } } 的对象
 * 调用关系：被 debugVerify() / debugCheckNow() / debugFlow() 调用
 */
function makeEvent_(obj) {
  // 这里不做 if，因为始终按传入对象构造事件
  return {
    postData: {
      contents: JSON.stringify(obj),
      type: 'application/json'
    }
  };
}

/**
 * debugVerify
 * 用途：模拟前端调用 action=verify；可在 IDE 中“运行此函数”，并在 doPost / findCodeInWindow_ 里打断点调试。
 * 返回：解析成对象的响应 JSON（便于直接在“运行结果”里看到）
 * 调用关系：独立入口；内部会调用 makeEvent_ → doPost
 */
function debugVerify() {
  const e = makeEvent_({
    action: 'verify',
    secret: SHARED_SECRET
  });
  const out = doPost(e); // 条件成立：始终走 doPost 的 verify 分支，因为 action=verify
  // TextOutput 一般可 getContent()；若你的环境不可用，可直接在调试器中查看 out 对象。
  if (out && typeof out.getContent === 'function') { // 条件成立：TextOutput 支持 getContent()
    return JSON.parse(out.getContent());
  }
  return out; // 返回原对象，便于在调试器里展开查看
}

/**
 * debugCheckNow
 * 用途：模拟前端调用 action=check；默认以“当前时刻 - 60 秒”为 since_epoch，窗口 120 秒。
 *       这样可以覆盖“最近两分钟”到达的邮件。可按需修改 sinceEpoch/windowSec 以匹配你要测的邮件。
 * 返回：解析成对象的响应 JSON
 * 调用关系：独立入口；内部会调用 makeEvent_ → doPost
 */
function debugCheckNow() {
  const sinceEpoch = Math.floor(Date.now() / 1000); // 条件成立时：以“当前时刻”为查询节点（中心点）
  const e = makeEvent_({
    action: 'check',
    since_epoch: sinceEpoch,
    window_sec: WINDOW_SEC_DEFAULT, // 可按需改，比如 120
    secret: SHARED_SECRET
  });
  const out = doPost(e); // 条件成立：始终走 doPost 的 check 分支，因为 action=check
  if (out && typeof out.getContent === 'function') { // 条件成立：TextOutput 支持 getContent()
    return JSON.parse(out.getContent());
  }
  return out;
}

/**
 * debugFlow
 * 用途：完整模拟一次“前端交互流程”：先 verify 拿服务器时间，再立刻用该时间做 check。
 * 返回：{ verify: <verify 响应对象>, check: <check 响应对象> }
 * 调用关系：独立入口；内部会调用 debugVerify() → doPost，再构造 check 事件 → doPost
 */
function debugFlow() {
  // 1) 先 verify
  const v = debugVerify(); // 条件成立：调用 verify 的模拟
  const sinceEpoch = v && v.since_epoch ? v.since_epoch : Math.floor(Date.now() / 1000);
  // 条件成立：如果 v.since_epoch 存在 → 用它；否则 → 用当前时间兜底（方便在空环境下也能跑）

  // 2) 再 check
  const e = makeEvent_({
    action: 'check',
    since_epoch: sinceEpoch,
    window_sec: WINDOW_SEC_DEFAULT, // 你也可以在这里临时加大窗口以方便调试
    secret: SHARED_SECRET
  });
  const out = doPost(e); // 条件成立：始终走 doPost 的 check 分支
  const checkObj = (out && typeof out.getContent === 'function') ? JSON.parse(out.getContent()) : out;

  // 返回组合结果，方便直接在“运行结果”里查看
  return {
    verify: v,
    check: checkObj
  };
}
