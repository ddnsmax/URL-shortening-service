export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest({ request, env, ctx });
    } catch (error) {
      return new Response(`Error: ${error?.stack || error?.message || error}`, {
        status: 500,
        headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store, no-cache, must-revalidate' },
      });
    }
  },
  async scheduled(controller, env, ctx) {
    const jobs = [cleanupExpiredPendingD1(env)];
    if (env && env.EDGEONE_CLEANUP_URL) jobs.push(triggerRemotePendingCleanup(env.EDGEONE_CLEANUP_URL, env.CLEANUP_TOKEN));
    if (env && env.PAGES_CLEANUP_URL) jobs.push(triggerRemotePendingCleanup(env.PAGES_CLEANUP_URL, env.CLEANUP_TOKEN));
    const results = await Promise.allSettled(jobs);
    const errors = results.filter(result => result.status === 'rejected').map(result => result.reason);
    if (errors.length) throw new Error(errors.map(error => String(error && (error.stack || error.message) || error)).join(' | '));
  }
};

function resolveD1Store(context) {
  const envDb = context && context.env && context.env.DB;
  if (envDb) return createD1Store(envDb);
  const altDb = context && context.env && context.env.duanlianjie;
  if (altDb) return createD1Store(altDb);
  const globalDb = globalThis && globalThis.DB;
  if (globalDb) return createD1Store(globalDb);
  try { if (typeof DB !== 'undefined' && DB) return createD1Store(DB); } catch (e) {}
  return null;
}

function createD1Store(db) {
  async function getSystemConfig() {
    const row = await db.prepare('SELECT value FROM system_config WHERE key = ?').bind('system_config').first();
    return row ? row.value : null;
  }

  async function putSystemConfig(value) {
    await db.prepare('INSERT INTO system_config (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at').bind('system_config', value, Date.now()).run();
  }

  async function getConfigValue(key) {
    const row = await db.prepare('SELECT value FROM system_config WHERE key = ?').bind(key).first();
    return row ? row.value : null;
  }

  async function putConfigValue(key, value) {
    await db.prepare('INSERT INTO system_config (key, value, updated_at) VALUES (?, ?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at').bind(key, value, Date.now()).run();
  }

  async function deleteConfigValue(key) {
    await db.prepare('DELETE FROM system_config WHERE key = ?').bind(key).run();
  }

  async function getMetaLinkKeys() {
    const result = await db.prepare('SELECT short FROM links ORDER BY created_at ASC').all();
    const rows = result && result.results ? result.results : [];
    return JSON.stringify(rows.map(row => row.short));
  }

  function rowToLink(row) {
    if (!row) return null;
    const data = {
      longUrl: row.long_url,
      status: row.status,
      createdAt: Number(row.created_at),
      visits: Number(row.visits || 0),
      lastVisitedAt: Number(row.last_visited_at || row.created_at),
      isPermanent: Number(row.is_permanent || 0) === 1
    };
    if (row.approved_at !== null && row.approved_at !== undefined) data.approvedAt = Number(row.approved_at);
    return JSON.stringify(data);
  }

  async function getLink(short) {
    const row = await db.prepare('SELECT short, long_url, status, created_at, approved_at, visits, last_visited_at, is_permanent FROM links WHERE short = ?').bind(short).first();
    return rowToLink(row);
  }

  async function putLink(short, value) {
    const data = JSON.parse(value);
    const createdAt = Number(data.createdAt || Date.now());
    const approvedAt = data.approvedAt === undefined || data.approvedAt === null ? null : Number(data.approvedAt);
    const visits = Number(data.visits || 0);
    const lastVisitedAt = Number(data.lastVisitedAt || createdAt);
    const isPermanent = data.isPermanent ? 1 : 0;
    await db.prepare('INSERT INTO links (short, long_url, status, created_at, approved_at, visits, last_visited_at, is_permanent) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(short) DO UPDATE SET long_url = excluded.long_url, status = excluded.status, created_at = excluded.created_at, approved_at = excluded.approved_at, visits = excluded.visits, last_visited_at = excluded.last_visited_at, is_permanent = excluded.is_permanent').bind(short, data.longUrl, data.status, createdAt, approvedAt, visits, lastVisitedAt, isPermanent).run();
  }

  async function deleteLink(short) {
    await db.prepare('DELETE FROM links WHERE short = ?').bind(short).run();
  }

  async function updateApprovedLinkTargetDirect(short, longUrl) {
    const result = await db.prepare('UPDATE links SET long_url = ? WHERE short = ? AND status = ?').bind(longUrl, short, 'approved').run();
    return Number(result && result.meta && result.meta.changes || 0) > 0;
  }

  async function getSession(type, token) {
    const row = await db.prepare('SELECT expire FROM sessions WHERE type = ? AND token = ?').bind(type, token).first();
    if (!row) return null;
    const expire = Number(row.expire);
    if (expire <= Date.now()) {
      await db.prepare('DELETE FROM sessions WHERE type = ? AND token = ?').bind(type, token).run();
      return null;
    }
    return JSON.stringify({ expire });
  }

  async function putSession(type, token, value) {
    const data = JSON.parse(value);
    const expire = Number(data.expire || 0);
    await db.prepare('INSERT INTO sessions (type, token, expire, created_at) VALUES (?, ?, ?, ?) ON CONFLICT(type, token) DO UPDATE SET expire = excluded.expire').bind(type, token, expire, Date.now()).run();
  }

  async function deleteSession(type, token) {
    await db.prepare('DELETE FROM sessions WHERE type = ? AND token = ?').bind(type, token).run();
  }

  return {
    async get(key) {
      if (key === 'system_config') return await getSystemConfig();
      if (key === 'meta_link_keys') return await getMetaLinkKeys();
      if (key.startsWith('short_link:')) return await getLink(key.substring('short_link:'.length));
      if (key.startsWith('session:')) return await getSession('admin', key.substring('session:'.length));
      if (key.startsWith('front_session:')) return await getSession('front', key.substring('front_session:'.length));
      if (key.startsWith('edge_session:')) return await getSession('edge', key.substring('edge_session:'.length));
      return null;
    },
    async put(key, value) {
      if (key === 'system_config') return await putSystemConfig(value);
      if (key === 'meta_link_keys') return;
      if (key.startsWith('short_link:')) return await putLink(key.substring('short_link:'.length), value);
      if (key.startsWith('session:')) return await putSession('admin', key.substring('session:'.length), value);
      if (key.startsWith('front_session:')) return await putSession('front', key.substring('front_session:'.length), value);
      if (key.startsWith('edge_session:')) return await putSession('edge', key.substring('edge_session:'.length), value);
    },
    async delete(key) {
      if (key === 'system_config') return await db.prepare('DELETE FROM system_config WHERE key = ?').bind('system_config').run();
      if (key === 'meta_link_keys') return;
      if (key.startsWith('short_link:')) return await deleteLink(key.substring('short_link:'.length));
      if (key.startsWith('session:')) return await deleteSession('admin', key.substring('session:'.length));
      if (key.startsWith('front_session:')) return await deleteSession('front', key.substring('front_session:'.length));
      if (key.startsWith('edge_session:')) return await deleteSession('edge', key.substring('edge_session:'.length));
    },
    updateApprovedLinkTarget: updateApprovedLinkTargetDirect
  };
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/[&<>'"]/g, match => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[match]));
}

function normalizeTargetUrl(value) {
  const candidate = String(value ?? '').trim();
  if (!candidate) throw new Error('目标地址不能为空');
  let parsed;
  try {
    parsed = new URL(candidate);
  } catch (error) {
    throw new Error('目标地址必须是有效的 HTTP 或 HTTPS 地址');
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new Error('目标地址必须是有效的 HTTP 或 HTTPS 地址');
  return parsed.href;
}

async function updateApprovedLinkTarget(store, short, longUrl) {
  if (typeof store.updateApprovedLinkTarget === 'function') return await store.updateApprovedLinkTarget(short, longUrl);
  const key = 'short_link:' + short;
  const value = await store.get(key);
  if (!value) return false;
  const link = JSON.parse(value);
  if (link.status !== 'approved') return false;
  link.longUrl = longUrl;
  await store.put(key, JSON.stringify(link));
  return true;
}

function base32tohex(base32) {
  let base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  let hex = "";
  for (let i = 0; i < base32.length; i++) {
    let val = base32chars.indexOf(base32.charAt(i).toUpperCase());
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  for (let i = 0; i + 4 <= bits.length; i += 4) {
    let chunk = bits.substr(i, 4);
    hex = hex + parseInt(chunk, 2).toString(16);
  }
  return hex;
}

async function verifyTOTP(secret, code) {
  if (!secret || !code || code.length !== 6) return false;
  try {
    const keyHex = base32tohex(secret);
    const keyBytes = new Uint8Array(keyHex.match(/[\da-f]{2}/gi).map(h => parseInt(h, 16)));
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    const epoch = Math.floor(Date.now() / 1000);
    for (let i = -1; i <= 1; i++) {
      const time = Math.floor(epoch / 30) + i;
      const timeBytes = new Uint8Array(8);
      let temp = time;
      for (let j = 7; j >= 0; j--) {
        timeBytes[j] = temp & 255;
        temp = temp >> 8;
      }
      const signature = await crypto.subtle.sign('HMAC', key, timeBytes);
      const hash = new Uint8Array(signature);
      const offset = hash[hash.length - 1] & 0xf;
      const binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
      const otp = (binary % 1000000).toString().padStart(6, '0');
      if (otp === code) return true;
    }
  } catch (e) { return false; }
  return false;
}

function generateBase32Secret() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let secret = '';
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  for (let i = 0; i < 16; i++) secret += chars[bytes[i] % 32];
  return secret;
}


function normalizeCleanupDays(value, fallback = 30) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(3650, Math.max(1, parsed));
}

function normalizeCleanupUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  const url = new URL(raw);
  const suffix = '/api/internal/pending-cleanup';
  if (!url.pathname.endsWith(suffix)) url.pathname = url.pathname.replace(/\/+$/, '') + suffix;
  url.search = '';
  url.hash = '';
  return url.toString();
}

async function triggerRemotePendingCleanup(value, token) {
  const url = normalizeCleanupUrl(value);
  const cleanupToken = String(token || '').trim();
  if (!url || !cleanupToken) throw new Error('远程清理地址或 CLEANUP_TOKEN 未配置');
  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': 'Bearer ' + cleanupToken,
      'Content-Type': 'application/json'
    },
    body: '{}'
  });
  const body = await response.text();
  if (!response.ok) throw new Error(url + '：' + response.status + ' ' + body);
  return body;
}

async function cleanupExpiredPendingD1(env) {
  const db = env && (env.DB || env.duanlianjie);
  if (!db) return;
  const row = await db.prepare('SELECT value FROM system_config WHERE key = ?').bind('system_config').first();
  if (!row || !row.value) return;
  let config = null;
  try { config = JSON.parse(row.value); } catch (e) { return; }
  if (!config || config.pending_auto_clean_enabled !== 1) return;
  const days = normalizeCleanupDays(config.pending_auto_clean_days, 30);
  const cutoff = Date.now() - days * 86400000;
  await db.prepare("DELETE FROM links WHERE status = 'pending' AND created_at <= ?").bind(cutoff).run();
}

async function handleRequest(context) {
  const { request, ctx } = context;
  const kv = resolveD1Store(context);
  const url = new URL(request.url);
  const path = url.pathname;
  const currentHost = url.host;

  if (!kv) return textResponse('未找到名为 DB 的 D1 数据库绑定', 500);

  let configStr = await kv.get('system_config');
  let config = configStr ? JSON.parse(configStr) : null;

  if (!config) {
    if (path === '/api/init' && request.method === 'POST') {
      const data = await request.json();
      if (!data.adminPath || !data.username || !data.password) return textResponse('error', 400);
      let aPath = data.adminPath.startsWith('/') ? data.adminPath : '/' + data.adminPath;
      await kv.put('system_config', JSON.stringify({
        adminPath: aPath,
        username: data.username,
        password: data.password,
        audit_enabled: 1,
        auto_clean_enabled: 0,
        auto_clean_days: 30,
        pending_auto_clean_enabled: 0,
        pending_auto_clean_days: 30,
        otp_enabled: 0,
        otp_secret: '',
        announce_enabled: 0,
        announcement: '欢迎使用极简短链接系统。',
        icp_number: '',
        icp_link: '',
        psb_number: '',
        psb_link: '',
        frontend_pwd_enabled: 0,
        frontend_pwd: '',
        wx_qq_mask_enabled: 1
      }));
      await kv.put('meta_link_keys', JSON.stringify([]));
      return textResponse('ok', 200);
    }
    return htmlResponse(getInitHtml());
  }

  let isFrontAuth = false;
  if (config && config.frontend_pwd_enabled === 1 && config.frontend_pwd) {
    const cookie = request.headers.get('Cookie') || '';
    const match = cookie.match(/(^| )front_auth=([^;]+)/);
    if (match) {
      const sessionData = await kv.get('front_session:' + match[2]);
      if (sessionData) {
        const parsed = JSON.parse(sessionData);
        if (parsed.expire > Date.now()) isFrontAuth = true;
      }
    }
  } else {
    isFrontAuth = true;
  }

  if (path === '/api/front_login' && request.method === 'POST') {
    await new Promise(r => setTimeout(r, Math.floor(Math.random() * 300) + 200));
    const data = await request.json();
    if (data.pwd === config.frontend_pwd) {
      const token = createRandomToken();
      await kv.put('front_session:' + token, JSON.stringify({ expire: Date.now() + 604800000 }));
      return new Response(JSON.stringify({ status: 'ok' }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Set-Cookie': `front_auth=${token}; HttpOnly; Path=/; Max-Age=604800; SameSite=Strict`,
          'Cache-Control': 'no-store, no-cache, must-revalidate'
        }
      });
    }
    return jsonResponse({ status: 'error' }, 403);
  }

  if (path === config.adminPath || path.startsWith(config.adminPath + '/')) {
    const cookie = request.headers.get('Cookie') || '';
    const sessionMatch = cookie.match(/(^| )admin_session=([^;]+)/);
    const sessionToken = sessionMatch ? sessionMatch[2] : null;
    let isAuthenticated = false;

    if (sessionToken) {
      const sessionData = await kv.get('session:' + sessionToken);
      if (sessionData) {
        const parsed = JSON.parse(sessionData);
        if (parsed.expire > Date.now()) isAuthenticated = true;
      }
    }

    if (path === config.adminPath + '/logout' && request.method === 'POST') {
      return new Response('ok', {
        status: 200,
        headers: { 
          'Set-Cookie': `admin_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict`,
          'Cache-Control': 'no-store, no-cache, must-revalidate'
        }
      });
    }

    if (path === config.adminPath + '/login' && request.method === 'POST') {
      await new Promise(r => setTimeout(r, Math.floor(Math.random() * 300) + 500));
      const data = await request.json();
      if (data.username === config.username && data.password === config.password) {
        if (config.otp_enabled === 1 && config.otp_secret) {
          if (!data.otp) return jsonResponse({ status: 'require_otp' }, 200);
          const isValid = await verifyTOTP(config.otp_secret, data.otp);
          if (!isValid) return jsonResponse({ status: 'error', msg: 'OTP动态验证码错误' }, 403);
        }
        const token = createRandomToken();
        await kv.put('session:' + token, JSON.stringify({ expire: Date.now() + 86400000 }));
        return new Response(JSON.stringify({ status: 'ok' }), {
          status: 200,
          headers: { 
            'Content-Type': 'application/json; charset=utf-8',
            'Set-Cookie': `admin_session=${token}; HttpOnly; Path=/; Max-Age=86400; SameSite=Strict`,
            'Cache-Control': 'no-store, no-cache, must-revalidate'
          }
        });
      }
      return jsonResponse({ status: 'error', msg: '账密错误' }, 403);
    }

    if (!isAuthenticated) return htmlResponse(getLoginHtml(config.adminPath));

    const adminSuffix = path.slice(config.adminPath.length);
    if (request.method === 'GET' && adminSuffix === '/api/basic/data') return jsonResponse({ config: { ...config, password: '', otp_secret: '' } });
    if (request.method === 'GET' && adminSuffix === '/api/links/data') return jsonResponse({ links: await loadAdminLinks(kv, config, 'approved') });
    if (request.method === 'GET' && adminSuffix === '/api/audit/data') return jsonResponse({ links: await loadAdminLinks(kv, config, 'pending') });
    if (request.method === 'GET' && adminSuffix === '/api/announcement/data') return jsonResponse({ announce_enabled: config.announce_enabled, announcement: config.announcement || '' });
    if (request.method === 'GET' && adminSuffix === '/api/filing/data') return jsonResponse({ icp_number: config.icp_number || '', icp_link: config.icp_link || '', psb_number: config.psb_number || '', psb_link: config.psb_link || '' });
    const actionPage = ({ '/api/basic/action': 'basic', '/api/links/action': 'links', '/api/audit/action': 'audit', '/api/announcement/action': 'announcement', '/api/filing/action': 'filing' })[adminSuffix] || '';
    const isActionRequest = Boolean(actionPage);
    if (isActionRequest && request.method === 'POST') {
      const reqData = await request.json();
      const action = reqData.action;
      const payload = reqData.payload || {};
      const allowedActions = {
        basic: ['update_basic_config', 'update_front_pwd_config', 'update_wx_qq_mask_config', 'update_clean_config', 'generate_otp_secret', 'enable_otp', 'disable_otp'],
        links: ['delete', 'batch_delete', 'toggle_permanent', 'update_target_url'],
        audit: ['approve', 'reject', 'batch_reject'],
        announcement: ['update_announcement'],
        filing: ['update_beian_config']
      };
      if (actionPage && !(allowedActions[actionPage] || []).includes(action)) return textResponse('Forbidden', 403);

      if (action === 'update_basic_config') {
        config.adminPath = payload.adminPath.startsWith('/') ? payload.adminPath : '/' + payload.adminPath;
        config.username = payload.username;
        if (payload.password) config.password = payload.password;
        config.audit_enabled = payload.audit_enabled ? 1 : 0;
        await kv.put('system_config', JSON.stringify(config));
      }
      else if (action === 'update_front_pwd_config') {
        config.frontend_pwd_enabled = payload.enabled ? 1 : 0;
        config.frontend_pwd = payload.pwd || '';
        await kv.put('system_config', JSON.stringify(config));
      }
      else if (action === 'update_wx_qq_mask_config') {
        config.wx_qq_mask_enabled = payload.enabled ? 1 : 0;
        await kv.put('system_config', JSON.stringify(config));
      }
      else if (action === 'update_clean_config') {
        config.auto_clean_enabled = payload.auto_clean_enabled ? 1 : 0;
        config.auto_clean_days = normalizeCleanupDays(payload.auto_clean_days, 30);
        config.pending_auto_clean_enabled = payload.pending_auto_clean_enabled ? 1 : 0;
        config.pending_auto_clean_days = normalizeCleanupDays(payload.pending_auto_clean_days, 30);
        await kv.put('system_config', JSON.stringify(config));
      }
      else if (action === 'update_announcement') {
        config.announce_enabled = payload.enabled ? 1 : 0;
        config.announcement = payload.announcement;
        await kv.put('system_config', JSON.stringify(config));
      } 
      else if (action === 'update_beian_config') {
        config.icp_number = payload.icp_number || '';
        config.icp_link = payload.icp_link || '';
        config.psb_number = payload.psb_number || '';
        config.psb_link = payload.psb_link || '';
        await kv.put('system_config', JSON.stringify(config));
      }
      else if (action === 'generate_otp_secret') {
        return jsonResponse({ secret: generateBase32Secret() }, 200);
      }
      else if (action === 'enable_otp') {
        if (payload.password !== config.password) return textResponse('管理员密码验证失败', 403);
        const isValid = await verifyTOTP(payload.secret, payload.code);
        if (!isValid) return textResponse('OTP动态验证码错误，无法开启', 403);
        config.otp_enabled = 1;
        config.otp_secret = payload.secret;
        await kv.put('system_config', JSON.stringify(config));
      }
      else if (action === 'disable_otp') {
        if (payload.password !== config.password) return textResponse('管理员密码验证失败', 403);
        config.otp_enabled = 0;
        config.otp_secret = '';
        await kv.put('system_config', JSON.stringify(config));
      }
      else if (action === 'update_target_url') {
        const short = String(payload.short || '').trim();
        if (!short) return textResponse('短码不能为空', 400);
        let longUrl;
        try {
          longUrl = normalizeTargetUrl(payload.longUrl);
        } catch (error) {
          return textResponse(error.message, 400);
        }
        const updated = await updateApprovedLinkTarget(kv, short, longUrl);
        if (!updated) return textResponse('链接不存在或未通过审核', 404);
        return jsonResponse({ status: 'ok', short, longUrl }, 200);
      }
      else if (action === 'approve') {
        const linkStr = await kv.get('short_link:' + payload.short);
        if (linkStr) {
          let linkData = JSON.parse(linkStr);
          linkData.status = 'approved';
          linkData.approvedAt = Date.now();
          await kv.put('short_link:' + payload.short, JSON.stringify(linkData));
        }
      } 
      else if (action === 'reject' || action === 'delete') {
        await kv.delete('short_link:' + payload.short);
        await removeLinkKey(kv, payload.short);
      }
      else if (action === 'batch_delete' || action === 'batch_reject') {
        for (let short of payload.shorts) {
          await kv.delete('short_link:' + short);
          await removeLinkKey(kv, short);
        }
      }
      else if (action === 'toggle_permanent') {
        const linkStr = await kv.get('short_link:' + payload.short);
        if (linkStr) {
          let linkData = JSON.parse(linkStr);
          linkData.isPermanent = !linkData.isPermanent;
          await kv.put('short_link:' + payload.short, JSON.stringify(linkData));
        }
      }
      return textResponse('ok', 200);
    }

    const adminPage = resolveAdminPage(path, config.adminPath);
    if (adminPage) {
      const links = adminPage === 'links' ? await loadAdminLinks(kv, config, 'approved') : adminPage === 'audit' ? await loadAdminLinks(kv, config, 'pending') : [];
      return htmlResponse(getAdminPageHtml({ page: adminPage, adminPath: config.adminPath, host: currentHost, config: { ...config, password: '', otp_secret: '' }, links }));
    }
    if (path === config.adminPath || path === config.adminPath + '/') return locationResponse(config.adminPath + '/basic');
    return textResponse('Not Found', 404);
  }

  if (path === '/api/generate' && request.method === 'POST') {
    if (!isFrontAuth) return textResponse('Forbidden', 403);
    const data = await request.json();
    const longUrl = data.longUrl;
    const customShort = data.customShort;
    if (!longUrl) return textResponse('error', 400);

    let short = customShort ? customShort.trim() : null;
    if (short) {
      if (short.startsWith('/')) short = short.substring(1);
      if ('/' + short === config.adminPath || await kv.get('short_link:' + short)) {
        return textResponse('已被占用 / 已存在', 400);
      }
    } else {
      const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      let len = 6, found = false;
      while (len <= 12 && !found) {
        for (let i = 0; i < 5; i++) {
          let res = '';
          for (let j = 0; j < len; j++) res += chars[Math.floor(Math.random() * chars.length)];
          if ('/' + res !== config.adminPath && !(await kv.get('short_link:' + res))) {
            short = res; found = true; break;
          }
        }
        len++;
      }
      if (!short) return textResponse('生成失败，请重试', 500);
    }

    const isAudit = config.audit_enabled !== undefined ? Number(config.audit_enabled) : 1;
    const status = isAudit ? 'pending' : 'approved';
    let newLinkData = { longUrl, status, createdAt: Date.now(), visits: 0, lastVisitedAt: Date.now() };
    if (!isAudit) {
      newLinkData.approvedAt = Date.now();
    }
    
    await kv.put('short_link:' + short, JSON.stringify(newLinkData));
    await addLinkKey(kv, short);
    
    return jsonResponse({ short, audit: isAudit }, 200);
  }

  if (path === '/') {
    if (!isFrontAuth) return htmlResponse(getFrontLoginHtml());
    return htmlResponse(getFrontendHtml(config));
  }

  const shortKey = path.substring(1);
  if (shortKey) {
    const linkStr = await kv.get('short_link:' + shortKey);
    if (linkStr) {
      let link = JSON.parse(linkStr);
      if (link.status === 'approved') {
        link.visits = (link.visits || 0) + 1;
        link.lastVisitedAt = Date.now();
        await kv.put('short_link:' + shortKey, JSON.stringify(link));
        return redirect(link.longUrl, config);
      }
    }
  }

  return redirect('/', config);
}

async function loadAdminLinks(kv, config, status = '') {
  const keys = await getLinkKeys(kv);
  const links = [];
  const remove = [];
  const now = Date.now();
  const autoCleanEnabled = config.auto_clean_enabled === 1;
  const cleanMs = (config.auto_clean_days || 30) * 86400000;
  const pendingCleanEnabled = config.pending_auto_clean_enabled === 1;
  const pendingCutoff = now - normalizeCleanupDays(config.pending_auto_clean_days, 30) * 86400000;
  for (let offset = 0; offset < keys.length; offset += 5) {
    const part = keys.slice(offset, offset + 5);
    const values = await Promise.all(part.map(key => kv.get('short_link:' + key)));
    for (let index = 0; index < part.length; index++) {
      const value = values[index];
      if (!value) continue;
      try {
        const data = JSON.parse(value);
        if (pendingCleanEnabled && data.status === 'pending' && Number(data.createdAt) > 0 && Number(data.createdAt) <= pendingCutoff) {
          remove.push(part[index]);
          continue;
        }
        if (autoCleanEnabled && data.status === 'approved' && !data.isPermanent && now - (data.lastVisitedAt || data.createdAt) > cleanMs) {
          remove.push(part[index]);
          continue;
        }
        if (!status || data.status === status) links.push({ short: part[index], ...data });
      } catch (e) {}
    }
  }
  for (let offset = 0; offset < remove.length; offset += 5) await Promise.all(remove.slice(offset, offset + 5).map(key => kv.delete('short_link:' + key)));
  if (remove.length) await kv.put('meta_link_keys', JSON.stringify(keys.filter(key => !remove.includes(key))));
  links.sort((a, b) => Number(b.createdAt || 0) - Number(a.createdAt || 0));
  return links;
}

async function getLinkKeys(kv) {
  const keysStr = await kv.get('meta_link_keys');
  return keysStr ? JSON.parse(keysStr) : [];
}

async function addLinkKey(kv, key) {
  const keys = await getLinkKeys(kv);
  if (!keys.includes(key)) {
    keys.push(key);
    await kv.put('meta_link_keys', JSON.stringify(keys));
  }
}

async function removeLinkKey(kv, key) {
  let keys = await getLinkKeys(kv);
  keys = keys.filter(k => k !== key);
  await kv.put('meta_link_keys', JSON.stringify(keys));
}

function createRandomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function locationResponse(location, status = 302) {
  return new Response(null, {
    status,
    headers: {
      'Location': location,
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0'
    }
  });
}

function htmlResponse(html, status = 200) {
  return new Response(html, { 
    status, 
    headers: { 
      'Content-Type': 'text/html; charset=utf-8', 
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0', 
      'Pragma': 'no-cache', 
      'Expires': '0' 
    } 
  });
}

function textResponse(text, status = 200) {
  return new Response(String(text ?? ''), { 
    status, 
    headers: { 
      'Content-Type': 'text/plain; charset=utf-8', 
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0', 
      'Pragma': 'no-cache', 
      'Expires': '0' 
    } 
  });
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), { 
    status, 
    headers: { 
      'Content-Type': 'application/json; charset=utf-8', 
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0', 
      'Pragma': 'no-cache', 
      'Expires': '0' 
    } 
  });
}

function redirect(location, config) {
  const psbIcon = `<img src="https://beian.mps.gov.cn/web/assets/logo01.6189a29f.png" style="width:16px;height:16px;vertical-align:middle;margin-right:4px;margin-top:-2px;" alt="">`;
  const icp = config && config.icp_number ? `<a href="${escapeHtml(config.icp_link)}" target="_blank" style="display:flex;align-items:center;">${escapeHtml(config.icp_number)}</a>` : '';
  const psb = config && config.psb_number ? `<a href="${escapeHtml(config.psb_link)}" target="_blank" style="display:flex;align-items:center;">${psbIcon}${escapeHtml(config.psb_number)}</a>` : '';
  let footerHtml = '';
  if (icp || psb) {
    footerHtml = `<div class="footer-beian">${icp}${psb}</div>`;
  }

  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="referrer" content="no-referrer">
  <meta http-equiv="Cache-Control" content="no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0">
  <meta http-equiv="Pragma" content="no-cache">
  <meta http-equiv="Expires" content="0">
  <title></title>
  <style>
    body { margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #fff; display: flex; flex-direction: column; min-height: 100vh; overflow: hidden; }
  </style>
</head>
<body>
  <div id="app"></div>
  <script>
    var target = "${location}";
    var ua = navigator.userAgent.toLowerCase();
    var isWx = /micromessenger|wxwork/i.test(ua);
    var isQQ = /qq|tencent|qzone|mqqbrowser/i.test(ua);
    var isApple = /iphone|ipad|ipod|macintosh|mac os x/i.test(ua);
    var showMask = ${config && config.wx_qq_mask_enabled !== undefined ? config.wx_qq_mask_enabled : 1};
    
    if ((isWx || isQQ) && showMask === 1) {
      document.title = "安全访问提示";
      document.body.style.background = "#333";
      
      var iconHtml = isApple 
        ? '<svg viewBox="0 0 100 100" style="width:100%;height:100%;"><circle cx="50" cy="50" r="50" fill="#007AFF"/><circle cx="50" cy="50" r="42" fill="none" stroke="#ffffff" stroke-dasharray="2 6.5" stroke-width="4"/><polygon points="44,56 80,20 56,44" fill="#FF3B30"/><polygon points="44,56 20,80 56,44" fill="#FFFFFF"/><circle cx="50" cy="50" r="4" fill="#cccccc"/></svg>'
        : '<svg viewBox="0 0 24 24" fill="#10b981" style="width:100%;height:100%;"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 17.93c-3.95-.49-7-3.85-7-7.93 0-.62.08-1.21.21-1.79L9 15v1c0 1.1.9 2 2 2v1.93zm6.9-2.54c-.26-.81-1-1.39-1.9-1.39h-1v-3c0-.55-.45-1-1-1H8v-2h2c.55 0 1-.45 1-1V7h2c1.1 0 2-.9 2-2v-.41c2.93 1.19 5 4.06 5 7.41 0 2.08-.8 3.97-2.1 5.39z"/></svg>';
        
      var footerHtml = \`${footerHtml}\`;
      
      document.getElementById('app').innerHTML = \`
        <style>
          .center-container { position: absolute; top: 40%; left: 50%; transform: translate(-50%, -50%); display: flex; flex-direction: column; align-items: center; z-index: 9999; width: 100%; }
          .icon-box { width: 80px; height: 80px; background: white; border-radius: 50%; padding: 4px; box-sizing: border-box; box-shadow: 0 4px 12px rgba(0,0,0,0.3); margin-bottom: 25px; }
          .mask-text { color: white; text-align: center; font-size: 18px; line-height: 1.8; font-weight: bold; white-space: nowrap; }
          .mask-text span { color: #ffeb3b; font-size: 24px; vertical-align: middle; margin: 0 4px; }
          .path-anim { stroke-dasharray: 8, 8; animation: march 1s linear infinite; }
          @keyframes march { from { stroke-dashoffset: 16; } to { stroke-dashoffset: 0; } }
          .footer-beian { position: fixed; bottom: 20px; left: 0; width: 100%; display: flex; justify-content: center; gap: 20px; font-size: 13px; z-index: 10000; }
          .footer-beian a { color: #9ca3af; text-decoration: none; transition: color 0.2s; display: flex; align-items: center; }
          .footer-beian a:hover { color: #d1d5db; }
        </style>
        
        <div class="center-container">
          <div class="icon-box" id="browser-icon">
            \${iconHtml}
          </div>
          <div class="mask-text">
            点击右上角 <span>···</span> 选择浏览器打开
          </div>
        </div>

        <svg id="arrow-svg" style="position: fixed; top: 0; left: 0; width: 100%; height: 100%; z-index: 9999; pointer-events: none;">
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="5" refY="5" markerWidth="6" markerHeight="6" orient="auto">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="white" />
            </marker>
          </defs>
          <path id="arrow-path" fill="none" stroke="white" stroke-width="3" class="path-anim" marker-end="url(#arrow)" />
        </svg>
        
        \${footerHtml}
      \`;
      
      function drawCurve() {
        var icon = document.getElementById('browser-icon');
        var path = document.getElementById('arrow-path');
        if(!icon || !path) return;
        var rect = icon.getBoundingClientRect();
        var startX = rect.right;
        var startY = rect.top + rect.height / 2;
        var endX = window.innerWidth - 25;
        var endY = 40;
        var cpX = endX;
        var cpY = startY;
        path.setAttribute('d', 'M ' + startX + ' ' + startY + ' Q ' + cpX + ' ' + cpY + ' ' + endX + ' ' + endY);
      }
      setTimeout(drawCurve, 50);
      window.addEventListener('resize', drawCurve);
    } else {
      window.location.replace(target);
    }
  <\/script>
</body>
</html>`;
  return htmlResponse(html);
}

function getFavicon() {
  return `<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%233b82f6' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><path d='M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71'/><path d='M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71'/></svg>">`;
}

function getCommonCss() {
  return `body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;background-color:#111827;color:#f3f4f6;display:flex;flex-direction:column;min-height:100vh}*{box-sizing:border-box}.container{max-width:850px;width:100%;margin:8vh auto 40px auto;padding:40px;background:#1f2937;border-radius:16px;box-shadow:0 20px 25px -5px rgba(0,0,0,0.5),0 10px 10px -5px rgba(0,0,0,0.3)}h2{text-align:center;margin-bottom:30px;color:#f9fafb;font-size:28px}.input-group{margin-bottom:24px}label{display:block;margin-bottom:10px;font-weight:500;font-size:15px;color:#d1d5db}input[type="text"],input[type="password"]{width:100%;padding:14px;border:1px solid #4b5563;border-radius:8px;font-size:16px;outline:none;transition:border .2s;color:#f3f4f6;background-color:#374151}input[type="text"]:focus,input[type="password"]:focus{border-color:#60a5fa}button{width:100%;padding:14px;background-color:#3b82f6;color:#fff;border:none;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer;transition:background .2s}button:hover{background-color:#2563eb}.msg{padding:12px;margin-bottom:24px;border-radius:8px;display:none;text-align:center;font-size:15px}.msg.error{background:#7f1d1d;color:#fecaca;border:1px solid #991b1b;display:block}.msg.success{background:#064e3b;color:#a7f3d0;border:1px solid #065f46;display:block}@media (max-width:768px){.container{padding:20px;margin:4vh auto 20px auto;width:90%}h2{font-size:24px;margin-bottom:20px}}`;
}

function getInitHtml() {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><meta name="robots" content="noindex, nofollow">${getFavicon()}<title>系统初始化</title><style>${getCommonCss()}</style></head><body><div class="container"><h2>短链接系统 - 首次部署初始化</h2><div id="msg" class="msg"></div><div class="input-group"><label>管理员 URL 路径 (例: /myadmin)</label><input type="text" id="adminPath" placeholder="/admin" value="/admin"></div><div class="input-group"><label>管理员账户</label><input type="text" id="username" placeholder="设置账号"></div><div class="input-group"><label>管理员密码</label><input type="password" id="password" placeholder="设置密码"></div><button onclick="initSys()">初始化系统</button></div><script>async function initSys(){const a=document.getElementById('adminPath').value;const u=document.getElementById('username').value;const p=document.getElementById('password').value;const m=document.getElementById('msg');if(!a||!u||!p){m.className='msg error';m.innerText='请填写完整信息';return;}const r=await fetch('/api/init',{method:'POST',body:JSON.stringify({adminPath:a,username:u,password:p})});if(r.ok){window.location.href=a.startsWith('/')?a:'/'+a;}else{m.className='msg error';m.innerText='初始化失败';}}</script></body></html>`;
}

function getLoginHtml(path) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><meta name="robots" content="noindex, nofollow">${getFavicon()}<title>管理员登录</title><style>${getCommonCss()}</style></head><body><div class="container" style="max-width:500px"><h2>后台登录</h2><div id="msg" class="msg" style="display:none"></div><div id="step1"><div class="input-group"><label>账户</label><input type="text" id="username"></div><div class="input-group"><label>密码</label><input type="password" id="password"></div><button onclick="loginStep1()">下一步</button></div><div id="step2" style="display:none"><div class="input-group"><label>动态验证码 (OTP)</label><input type="text" id="otpCode" placeholder="输入 6 位动态码" autocomplete="off" style="text-align:center;font-size:24px;letter-spacing:8px;font-weight:bold" oninput="if(this.value.length===6) loginStep2()"></div><button onclick="loginStep2()">验证并登录</button><div style="text-align:center;margin-top:20px"><a href="javascript:void(0)" onclick="location.reload()" style="color:#9ca3af;font-size:14px;text-decoration:none;transition:color 0.2s" onmouseover="this.style.color='#f3f4f6'" onmouseout="this.style.color='#9ca3af'">返回重新输入账密</a></div></div></div><script>let tmpU='';let tmpP='';async function loginStep1(){const u=document.getElementById('username').value;const p=document.getElementById('password').value;const m=document.getElementById('msg');if(!u||!p){m.style.display='';m.className='msg error';m.innerText='请输入账户和密码';return;}const r=await fetch('${path}/login',{method:'POST',body:JSON.stringify({username:u,password:p})});const d=await r.json();if(r.ok){if(d.status==='require_otp'){tmpU=u;tmpP=p;document.getElementById('step1').style.display='none';document.getElementById('step2').style.display='block';m.style.display='none';document.getElementById('otpCode').focus();}else{window.location.reload();}}else{m.style.display='';m.className='msg error';m.innerText=d.msg||'验证失败';}}async function loginStep2(){const o=document.getElementById('otpCode').value;const m=document.getElementById('msg');if(!o){m.style.display='';m.className='msg error';m.innerText='请输入动态验证码';return;}const r=await fetch('${path}/login',{method:'POST',body:JSON.stringify({username:tmpU,password:tmpP,otp:o})});const d=await r.json();if(r.ok){window.location.reload();}else{m.style.display='';m.className='msg error';m.innerText=d.msg||'验证失败';document.getElementById('otpCode').value='';document.getElementById('otpCode').focus();}}</script></body></html>`;
}

function getFrontLoginHtml() {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>输入访问密码</title><style>${getCommonCss()}</style></head><body><div class="container" style="max-width:400px"><h2>访问限制</h2><div id="msg" class="msg"></div><div class="input-group"><input type="password" id="pwd" placeholder="请输入前台访问密码" onkeydown="if(event.key==='Enter')verifyPwd()"></div><button onclick="verifyPwd()">验证进入</button></div><script>async function verifyPwd(){const p=document.getElementById('pwd').value;const m=document.getElementById('msg');if(!p){m.style.display='block';m.className='msg error';m.innerText='请输入密码';return;}const r=await fetch('/api/front_login',{method:'POST',body:JSON.stringify({pwd:p})});if(r.ok){window.location.reload();}else{m.style.display='block';m.className='msg error';m.innerText='密码错误';}}</script></body></html>`;
}

function getFrontendHtml(config) {
  const showAnnounce = config && config.announce_enabled === 1;
  const ann = config && config.announcement ? config.announcement : '';
  let noticeHtml = '';
  if (showAnnounce && ann) {
    noticeHtml = `<div class="notice-box"><div class="notice-title">公告</div><div class="notice-content">${ann}</div></div>`;
  }
  const psbIcon = `<img src="https://beian.mps.gov.cn/web/assets/logo01.6189a29f.png" style="width:16px;height:16px;vertical-align:middle;margin-right:4px;margin-top:-2px;" alt="">`;
  const icp = config && config.icp_number ? `<a href="${escapeHtml(config.icp_link)}" target="_blank" style="display:flex;align-items:center;">${escapeHtml(config.icp_number)}</a>` : '';
  const psb = config && config.psb_number ? `<a href="${escapeHtml(config.psb_link)}" target="_blank" style="display:flex;align-items:center;">${psbIcon}${escapeHtml(config.psb_number)}</a>` : '';
  let footerHtml = '';
  if (icp || psb) {
    footerHtml = `<div class="footer-beian">${icp}${psb}</div>`;
  }

  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>专业短链接生成器 - 免费在线短网址、防封防屏蔽工具</title><meta name="description" content="专业短链接生成器，提供免费在线短网址生成服务，支持永久有效、自定义后缀、批量转换、访问统计等功能。适用于微信、抖音、小红书、公众号等多平台推广，生成稳定防封短链接，操作简单无广告，助力营销推广、裂变引流，是高效实用的在线短链接工具。"><meta name="keywords" content="短链接生成器,短网址生成器,免费短链接,永久短网址,防封短链接,微信短链接生成,抖音短链接,小红书短链接,自定义短链接,在线短链接工具"><meta property="og:title" content="专业短链接生成器 - 免费在线短网址、防封防屏蔽工具"><meta property="og:description" content="专业短链接生成器，提供免费在线短网址生成服务，支持永久有效、自定义后缀、批量转换、访问统计等功能。适用于微信、抖音、小红书、公众号等多平台推广，生成稳定防封短链接，操作简单无广告，助力营销推广、裂变引流，是高效实用的在线短链接工具。">${getFavicon()}<style>${getCommonCss()}.container{min-height:450px}.flex-row{display:flex;gap:12px}.flex-row input{flex:1}.flex-row button{width:130px}.notice-box{margin-top:40px;border-top:1px solid #4b5563;padding-top:30px}.notice-title{text-align:center;font-weight:bold;font-size:20px;margin-bottom:20px;color:#f9fafb}.notice-content{color:#d1d5db;line-height:1.8;font-size:15px;word-wrap:break-word;overflow-wrap:break-word;background:#374151;padding:20px;border-radius:12px;border:1px solid #4b5563;min-height:120px}.notice-content a{color:#60a5fa;text-decoration:underline}.result-box{display:none;margin-top:24px;padding:24px;background:#064e3b;border:1px solid #065f46;border-radius:12px;text-align:center}@media (max-width:768px){.flex-row{flex-direction:column;gap:12px}.flex-row button{width:100%}}
  .footer-beian { margin-top: auto; padding: 20px 0; display: flex; justify-content: center; gap: 20px; font-size: 13px; text-align: center; border-top: 1px solid #374151; }
  .footer-beian a { color: #9ca3af; text-decoration: none; transition: color 0.2s; display: flex; align-items: center;}
  .footer-beian a:hover { color: #d1d5db; }
  </style></head><body><div class="container"><h2>短链接生成</h2><div id="msg" class="msg"></div><div class="input-group"><label>输入长网址</label><div class="flex-row"><input type="text" id="longUrl" placeholder="https://..."><button onclick="generate()" id="btnGen">生成</button></div></div><div class="input-group"><label>自定义短链接 (可选):</label><input type="text" id="customShort" placeholder="不填写则系统自动生成"></div><div id="resultBox" class="result-box"><div id="resultTitle" style="margin-bottom:12px;color:#34d399;font-weight:bold;font-size:16px;"></div><a id="resultLink" href="" target="_blank" style="display:inline-block;margin-bottom:18px;color:#60a5fa;font-size:18px;word-break:break-all;text-decoration:none;"></a><br><button onclick="copyLink()" style="width:auto;padding:12px 28px;background:#059669;border:1px solid #047857;">一键复制短链接</button><div id="frontQrBox" style="margin-top:20px;display:flex;flex-direction:column;align-items:center;gap:8px;"><img id="frontQrImg" src="" style="width:180px;height:180px;background:#fff;padding:10px;border-radius:8px;box-sizing:border-box;"><div style="font-size:14px;color:#a7f3d0;">扫码访问短链接</div></div></div>${noticeHtml}</div>${footerHtml}<script>function makeQrImg(text){function svg(t){const tables={1:[26,7,1,[]],2:[44,10,1,[6,18]],3:[70,15,1,[6,22]],4:[100,20,1,[6,26]],5:[134,26,1,[6,30]],6:[172,18,2,[6,34]],7:[196,20,2,[6,22,38]],8:[242,24,2,[6,24,42]],9:[292,30,2,[6,26,46]],10:[346,18,4,[6,28,50]]};const enc=new TextEncoder().encode(t);let v=1,cfg=null,dataCodewords=0;for(;v<=10;v++){cfg=tables[v];dataCodewords=cfg[0]-cfg[1]*cfg[2];let cc=v<10?8:16;if(4+cc+enc.length*8<=dataCodewords*8)break}if(v>10)throw new Error('QR内容过长');const totalCodewords=cfg[0],eccLen=cfg[1],numBlocks=cfg[2],aligns=cfg[3],size=17+4*v,ccBits=v<10?8:16;let bits=[];function add(val,len){for(let i=len-1;i>=0;i--)bits.push((val>>>i)&1)}add(4,4);add(enc.length,ccBits);for(const b of enc)add(b,8);let maxBits=dataCodewords*8;let term=Math.min(4,maxBits-bits.length);for(let i=0;i<term;i++)bits.push(0);while(bits.length%8)bits.push(0);let data=[];for(let i=0;i<bits.length;i+=8){let b=0;for(let j=0;j<8;j++)b=(b<<1)|bits[i+j];data.push(b)}for(let p=236;data.length<dataCodewords;p^=253)data.push(p);let exp=new Array(512),log=new Array(256),x=1;for(let i=0;i<255;i++){exp[i]=x;log[x]=i;x<<=1;if(x&256)x^=285}for(let i=255;i<512;i++)exp[i]=exp[i-255];const mul=(a,b)=>a&&b?exp[log[a]+log[b]]:0;let gen=new Array(eccLen).fill(0);gen[eccLen-1]=1;let root=1;for(let i=0;i<eccLen;i++){for(let j=0;j<eccLen;j++){gen[j]=mul(gen[j],root);if(j+1<eccLen)gen[j]^=gen[j+1]}root=mul(root,2)}function ecc(dat){let res=new Array(eccLen).fill(0);for(const b of dat){let factor=b^res.shift();res.push(0);for(let i=0;i<eccLen;i++)res[i]^=mul(gen[i],factor)}return res}let blocks=[],k=0,numShort=numBlocks-totalCodewords%numBlocks,shortLen=Math.floor(totalCodewords/numBlocks);for(let i=0;i<numBlocks;i++){let datLen=shortLen-eccLen+(i<numShort?0:1);let dat=data.slice(k,k+datLen);k+=datLen;blocks.push({dat,ec:ecc(dat)})}let code=[],maxDat=Math.max(...blocks.map(b=>b.dat.length));for(let i=0;i<maxDat;i++)for(const b of blocks)if(i<b.dat.length)code.push(b.dat[i]);for(let i=0;i<eccLen;i++)for(const b of blocks)code.push(b.ec[i]);let m=Array.from({length:size},()=>Array(size).fill(false)),f=Array.from({length:size},()=>Array(size).fill(false));function set(x,y,val,func=true){if(0<=x&&x<size&&0<=y&&y<size){m[y][x]=!!val;if(func)f[y][x]=true}}function finder(cx,cy){for(let dy=-4;dy<=4;dy++)for(let dx=-4;dx<=4;dx++){let d=Math.max(Math.abs(dx),Math.abs(dy));set(cx+dx,cy+dy,d!==2&&d!==4,true)}}finder(3,3);finder(size-4,3);finder(3,size-4);for(let i=0;i<size;i++){if(!f[6][i])set(i,6,i%2===0,true);if(!f[i][6])set(6,i,i%2===0,true)}function align(cx,cy){for(let dy=-2;dy<=2;dy++)for(let dx=-2;dx<=2;dx++)set(cx+dx,cy+dy,Math.max(Math.abs(dx),Math.abs(dy))!==1,true)}for(const y of aligns)for(const x of aligns)if(!((x===6&&y===6)||(x===size-7&&y===6)||(x===6&&y===size-7)))align(x,y);set(8,size-8,true,true);if(v>=7){function verBits(){let rem=v;for(let i=0;i<12;i++)rem=(rem<<1)^(((rem>>>11)&1)*7973);return(v<<12)|rem}let vb=verBits();for(let i=0;i<18;i++){let bit=((vb>>>i)&1)!==0,a=size-11+i%3,b=Math.floor(i/3);set(a,b,bit,true);set(b,a,bit,true)}}function fmtBits(){let data=(1<<3)|0,rem=data;for(let i=0;i<10;i++)rem=(rem<<1)^(((rem>>>9)&1)*1335);return((data<<10)|rem)^21522}let fb=fmtBits();for(let i=0;i<=5;i++)set(8,i,((fb>>>i)&1)!==0,true);set(8,7,((fb>>>6)&1)!==0,true);set(8,8,((fb>>>7)&1)!==0,true);set(7,8,((fb>>>8)&1)!==0,true);for(let i=9;i<15;i++)set(14-i,8,((fb>>>i)&1)!==0,true);for(let i=0;i<8;i++)set(size-1-i,8,((fb>>>i)&1)!==0,true);for(let i=8;i<15;i++)set(8,size-15+i,((fb>>>i)&1)!==0,true);let bitIndex=0;for(let right=size-1;right>=1;right-=2){if(right===6)right--;for(let vert=0;vert<size;vert++){let y=(((right+1)&2)===0)?size-1-vert:vert;for(let x=right;x>=right-1;x--){if(!f[y][x]){let bit=false;if(bitIndex<code.length*8)bit=((code[bitIndex>>>3]>>>(7-(bitIndex&7)))&1)!==0;bitIndex++;if((x+y)%2===0)bit=!bit;m[y][x]=bit}}}}let cell=4,dim=(size+8)*cell,path='';for(let y=0;y<size;y++){let x=0;while(x<size){while(x<size&&!m[y][x])x++;let x0=x;while(x<size&&m[y][x])x++;if(x>x0)path+='M'+((x0+4)*cell)+' '+((y+4)*cell)+'h'+((x-x0)*cell)+'v'+cell+'H'+((x0+4)*cell)+'z'}}return'<svg xmlns="http://www.w3.org/2000/svg" width="'+dim+'" height="'+dim+'" viewBox="0 0 '+dim+' '+dim+'"><rect width="100%" height="100%" fill="#fff"/><path d="'+path+'" fill="#000"/></svg>'}return'data:image/svg+xml;charset=utf-8,'+encodeURIComponent(svg(text))}async function generate(){const l=document.getElementById('longUrl').value.trim();const c=document.getElementById('customShort').value.trim();const m=document.getElementById('msg');const b=document.getElementById('btnGen');const rb=document.getElementById('resultBox');const rl=document.getElementById('resultLink');const rt=document.getElementById('resultTitle');if(!l){m.style.display='';m.className='msg error';m.innerText='请输入长网址';rb.style.display='none';return;}if(!l.startsWith('http://')&&!l.startsWith('https://')){m.style.display='';m.className='msg error';m.innerText='请补全链接的 http:// 或 https:// 前缀';rb.style.display='none';return;}b.disabled=true;b.innerText='提交中...';const r=await fetch('/api/generate',{method:'POST',body:JSON.stringify({longUrl:l,customShort:c})});if(r.ok){const data=await r.json();const fullUrl=window.location.protocol+'//'+window.location.host+'/'+data.short;m.style.display='none';rt.innerText=data.audit?'您的短链接已生成 (待管理员审核后生效)：':'生成成功！您的短链接已生效可直接访问：';rl.href=fullUrl;rl.innerText=fullUrl;document.getElementById('frontQrImg').src=makeQrImg(fullUrl);rb.style.display='block';document.getElementById('longUrl').value='';document.getElementById('customShort').value='';}else{const t=await r.text();m.style.display='';m.className='msg error';m.innerText=t;rb.style.display='none';}b.disabled=false;b.innerText='生成';}async function copyLink(){const txt=document.getElementById('resultLink').innerText;try{await navigator.clipboard.writeText(txt);alert('复制成功！');}catch(e){alert('复制失败，请手动选取复制');}}</script></body></html>`;
}

const { getAdminPageHtml, resolveAdminPage } = (() => {
function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[c]));
}

function escapeAttr(value) {
  return escapeHtml(value).replace(/`/g, '&#96;');
}

function formatTime(value) {
  if (!value) return '-';
  return new Date(Number(value)).toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai', hour12: false }).replace(/\//g, '-');
}

function pageTitle(page) {
  return ({ basic: '基础设置', links: '链接管理', audit: '审核中心', announcement: '公告管理', filing: '备案管理' })[page] || '管理后台';
}

function resolveAdminPage(path, adminPath) {
  const normalized = path.replace(/\/+$/, '') || '/';
  const base = adminPath.replace(/\/+$/, '');
  if (normalized === base) return null;
  const suffix = normalized.slice(base.length + 1);
  if (['basic', 'links', 'audit', 'announcement', 'filing'].includes(suffix)) return suffix;
  return null;
}

function layout(page, adminPath, body, script = '') {
  const title = pageTitle(page);
  const items = [
    ['basic', '基础设置'],
    ['links', '链接管理'],
    ['audit', '审核中心'],
    ['announcement', '公告管理'],
    ['filing', '备案管理']
  ];
  const nav = items.map(([id, label]) => `<a class="nav-item${id === page ? ' active' : ''}" href="${escapeAttr(adminPath)}/${id}">${label}</a>`).join('');
  return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><meta http-equiv="Cache-Control" content="no-store,no-cache,must-revalidate,max-age=0"><title>${title} - 短链接后台</title><style>*{box-sizing:border-box}body{margin:0;font-family:Arial,"Microsoft YaHei",sans-serif;background:#f3f4f6;color:#111827}.app{min-height:100vh;display:flex}.sidebar{position:fixed;left:0;top:0;bottom:0;width:240px;background:#111827;color:#fff;padding:24px 16px;display:flex;flex-direction:column}.logo{font-size:22px;font-weight:700;padding:0 12px 24px;border-bottom:1px solid #374151;margin-bottom:18px}.nav{display:flex;flex-direction:column;gap:8px}.nav-item{display:block;color:#d1d5db;text-decoration:none;padding:12px 14px;border-radius:8px;font-size:15px}.nav-item:hover,.nav-item.active{background:#2563eb;color:#fff}.side-actions{margin-top:auto;display:grid;gap:10px}.side-actions a,.side-actions button{width:100%;padding:10px;border-radius:7px;border:1px solid #4b5563;background:#1f2937;color:#fff;text-align:center;text-decoration:none;cursor:pointer}.main{margin-left:240px;width:calc(100% - 240px);padding:32px}.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px}.header h1{font-size:26px;margin:0}.card{background:#fff;border-radius:12px;padding:22px;box-shadow:0 2px 8px rgba(15,23,42,.07);margin-bottom:20px}.card h2,.card h3{margin:0 0 18px}.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.form-group{margin-bottom:16px}.form-group label{display:block;margin-bottom:7px;font-weight:600;color:#374151}.inline{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.inline label{margin:0}.inline input[type=checkbox]{width:auto}.input,select,input[type=text],input[type=password],input[type=number],input[type=color]{width:100%;padding:10px 12px;border:1px solid #d1d5db;border-radius:7px;background:#fff;font-size:14px}.btn{display:inline-block;border:0;border-radius:7px;padding:9px 14px;background:#2563eb;color:#fff;cursor:pointer;font-size:14px;text-decoration:none;width:auto}.btn:hover{filter:brightness(.95)}.btn-danger{background:#dc2626}.btn-success{background:#059669}.btn-warning{background:#d97706}.btn-secondary{background:#6b7280}.actions{display:flex;gap:7px;flex-wrap:wrap}.notice{display:none;padding:12px 14px;border-radius:7px;margin-bottom:16px}.notice.ok{display:block;background:#d1fae5;color:#065f46}.notice.error{display:block;background:#fee2e2;color:#991b1b}.table-wrap{overflow:auto}table{width:100%;border-collapse:collapse;min-width:820px}th,td{text-align:left;padding:11px;border-bottom:1px solid #e5e7eb;vertical-align:middle}th{background:#f9fafb;font-size:13px;color:#4b5563}.badge{display:inline-block;padding:4px 8px;border-radius:999px;background:#dbeafe;color:#1d4ed8;font-size:12px}.muted{color:#6b7280;font-size:13px}.editor-toolbar{display:flex;gap:6px;flex-wrap:wrap;padding:8px;background:#f3f4f6;border:1px solid #d1d5db;border-bottom:0;border-radius:7px 7px 0 0}.editor-toolbar button,.editor-toolbar select{width:auto;padding:6px 9px;border:1px solid #d1d5db;border-radius:5px;background:#fff}.editor{min-height:220px;border:1px solid #d1d5db;border-radius:0 0 7px 7px;padding:14px;outline:none;background:#fff}.modal{display:none;position:fixed;inset:0;background:rgba(0,0,0,.58);z-index:100;align-items:center;justify-content:center;padding:20px}.modal.open{display:flex}.modal-card{width:100%;max-width:380px;background:#fff;border-radius:12px;padding:24px;text-align:center}.modal-card img{width:250px;height:250px;padding:10px;border:1px solid #e5e7eb}@media(max-width:800px){.sidebar{position:static;width:100%;min-height:auto}.app{display:block}.main{margin:0;width:100%;padding:18px}.nav{display:grid;grid-template-columns:repeat(2,1fr)}.side-actions{margin-top:18px}.grid{grid-template-columns:1fr}.header h1{font-size:22px}}</style></head><body><div class="app"><aside class="sidebar"><div class="logo">管理后台</div><nav class="nav">${nav}</nav><div class="side-actions"><a href="/" target="_blank">返回前台</a><button type="button" id="logoutBtn">退出登录</button></div></aside><main class="main"><div class="header"><h1>${title}</h1></div><div id="notice" class="notice"></div>${body}</main></div><script>const ADMIN_BASE=${JSON.stringify(adminPath)};const PAGE=${JSON.stringify(page)};const ACTION_URL=ADMIN_BASE+'/api/'+PAGE+'/action';function showNotice(message,ok=true){const el=document.getElementById('notice');el.className='notice '+(ok?'ok':'error');el.textContent=message;window.scrollTo({top:0,behavior:'smooth'});}async function postAction(action,payload={}){const response=await fetch(ACTION_URL,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action,payload})});const text=await response.text();if(!response.ok)throw new Error(text||'操作失败');return (response.headers.get('Content-Type')||'').includes('application/json')&&text?JSON.parse(text):text;}document.getElementById('logoutBtn').addEventListener('click',async()=>{if(!confirm('确定退出登录吗？'))return;await fetch(ADMIN_BASE+'/logout',{method:'POST'});location.href=ADMIN_BASE+'/basic';});${script}</script></body></html>`;
}

function basicPage(adminPath, config) {
  const c = config || {};
  const body = `<div class="card"><h2>后台基础信息</h2><div class="grid"><div class="form-group"><label>后台路径</label><input id="adminPath" type="text" value="${escapeAttr(c.adminPath || adminPath)}"></div><div class="form-group"><label>管理员账号</label><input id="username" type="text" value="${escapeAttr(c.username || '')}"></div></div><div class="form-group"><label>修改密码</label><input id="password" type="password" placeholder="留空则不修改"></div><div class="form-group inline"><input id="auditEnabled" type="checkbox" ${c.audit_enabled !== 0 ? 'checked' : ''}><label for="auditEnabled">新短链接需要人工审核</label></div><button class="btn" id="saveBasic">保存基础信息</button></div><div class="card"><h2>自动清理</h2><div class="grid"><div><div class="form-group inline"><input id="autoCleanEnabled" type="checkbox" ${c.auto_clean_enabled === 1 ? 'checked' : ''}><label for="autoCleanEnabled">清理长期未访问的已通过链接</label></div><div class="form-group"><label>未访问天数</label><input id="autoCleanDays" type="number" min="1" max="3650" value="${escapeAttr(c.auto_clean_days || 30)}"></div></div><div><div class="form-group inline"><input id="pendingCleanEnabled" type="checkbox" ${c.pending_auto_clean_enabled === 1 ? 'checked' : ''}><label for="pendingCleanEnabled">清理长期未处理的待审核链接</label></div><div class="form-group"><label>待审核保留天数</label><input id="pendingCleanDays" type="number" min="1" max="3650" value="${escapeAttr(c.pending_auto_clean_days || 30)}"></div></div></div><button class="btn" id="saveClean">保存清理设置</button></div><div class="card"><h2>前台访问</h2><div class="form-group inline"><input id="frontEnabled" type="checkbox" ${c.frontend_pwd_enabled === 1 ? 'checked' : ''}><label for="frontEnabled">开启前台访问密码</label></div><div class="form-group"><label>前台密码</label><input id="frontPassword" type="text" value="${escapeAttr(c.frontend_pwd || '')}"></div><button class="btn" id="saveFront">保存前台密码</button><hr style="border:0;border-top:1px solid #e5e7eb;margin:22px 0"><div class="form-group inline"><input id="maskEnabled" type="checkbox" ${c.wx_qq_mask_enabled !== 0 ? 'checked' : ''}><label for="maskEnabled">启用微信、QQ 防封引导</label></div><button class="btn" id="saveMask">保存防封设置</button></div><div class="card"><h2>OTP 二次验证</h2><p class="muted">当前状态：${c.otp_enabled === 1 ? '已开启' : '未开启'}</p>${c.otp_enabled === 1 ? '<div class="form-group"><label>管理员密码</label><input id="otpDisablePassword" type="password"></div><button class="btn btn-danger" id="disableOtp">关闭 OTP</button>' : '<button class="btn" id="generateOtp">生成 OTP 密钥</button><div id="otpPanel" style="display:none;margin-top:18px"><div id="otpSecret" style="font-family:monospace;word-break:break-all;margin-bottom:12px"></div><img id="otpQr" alt="OTP QR" style="width:220px;height:220px;background:#fff;border:1px solid #e5e7eb;padding:8px"><div class="grid" style="margin-top:16px"><div class="form-group"><label>6 位动态验证码</label><input id="otpCode" type="text" maxlength="6"></div><div class="form-group"><label>管理员密码</label><input id="otpPassword" type="password"></div></div><button class="btn btn-success" id="enableOtp">确认开启</button></div>'}</div>`;
  const script = `function makeQrImg(text){function svg(t){const tables={1:[26,7,1,[]],2:[44,10,1,[6,18]],3:[70,15,1,[6,22]],4:[100,20,1,[6,26]],5:[134,26,1,[6,30]],6:[172,18,2,[6,34]],7:[196,20,2,[6,22,38]],8:[242,24,2,[6,24,42]],9:[292,30,2,[6,26,46]],10:[346,18,4,[6,28,50]]};const enc=new TextEncoder().encode(t);let v=1,cfg=null,dataCodewords=0;for(;v<=10;v++){cfg=tables[v];dataCodewords=cfg[0]-cfg[1]*cfg[2];let cc=v<10?8:16;if(4+cc+enc.length*8<=dataCodewords*8)break}if(v>10)throw new Error('QR内容过长');const totalCodewords=cfg[0],eccLen=cfg[1],numBlocks=cfg[2],aligns=cfg[3],size=17+4*v,ccBits=v<10?8:16;let bits=[];function add(val,len){for(let i=len-1;i>=0;i--)bits.push((val>>>i)&1)}add(4,4);add(enc.length,ccBits);for(const b of enc)add(b,8);let maxBits=dataCodewords*8;let term=Math.min(4,maxBits-bits.length);for(let i=0;i<term;i++)bits.push(0);while(bits.length%8)bits.push(0);let data=[];for(let i=0;i<bits.length;i+=8){let b=0;for(let j=0;j<8;j++)b=(b<<1)|bits[i+j];data.push(b)}for(let p=236;data.length<dataCodewords;p^=253)data.push(p);let exp=new Array(512),log=new Array(256),x=1;for(let i=0;i<255;i++){exp[i]=x;log[x]=i;x<<=1;if(x&256)x^=285}for(let i=255;i<512;i++)exp[i]=exp[i-255];const mul=(a,b)=>a&&b?exp[log[a]+log[b]]:0;let gen=new Array(eccLen).fill(0);gen[eccLen-1]=1;let root=1;for(let i=0;i<eccLen;i++){for(let j=0;j<eccLen;j++){gen[j]=mul(gen[j],root);if(j+1<eccLen)gen[j]^=gen[j+1]}root=mul(root,2)}function ecc(dat){let res=new Array(eccLen).fill(0);for(const b of dat){let factor=b^res.shift();res.push(0);for(let i=0;i<eccLen;i++)res[i]^=mul(gen[i],factor)}return res}let blocks=[],k=0,numShort=numBlocks-totalCodewords%numBlocks,shortLen=Math.floor(totalCodewords/numBlocks);for(let i=0;i<numBlocks;i++){let datLen=shortLen-eccLen+(i<numShort?0:1);let dat=data.slice(k,k+datLen);k+=datLen;blocks.push({dat,ec:ecc(dat)})}let code=[],maxDat=Math.max(...blocks.map(b=>b.dat.length));for(let i=0;i<maxDat;i++)for(const b of blocks)if(i<b.dat.length)code.push(b.dat[i]);for(let i=0;i<eccLen;i++)for(const b of blocks)code.push(b.ec[i]);let m=Array.from({length:size},()=>Array(size).fill(false)),f=Array.from({length:size},()=>Array(size).fill(false));function set(x,y,val,func=true){if(0<=x&&x<size&&0<=y&&y<size){m[y][x]=!!val;if(func)f[y][x]=true}}function finder(cx,cy){for(let dy=-4;dy<=4;dy++)for(let dx=-4;dx<=4;dx++){let d=Math.max(Math.abs(dx),Math.abs(dy));set(cx+dx,cy+dy,d!==2&&d!==4,true)}}finder(3,3);finder(size-4,3);finder(3,size-4);for(let i=0;i<size;i++){if(!f[6][i])set(i,6,i%2===0,true);if(!f[i][6])set(6,i,i%2===0,true)}function align(cx,cy){for(let dy=-2;dy<=2;dy++)for(let dx=-2;dx<=2;dx++)set(cx+dx,cy+dy,Math.max(Math.abs(dx),Math.abs(dy))!==1,true)}for(const y of aligns)for(const x of aligns)if(!((x===6&&y===6)||(x===size-7&&y===6)||(x===6&&y===size-7)))align(x,y);set(8,size-8,true,true);if(v>=7){function verBits(){let rem=v;for(let i=0;i<12;i++)rem=(rem<<1)^(((rem>>>11)&1)*7973);return(v<<12)|rem}let vb=verBits();for(let i=0;i<18;i++){let bit=((vb>>>i)&1)!==0,a=size-11+i%3,b=Math.floor(i/3);set(a,b,bit,true);set(b,a,bit,true)}}function fmtBits(){let data=(1<<3)|0,rem=data;for(let i=0;i<10;i++)rem=(rem<<1)^(((rem>>>9)&1)*1335);return((data<<10)|rem)^21522}let fb=fmtBits();for(let i=0;i<=5;i++)set(8,i,((fb>>>i)&1)!==0,true);set(8,7,((fb>>>6)&1)!==0,true);set(8,8,((fb>>>7)&1)!==0,true);set(7,8,((fb>>>8)&1)!==0,true);for(let i=9;i<15;i++)set(14-i,8,((fb>>>i)&1)!==0,true);for(let i=0;i<8;i++)set(size-1-i,8,((fb>>>i)&1)!==0,true);for(let i=8;i<15;i++)set(8,size-15+i,((fb>>>i)&1)!==0,true);let bitIndex=0;for(let right=size-1;right>=1;right-=2){if(right===6)right--;for(let vert=0;vert<size;vert++){let y=(((right+1)&2)===0)?size-1-vert:vert;for(let x=right;x>=right-1;x--){if(!f[y][x]){let bit=false;if(bitIndex<code.length*8)bit=((code[bitIndex>>>3]>>>(7-(bitIndex&7)))&1)!==0;bitIndex++;if((x+y)%2===0)bit=!bit;m[y][x]=bit}}}}let cell=4,dim=(size+8)*cell,path='';for(let y=0;y<size;y++){let x=0;while(x<size){while(x<size&&!m[y][x])x++;let x0=x;while(x<size&&m[y][x])x++;if(x>x0)path+='M'+((x0+4)*cell)+' '+((y+4)*cell)+'h'+((x-x0)*cell)+'v'+cell+'H'+((x0+4)*cell)+'z'}}return'<svg xmlns="http://www.w3.org/2000/svg" width="'+dim+'" height="'+dim+'" viewBox="0 0 '+dim+' '+dim+'"><rect width="100%" height="100%" fill="#fff"/><path d="'+path+'" fill="#000"/></svg>'}return'data:image/svg+xml;charset=utf-8,'+encodeURIComponent(svg(text))}let otpSecret='';document.getElementById('saveBasic').addEventListener('click',async()=>{try{const next=document.getElementById('adminPath').value.trim();await postAction('update_basic_config',{adminPath:next,username:document.getElementById('username').value.trim(),password:document.getElementById('password').value,audit_enabled:document.getElementById('auditEnabled').checked});location.href=(next.startsWith('/')?next:'/'+next)+'/basic';}catch(e){showNotice(e.message,false);}});document.getElementById('saveClean').addEventListener('click',async()=>{try{await postAction('update_clean_config',{auto_clean_enabled:document.getElementById('autoCleanEnabled').checked,auto_clean_days:Number(document.getElementById('autoCleanDays').value),pending_auto_clean_enabled:document.getElementById('pendingCleanEnabled').checked,pending_auto_clean_days:Number(document.getElementById('pendingCleanDays').value)});showNotice('自动清理设置已保存');}catch(e){showNotice(e.message,false);}});document.getElementById('saveFront').addEventListener('click',async()=>{try{const enabled=document.getElementById('frontEnabled').checked;const pwd=document.getElementById('frontPassword').value.trim();if(enabled&&!pwd)throw new Error('开启前台密码时密码不能为空');await postAction('update_front_pwd_config',{enabled,pwd});showNotice('前台密码设置已保存');}catch(e){showNotice(e.message,false);}});document.getElementById('saveMask').addEventListener('click',async()=>{try{await postAction('update_wx_qq_mask_config',{enabled:document.getElementById('maskEnabled').checked});showNotice('防封设置已保存');}catch(e){showNotice(e.message,false);}});const generate=document.getElementById('generateOtp');if(generate)generate.addEventListener('click',async()=>{try{const response=await fetch(ACTION_URL,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({action:'generate_otp_secret',payload:{}})});const data=await response.json();if(!response.ok)throw new Error(data.error||'生成失败');otpSecret=data.secret;document.getElementById('otpSecret').textContent=otpSecret;document.getElementById('otpQr').src=makeQrImg('otpauth://totp/ShortLinkAdmin?secret='+otpSecret+'&issuer=EdgeOne');document.getElementById('otpPanel').style.display='block';}catch(e){showNotice(e.message,false);}});const enable=document.getElementById('enableOtp');if(enable)enable.addEventListener('click',async()=>{try{await postAction('enable_otp',{secret:otpSecret,code:document.getElementById('otpCode').value.trim(),password:document.getElementById('otpPassword').value});location.reload();}catch(e){showNotice(e.message,false);}});const disable=document.getElementById('disableOtp');if(disable)disable.addEventListener('click',async()=>{try{await postAction('disable_otp',{password:document.getElementById('otpDisablePassword').value});location.reload();}catch(e){showNotice(e.message,false);}});`;
  return layout('basic', adminPath, body, script);
}

function linksPage(adminPath, host, links) {
  const rows = links.length ? links.map(link => `<tr><td><input class="row-check" type="checkbox" value="${escapeAttr(link.short)}"></td><td><a href="//${escapeAttr(host)}/${encodeURIComponent(link.short)}" target="_blank">${escapeHtml(host)}/${escapeHtml(link.short)}</a>${link.isPermanent ? ' <span class="badge">免清理</span>' : ''}</td><td class="target-url" data-short="${escapeAttr(link.short)}" style="max-width:420px;word-break:break-all">${escapeHtml(link.longUrl)}</td><td>${Number(link.visits || 0)}</td><td>${formatTime(link.approvedAt || link.createdAt)}</td><td><div class="actions"><button class="btn btn-success qr-btn" data-short="${escapeAttr(link.short)}">二维码</button><button class="btn edit-btn" data-short="${escapeAttr(link.short)}" data-url="${escapeAttr(link.longUrl)}">编辑</button><button class="btn btn-warning permanent-btn" data-short="${escapeAttr(link.short)}">${link.isPermanent ? '取消免清' : '设为免清'}</button><button class="btn btn-danger delete-btn" data-short="${escapeAttr(link.short)}">删除</button></div></td></tr>`).join('') : '<tr><td colspan="6" class="muted">暂无已通过链接</td></tr>';
  const body = `<div class="card"><div class="inline" style="justify-content:space-between;margin-bottom:16px"><div><strong>已通过链接</strong> <span class="badge">${links.length}</span></div><button class="btn btn-danger" id="batchDelete">批量删除</button></div><div class="table-wrap"><table><thead><tr><th><input id="selectAll" type="checkbox"></th><th>短链接</th><th>目标地址</th><th>访问量</th><th>通过时间</th><th>操作</th></tr></thead><tbody>${rows}</tbody></table></div></div><div id="qrModal" class="modal"><div class="modal-card"><h3>短链接二维码</h3><img id="qrImage" alt="二维码"><p id="qrText" style="word-break:break-all;color:#2563eb"></p><button class="btn" id="closeQr">关闭</button></div></div><div id="editModal" class="modal"><div class="modal-card" style="max-width:560px;text-align:left"><h3>编辑目标地址</h3><p class="muted">短码：<span id="editShort"></span></p><form id="editForm"><div class="form-group"><label for="editUrl">目标地址</label><input id="editUrl" type="url" required autocomplete="off" placeholder="https://example.com/"></div><div class="actions" style="justify-content:flex-end"><button type="button" class="btn btn-secondary" id="cancelEdit">取消</button><button type="submit" class="btn">保存</button></div></form></div></div>`;
  const script = `function makeQrImg(text){function svg(t){const tables={1:[26,7,1,[]],2:[44,10,1,[6,18]],3:[70,15,1,[6,22]],4:[100,20,1,[6,26]],5:[134,26,1,[6,30]],6:[172,18,2,[6,34]],7:[196,20,2,[6,22,38]],8:[242,24,2,[6,24,42]],9:[292,30,2,[6,26,46]],10:[346,18,4,[6,28,50]]};const enc=new TextEncoder().encode(t);let v=1,cfg=null,dataCodewords=0;for(;v<=10;v++){cfg=tables[v];dataCodewords=cfg[0]-cfg[1]*cfg[2];let cc=v<10?8:16;if(4+cc+enc.length*8<=dataCodewords*8)break}if(v>10)throw new Error('QR内容过长');const totalCodewords=cfg[0],eccLen=cfg[1],numBlocks=cfg[2],aligns=cfg[3],size=17+4*v,ccBits=v<10?8:16;let bits=[];function add(val,len){for(let i=len-1;i>=0;i--)bits.push((val>>>i)&1)}add(4,4);add(enc.length,ccBits);for(const b of enc)add(b,8);let maxBits=dataCodewords*8;let term=Math.min(4,maxBits-bits.length);for(let i=0;i<term;i++)bits.push(0);while(bits.length%8)bits.push(0);let data=[];for(let i=0;i<bits.length;i+=8){let b=0;for(let j=0;j<8;j++)b=(b<<1)|bits[i+j];data.push(b)}for(let p=236;data.length<dataCodewords;p^=253)data.push(p);let exp=new Array(512),log=new Array(256),x=1;for(let i=0;i<255;i++){exp[i]=x;log[x]=i;x<<=1;if(x&256)x^=285}for(let i=255;i<512;i++)exp[i]=exp[i-255];const mul=(a,b)=>a&&b?exp[log[a]+log[b]]:0;let gen=new Array(eccLen).fill(0);gen[eccLen-1]=1;let root=1;for(let i=0;i<eccLen;i++){for(let j=0;j<eccLen;j++){gen[j]=mul(gen[j],root);if(j+1<eccLen)gen[j]^=gen[j+1]}root=mul(root,2)}function ecc(dat){let res=new Array(eccLen).fill(0);for(const b of dat){let factor=b^res.shift();res.push(0);for(let i=0;i<eccLen;i++)res[i]^=mul(gen[i],factor)}return res}let blocks=[],k=0,numShort=numBlocks-totalCodewords%numBlocks,shortLen=Math.floor(totalCodewords/numBlocks);for(let i=0;i<numBlocks;i++){let datLen=shortLen-eccLen+(i<numShort?0:1);let dat=data.slice(k,k+datLen);k+=datLen;blocks.push({dat,ec:ecc(dat)})}let code=[],maxDat=Math.max(...blocks.map(b=>b.dat.length));for(let i=0;i<maxDat;i++)for(const b of blocks)if(i<b.dat.length)code.push(b.dat[i]);for(let i=0;i<eccLen;i++)for(const b of blocks)code.push(b.ec[i]);let m=Array.from({length:size},()=>Array(size).fill(false)),f=Array.from({length:size},()=>Array(size).fill(false));function set(x,y,val,func=true){if(0<=x&&x<size&&0<=y&&y<size){m[y][x]=!!val;if(func)f[y][x]=true}}function finder(cx,cy){for(let dy=-4;dy<=4;dy++)for(let dx=-4;dx<=4;dx++){let d=Math.max(Math.abs(dx),Math.abs(dy));set(cx+dx,cy+dy,d!==2&&d!==4,true)}}finder(3,3);finder(size-4,3);finder(3,size-4);for(let i=0;i<size;i++){if(!f[6][i])set(i,6,i%2===0,true);if(!f[i][6])set(6,i,i%2===0,true)}function align(cx,cy){for(let dy=-2;dy<=2;dy++)for(let dx=-2;dx<=2;dx++)set(cx+dx,cy+dy,Math.max(Math.abs(dx),Math.abs(dy))!==1,true)}for(const y of aligns)for(const x of aligns)if(!((x===6&&y===6)||(x===size-7&&y===6)||(x===6&&y===size-7)))align(x,y);set(8,size-8,true,true);if(v>=7){function verBits(){let rem=v;for(let i=0;i<12;i++)rem=(rem<<1)^(((rem>>>11)&1)*7973);return(v<<12)|rem}let vb=verBits();for(let i=0;i<18;i++){let bit=((vb>>>i)&1)!==0,a=size-11+i%3,b=Math.floor(i/3);set(a,b,bit,true);set(b,a,bit,true)}}function fmtBits(){let data=(1<<3)|0,rem=data;for(let i=0;i<10;i++)rem=(rem<<1)^(((rem>>>9)&1)*1335);return((data<<10)|rem)^21522}let fb=fmtBits();for(let i=0;i<=5;i++)set(8,i,((fb>>>i)&1)!==0,true);set(8,7,((fb>>>6)&1)!==0,true);set(8,8,((fb>>>7)&1)!==0,true);set(7,8,((fb>>>8)&1)!==0,true);for(let i=9;i<15;i++)set(14-i,8,((fb>>>i)&1)!==0,true);for(let i=0;i<8;i++)set(size-1-i,8,((fb>>>i)&1)!==0,true);for(let i=8;i<15;i++)set(8,size-15+i,((fb>>>i)&1)!==0,true);let bitIndex=0;for(let right=size-1;right>=1;right-=2){if(right===6)right--;for(let vert=0;vert<size;vert++){let y=(((right+1)&2)===0)?size-1-vert:vert;for(let x=right;x>=right-1;x--){if(!f[y][x]){let bit=false;if(bitIndex<code.length*8)bit=((code[bitIndex>>>3]>>>(7-(bitIndex&7)))&1)!==0;bitIndex++;if((x+y)%2===0)bit=!bit;m[y][x]=bit}}}}let cell=4,dim=(size+8)*cell,path='';for(let y=0;y<size;y++){let x=0;while(x<size){while(x<size&&!m[y][x])x++;let x0=x;while(x<size&&m[y][x])x++;if(x>x0)path+='M'+((x0+4)*cell)+' '+((y+4)*cell)+'h'+((x-x0)*cell)+'v'+cell+'H'+((x0+4)*cell)+'z'}}return'<svg xmlns="http://www.w3.org/2000/svg" width="'+dim+'" height="'+dim+'" viewBox="0 0 '+dim+' '+dim+'"><rect width="100%" height="100%" fill="#fff"/><path d="'+path+'" fill="#000"/></svg>'}return'data:image/svg+xml;charset=utf-8,'+encodeURIComponent(svg(text))}const editModal=document.getElementById('editModal');const editForm=document.getElementById('editForm');const editUrl=document.getElementById('editUrl');const editShort=document.getElementById('editShort');let editingButton=null;function closeEditModal(){editModal.classList.remove('open');editingButton=null;editForm.reset()}document.querySelectorAll('.edit-btn').forEach(btn=>btn.addEventListener('click',()=>{editingButton=btn;editShort.textContent=btn.dataset.short;editUrl.value=btn.dataset.url;editModal.classList.add('open');editUrl.focus();editUrl.select()}));document.getElementById('cancelEdit').addEventListener('click',closeEditModal);editModal.addEventListener('click',e=>{if(e.target===editModal)closeEditModal()});editForm.addEventListener('submit',async e=>{e.preventDefault();if(!editingButton)return;let parsed;try{parsed=new URL(editUrl.value.trim())}catch(error){return showNotice('目标地址必须是有效的 HTTP 或 HTTPS 地址',false)}if(parsed.protocol!=='http:'&&parsed.protocol!=='https:')return showNotice('目标地址必须是有效的 HTTP 或 HTTPS 地址',false);try{const result=await postAction('update_target_url',{short:editingButton.dataset.short,longUrl:parsed.href});const updatedUrl=result&&result.longUrl?result.longUrl:parsed.href;editingButton.dataset.url=updatedUrl;editingButton.closest('tr').querySelector('.target-url').textContent=updatedUrl;closeEditModal();showNotice('目标地址已更新')}catch(error){showNotice(error.message,false)}});document.getElementById('selectAll').addEventListener('change',e=>document.querySelectorAll('.row-check').forEach(x=>x.checked=e.target.checked));document.querySelectorAll('.delete-btn').forEach(btn=>btn.addEventListener('click',async()=>{if(!confirm('确定删除这个链接吗？'))return;try{await postAction('delete',{short:btn.dataset.short});location.reload();}catch(e){showNotice(e.message,false);}}));document.querySelectorAll('.permanent-btn').forEach(btn=>btn.addEventListener('click',async()=>{try{await postAction('toggle_permanent',{short:btn.dataset.short});location.reload();}catch(e){showNotice(e.message,false);}}));document.getElementById('batchDelete').addEventListener('click',async()=>{const shorts=Array.from(document.querySelectorAll('.row-check:checked')).map(x=>x.value);if(!shorts.length)return showNotice('请先选择链接',false);if(!confirm('确定删除选中的 '+shorts.length+' 条链接吗？'))return;try{await postAction('batch_delete',{shorts});location.reload();}catch(e){showNotice(e.message,false);}});const modal=document.getElementById('qrModal');document.querySelectorAll('.qr-btn').forEach(btn=>btn.addEventListener('click',()=>{const url=location.protocol+'//'+location.host+'/'+btn.dataset.short;document.getElementById('qrImage').src=makeQrImg(url);document.getElementById('qrText').textContent=url;modal.classList.add('open');}));document.getElementById('closeQr').addEventListener('click',()=>modal.classList.remove('open'));`;
  return layout('links', adminPath, body, script);
}

function auditPage(adminPath, host, links) {
  const rows = links.length ? links.map(link => `<tr><td><input class="row-check" type="checkbox" value="${escapeAttr(link.short)}"></td><td>${escapeHtml(host)}/${escapeHtml(link.short)}</td><td style="max-width:480px;word-break:break-all">${escapeHtml(link.longUrl)}</td><td>${formatTime(link.createdAt)}</td><td><span class="badge">待审核</span></td><td><div class="actions"><button class="btn btn-success approve-btn" data-short="${escapeAttr(link.short)}">通过</button><button class="btn btn-danger reject-btn" data-short="${escapeAttr(link.short)}">拒绝</button></div></td></tr>`).join('') : '<tr><td colspan="6" class="muted">暂无待审核申请</td></tr>';
  const body = `<div class="card"><div class="inline" style="justify-content:space-between;margin-bottom:16px"><div><strong>待审核申请</strong> <span class="badge">${links.length}</span></div><button class="btn btn-danger" id="batchReject">批量拒绝</button></div><div class="table-wrap"><table><thead><tr><th><input id="selectAll" type="checkbox"></th><th>短链接</th><th>目标地址</th><th>提交时间</th><th>状态</th><th>操作</th></tr></thead><tbody>${rows}</tbody></table></div></div>`;
  const script = `document.getElementById('selectAll').addEventListener('change',e=>document.querySelectorAll('.row-check').forEach(x=>x.checked=e.target.checked));document.querySelectorAll('.approve-btn').forEach(btn=>btn.addEventListener('click',async()=>{try{await postAction('approve',{short:btn.dataset.short});location.reload();}catch(e){showNotice(e.message,false);}}));document.querySelectorAll('.reject-btn').forEach(btn=>btn.addEventListener('click',async()=>{if(!confirm('确定拒绝并删除这条申请吗？'))return;try{await postAction('reject',{short:btn.dataset.short});location.reload();}catch(e){showNotice(e.message,false);}}));document.getElementById('batchReject').addEventListener('click',async()=>{const shorts=Array.from(document.querySelectorAll('.row-check:checked')).map(x=>x.value);if(!shorts.length)return showNotice('请先选择申请',false);if(!confirm('确定拒绝选中的 '+shorts.length+' 条申请吗？'))return;try{await postAction('batch_reject',{shorts});location.reload();}catch(e){showNotice(e.message,false);}});`;
  return layout('audit', adminPath, body, script);
}

function announcementPage(adminPath, config) {
  const body = `<div class="card"><h2>前台公告板</h2><div class="form-group inline"><input id="enabled" type="checkbox" ${config.announce_enabled === 1 ? 'checked' : ''}><label for="enabled">在前台显示公告</label></div><div class="editor-toolbar"><button type="button" data-cmd="bold"><b>B</b></button><button type="button" data-cmd="italic"><i>I</i></button><button type="button" data-cmd="justifyLeft">左对齐</button><button type="button" data-cmd="justifyCenter">居中</button><button type="button" data-cmd="justifyRight">右对齐</button><button type="button" id="addLink">添加链接</button><select id="fontSize"><option value="">字号</option><option value="1">极小</option><option value="3">正常</option><option value="5">大号</option><option value="7">特大</option></select><input id="fontColor" type="color" style="width:38px;height:32px;padding:2px"></div><div id="editor" class="editor" contenteditable="true">${config.announcement || ''}</div><button class="btn" id="save" style="margin-top:16px">发布公告</button></div>`;
  const script = `document.querySelectorAll('[data-cmd]').forEach(btn=>btn.addEventListener('click',()=>{document.execCommand(btn.dataset.cmd,false,null);document.getElementById('editor').focus();}));document.getElementById('fontSize').addEventListener('change',e=>{if(e.target.value)document.execCommand('fontSize',false,e.target.value);e.target.value='';});document.getElementById('fontColor').addEventListener('change',e=>document.execCommand('foreColor',false,e.target.value));document.getElementById('addLink').addEventListener('click',()=>{const url=prompt('输入超链接地址','https://');if(url)document.execCommand('createLink',false,url);});document.getElementById('save').addEventListener('click',async()=>{try{await postAction('update_announcement',{enabled:document.getElementById('enabled').checked,announcement:document.getElementById('editor').innerHTML});showNotice('公告已更新');}catch(e){showNotice(e.message,false);}});`;
  return layout('announcement', adminPath, body, script);
}

function filingPage(adminPath, config) {
  const body = `<div class="card"><h2>网站备案信息</h2><div class="grid"><div><h3>ICP 备案</h3><div class="form-group"><label>备案号</label><input id="icpNumber" type="text" value="${escapeAttr(config.icp_number || '')}"></div><div class="form-group"><label>查询地址</label><input id="icpLink" type="text" value="${escapeAttr(config.icp_link || '')}"></div></div><div><h3>公安网安备案</h3><div class="form-group"><label>备案号</label><input id="psbNumber" type="text" value="${escapeAttr(config.psb_number || '')}"></div><div class="form-group"><label>查询地址</label><input id="psbLink" type="text" value="${escapeAttr(config.psb_link || '')}"></div></div></div><button class="btn" id="save">保存备案信息</button></div>`;
  const script = `document.getElementById('save').addEventListener('click',async()=>{try{await postAction('update_beian_config',{icp_number:document.getElementById('icpNumber').value.trim(),icp_link:document.getElementById('icpLink').value.trim(),psb_number:document.getElementById('psbNumber').value.trim(),psb_link:document.getElementById('psbLink').value.trim()});showNotice('备案信息已保存');}catch(e){showNotice(e.message,false);}});`;
  return layout('filing', adminPath, body, script);
}

function getAdminPageHtml({ page, adminPath, host, config, links = [] }) {
  if (page === 'basic') return basicPage(adminPath, config);
  if (page === 'links') return linksPage(adminPath, host, links);
  if (page === 'audit') return auditPage(adminPath, host, links);
  if (page === 'announcement') return announcementPage(adminPath, config);
  if (page === 'filing') return filingPage(adminPath, config);
  return basicPage(adminPath, config);
}

return { getAdminPageHtml, resolveAdminPage };
})();
