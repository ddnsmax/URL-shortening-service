function normalizeCleanupDays(value, fallback = 30) {
  const parsed = Number.parseInt(value, 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(3650, Math.max(1, parsed));
}

async function getLinkKeys(kv) {
  const value = await kv.get('meta_link_keys');
  return value ? JSON.parse(value) : [];
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

async function cleanupExpiredPendingKv(kv) {
  const configValue = await kv.get('system_config');
  if (!configValue) return;
  let config = null;
  try { config = JSON.parse(configValue); } catch (e) { return; }
  if (!config || config.pending_auto_clean_enabled !== 1) return;
  const days = normalizeCleanupDays(config.pending_auto_clean_days, 30);
  const cutoff = Date.now() - days * 86400000;
  const keys = await getLinkKeys(kv);
  if (keys.length === 0) {
    try { await kv.delete('pending_cleanup_cursor'); } catch (e) {}
    return;
  }
  let cursor = null;
  try { cursor = await kv.get('pending_cleanup_cursor'); } catch (e) {}
  let start = cursor ? keys.indexOf(cursor) : 0;
  if (start < 0) start = 0;
  const maxScan = Math.min(keys.length, 500);
  const deleted = [];
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
    } catch (e) {}
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
}

export default {
  async fetch() {
    return new Response('Not Found', { status: 404 });
  },
  async scheduled(controller, env, ctx) {
    if (!env || !env.duanlianjie) throw new Error('未找到名为 duanlianjie 的 KV 绑定');
    await cleanupExpiredPendingKv(env.duanlianjie);
  }
};
