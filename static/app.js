let authToken = localStorage.getItem("cosmo_fw_token") || "";
let blacklistCache = [];
let whitelistCache = [];
let trapsCache = [];

function escapeHtml(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function showToast(msg, type = "success") {
  const c = document.getElementById("toastContainer");
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = msg;
  c.appendChild(el);
  setTimeout(() => el.remove(), 3200);
}

async function api(path, opts = {}) {
  const headers = { "Content-Type": "application/json", ...(opts.headers || {}) };
  if (authToken) headers["Authorization"] = `Bearer ${authToken}`;
  const resp = await fetch(path, { ...opts, headers });
  const data = await resp.json().catch(() => ({ success: false, message: "响应解析失败" }));
  if (resp.status === 401 && path !== "/api/v1/auth/login") {
    authToken = "";
    localStorage.removeItem("cosmo_fw_token");
    showLogin();
  }
  return data;
}

function formatDateTime(ts) {
  if (!ts) return { short: "-", full: "-" };
  const d = new Date(ts * 1000);
  const p = n => String(n).padStart(2, "0");
  const full = `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  const short = `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
  return { short, full };
}

function formatBanReasonCell(rawReason, source) {
  const text = (rawReason || "").trim();
  if (!text) {
    return `<div class="ban-reason-wrap"><div class="ban-reason-title-row"><span class="ban-reason-tag manual">手动</span><span class="ban-reason-title">无说明</span></div></div>`;
  }
  let tagClass = "probe";
  let tagLabel = "异常探测";
  if (source === "manual" || text.includes("手动")) {
    tagClass = "manual"; tagLabel = "手动封禁";
  } else if (text.includes("哨兵诱捕")) {
    tagClass = "trap"; tagLabel = "哨兵诱捕";
  } else if (text.includes("横向扫描") || text.includes("跨端口")) {
    tagClass = "sweep"; tagLabel = "横向扫段";
  } else if (text.includes("暴力破解") || text.includes("爆破") || text.includes("洪泛") || source === "brute_force") {
    tagClass = "brute"; tagLabel = "高频爆破";
  } else if (text.includes("漏洞") || text.includes("代理") || text.includes("扫描工具")) {
    tagClass = "probe"; tagLabel = "漏洞扫描";
  } else if (text.includes("核心服务") || text.includes("SSH")) {
    tagClass = "probe"; tagLabel = "协议探测";
  }

  const chips = [];
  let mainTitle = text;
  const mBracket = text.match(/\[([^\]]+)\]/);
  if (mBracket && mBracket[1].trim()) chips.push({ text: mBracket[1].trim(), cls: "" });

  const mPorts = text.match(/(?:探测端口|未分配端口|端口)[:：\s]*([0-9,\s]+)/);
  if (mPorts && mPorts[1]) {
    chips.unshift({ text: `端口 ${mPorts[1].trim().replace(/\s+/g, "")}`, cls: "port" });
  } else {
    const mSingle = text.match(/\((\d{2,5})\)/);
    if (mSingle) chips.unshift({ text: `端口 ${mSingle[1]}`, cls: "port" });
  }
  const mScore = text.match(/累计异常评分\s*(\d+\/\d+)/);
  if (mScore) chips.push({ text: `评分 ${mScore[1]}`, cls: "" });
  const mCount = text.match(/触发\s*(\d+)\s*次/);
  if (mCount) chips.push({ text: `触发 ${mCount[1]} 次`, cls: "" });

  if (chips.length > 0) {
    const idx = text.indexOf("(");
    if (idx > 2) mainTitle = text.slice(0, idx).trim();
  }
  const chipsHtml = chips.length
    ? `<div class="ban-reason-meta">${chips.map(c => `<span class="ban-meta-chip ${c.cls}" title="${escapeHtml(c.text)}">${escapeHtml(c.text)}</span>`).join("")}</div>`
    : "";
  return `
    <div class="ban-reason-wrap" title="${escapeHtml(text)}">
      <div class="ban-reason-title-row">
        <span class="ban-reason-tag ${tagClass}">${tagLabel}</span>
        <span class="ban-reason-title">${escapeHtml(mainTitle)}</span>
      </div>
      ${chipsHtml}
    </div>
  `;
}

// ----------------- Auth & View Switching -----------------

function showLogin() {
  document.getElementById("loginView").style.display = "flex";
  document.getElementById("appView").style.display = "none";
}

function showApp(user) {
  document.getElementById("loginView").style.display = "none";
  document.getElementById("appView").style.display = "block";
  if (user && user.username) {
    document.getElementById("currentUserLabel").textContent = user.username;
  }
  refreshAll();
}

async function handleLogin(e) {
  e.preventDefault();
  const username = document.getElementById("loginUser").value.trim();
  const password = document.getElementById("loginPass").value;
  const res = await api("/api/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
  if (res.success && res.token) {
    authToken = res.token;
    localStorage.setItem("cosmo_fw_token", authToken);
    showToast("登录成功");
    showApp(res.user);
  } else {
    showToast(res.message || "登录失败", "error");
  }
}

async function handleLogout() {
  await api("/api/v1/auth/logout", { method: "POST", body: "{}" });
  authToken = "";
  localStorage.removeItem("cosmo_fw_token");
  showLogin();
}

function switchTab(tab) {
  document.querySelectorAll(".tab-btn").forEach(b => b.classList.toggle("active", b.dataset.tab === tab));
  document.querySelectorAll(".tab-pane").forEach(p => p.classList.toggle("active", p.id === `tab-${tab}`));
  if (tab === "blacklist") loadBlacklist();
  if (tab === "whitelist") loadWhitelist();
  if (tab === "traps") loadTraps();
  if (tab === "unban") loadUnbanRequests();
  if (tab === "settings") { loadSettings(); loadEvents(); }
}

function openModal(id) { document.getElementById(id)?.classList.add("active"); }
function closeModal(id) { document.getElementById(id)?.classList.remove("active"); }

function toggleTheme() {
  const html = document.documentElement;
  const next = html.getAttribute("data-theme") === "dark" ? "light" : "dark";
  html.setAttribute("data-theme", next);
  localStorage.setItem("cosmo_fw_theme", next);
  document.getElementById("themeBtn").textContent = next === "dark" ? "☀️ 浅色" : "🌙 深色";
}

// ----------------- Loaders -----------------

async function refreshAll() {
  await Promise.all([loadDashboard(), loadBlacklist(), loadWhitelist(), loadTraps(), loadUnbanRequests(), loadSettings(), loadEvents()]);
}

async function loadDashboard() {
  const res = await api("/api/v1/dashboard");
  if (!res.success) return;
  const s = res.stats;
  document.getElementById("statTotalBans").textContent = s.total_bans;
  document.getElementById("statAutoBans").textContent = s.auto_bans;
  document.getElementById("statManualBans").textContent = s.manual_bans;
  document.getElementById("statWhitelist").textContent = s.whitelist_count;
  document.getElementById("statTraps").textContent = `${s.trap_listening} / ${s.trap_total}`;
  document.getElementById("statTrapHits").textContent = s.trap_hits;
  document.getElementById("statDroppedPkts").textContent = (s.kernel?.dropped_packets || 0).toLocaleString();

  const statusEl = document.getElementById("statDefenseStatus");
  statusEl.textContent = s.defense_enabled ? "运行中" : "已暂停";
  statusEl.style.color = s.defense_enabled ? "var(--success)" : "var(--warning)";

  const kBadge = document.getElementById("kernelModeBadge");
  if (s.kernel?.mode === "ipset+iptables") {
    kBadge.className = "badge badge-success";
    kBadge.textContent = "内核级 ipset+iptables";
  } else if (s.kernel?.mode === "iptables") {
    kBadge.className = "badge badge-primary";
    kBadge.textContent = "内核级 iptables";
  } else {
    kBadge.className = "badge badge-warning";
    kBadge.textContent = "本地测试模式（非 root）";
  }
}

async function loadBlacklist() {
  const res = await api("/api/v1/blacklist");
  if (res.success) {
    blacklistCache = res.blacklist || [];
    renderBlacklist();
  }
}

function renderBlacklist() {
  const tbody = document.getElementById("blacklistTbody");
  const q = (document.getElementById("blacklistSearch")?.value || "").trim().toLowerCase();
  const items = q
    ? blacklistCache.filter(x => (x.ip || "").toLowerCase().includes(q) || (x.reason || "").toLowerCase().includes(q))
    : blacklistCache;

  if (!items.length) {
    tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; color:var(--text-dim); padding:2.5rem;">当前暂无生效中的封禁记录</td></tr>`;
    return;
  }

  tbody.innerHTML = items.map(item => {
    const srcBadge = item.source === "auto_scan"
      ? '<span class="badge badge-warning">自动防扫描</span>'
      : item.source === "brute_force"
        ? '<span class="badge badge-danger">密码爆破</span>'
        : '<span class="badge badge-primary">手动封禁</span>';

    let expHtml = '<span class="badge badge-outline">永久封禁</span>';
    if (item.expire_at && item.expire_at > 0) {
      const f = formatDateTime(item.expire_at);
      const sec = item.remaining_seconds || 0;
      const rem = sec > 86400 ? `剩余 ${Math.floor(sec / 86400)} 天`
        : sec > 3600 ? `剩余 ${Math.floor(sec / 3600)} 小时`
        : `剩余 ${Math.max(1, Math.floor(sec / 60))} 分钟`;
      expHtml = `<div class="ban-time-cell" title="${f.full}"><span class="ban-time-main">${f.short}</span><span class="ban-time-sub">${rem}</span></div>`;
    }
    const cf = formatDateTime(item.created_at);
    return `
      <tr>
        <td style="color:var(--text-dim);">#${item.id}</td>
        <td><span class="ban-ip-code">${escapeHtml(item.ip)}</span></td>
        <td>${srcBadge}</td>
        <td class="ban-reason-td">${formatBanReasonCell(item.reason, item.source)}</td>
        <td><div class="ban-time-cell" title="${cf.full}"><span class="ban-time-main">${cf.short}</span></div></td>
        <td>${expHtml}</td>
        <td><button class="btn btn-danger btn-sm" onclick="deleteBan(${item.id}, '${escapeHtml(item.ip)}')">解封</button></td>
      </tr>
    `;
  }).join("");
}

async function loadWhitelist() {
  const res = await api("/api/v1/whitelist");
  if (!res.success) return;
  whitelistCache = res.whitelist || [];
  const tbody = document.getElementById("whitelistTbody");
  if (!whitelistCache.length) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-dim); padding:2.5rem;">暂无自定义白名单（局域网与本机回环已默认自动豁免）</td></tr>`;
    return;
  }
  tbody.innerHTML = whitelistCache.map(item => {
    const cf = formatDateTime(item.created_at);
    return `
      <tr>
        <td style="color:var(--text-dim);">#${item.id}</td>
        <td><span class="wl-ip-code">${escapeHtml(item.entry)}</span></td>
        <td style="white-space:normal;">${escapeHtml(item.note || "-")}</td>
        <td><span class="ban-time-main" title="${cf.full}">${cf.short}</span></td>
        <td><button class="btn btn-outline btn-sm danger-text" onclick="deleteWhitelist(${item.id}, '${escapeHtml(item.entry)}')">移除</button></td>
      </tr>
    `;
  }).join("");
}

async function loadTraps() {
  const res = await api("/api/v1/trap_ports");
  if (!res.success) return;
  trapsCache = res.trap_ports || [];
  const tbody = document.getElementById("trapsTbody");
  if (!trapsCache.length) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-dim); padding:2.5rem;">暂未配置诱捕端口</td></tr>`;
    return;
  }
  tbody.innerHTML = trapsCache.map(t => {
    let stBadge = '<span class="badge badge-outline">已停用</span>';
    if (t.runtime_status === "listening") stBadge = '<span class="badge badge-success">● 实时监听中</span>';
    else if (t.runtime_status === "occupied") stBadge = '<span class="badge badge-warning">端口已被占用（已自动避让）</span>';
    else if (t.runtime_status === "permission_denied") stBadge = '<span class="badge badge-danger">低位端口需 root 权限</span>';
    else if (t.runtime_status === "pending") stBadge = '<span class="badge badge-primary">启动中...</span>';

    const lh = t.last_hit_at ? formatDateTime(t.last_hit_at).short : "-";
    return `
      <tr>
        <td><span class="port-code">:${t.port}</span></td>
        <td style="white-space:normal;">${escapeHtml(t.note || "-")}</td>
        <td>${stBadge}</td>
        <td style="font-weight:600; color:${t.hit_count > 0 ? "var(--warning)" : "var(--text-muted)"};">${t.hit_count || 0} 次</td>
        <td><span class="ban-time-main">${lh}</span></td>
        <td>
          <div style="display:flex; gap:0.4rem;">
            <button class="btn btn-outline btn-sm" onclick="toggleTrap(${t.id}, ${t.enabled ? "false" : "true"})">${t.enabled ? "停用" : "启用"}</button>
            <button class="btn btn-outline btn-sm danger-text" onclick="deleteTrap(${t.id}, ${t.port})">删除</button>
          </div>
        </td>
      </tr>
    `;
  }).join("");
}

async function loadSettings() {
  const res = await api("/api/v1/settings");
  if (!res.success) return;
  const s = res.settings;
  document.getElementById("setEnabled").checked = s.defense_enabled === "1";
  document.getElementById("setFullPort").checked = s.full_port_conntrack === "1";
  document.getElementById("setSshd").checked = s.sshd_monitor === "1";
  document.getElementById("setWeb").checked = s.web_monitor === "1";
  document.getElementById("setAutoUnban").checked = s.auto_unban_enabled !== "0";
  document.getElementById("setThreshold").value = s.threshold || "5";
  document.getElementById("setWindow").value = s.window_sec || "600";
  document.getElementById("setBanDuration").value = s.ban_duration || "86400";
  document.getElementById("setTrustedPorts").value = s.trusted_service_ports || "22,7000,7001,8024";
}

async function loadUnbanRequests() {
  const tbody = document.getElementById("unbanTbody");
  if (!tbody) return;
  const res = await api("/api/v1/unban_requests");
  if (!res.success) return;
  const items = res.requests || [];
  if (!items.length) {
    tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:var(--text-dim); padding:2.2rem;">暂无用户解封申请记录</td></tr>`;
    return;
  }
  tbody.innerHTML = items.map(r => {
    const cf = formatDateTime(r.created_at);
    const stBadge = r.status === "auto_approved"
      ? '<span class="badge badge-success">已自动解封</span>'
      : r.status === "approved"
        ? '<span class="badge badge-primary">已人工通过</span>'
        : r.status === "rejected"
          ? '<span class="badge badge-danger">已驳回</span>'
          : '<span class="badge badge-warning">待人工审核</span>';
    const actions = r.status === "pending"
      ? `<div style="display:flex; gap:0.35rem;"><button class="btn btn-primary btn-sm" onclick="handleUnbanDecision(${r.id}, true)">通过</button><button class="btn btn-outline btn-sm danger-text" onclick="handleUnbanDecision(${r.id}, false)">驳回</button></div>`
      : `<span class="muted">-</span>`;
    return `
      <tr>
        <td style="color:var(--text-dim);">#${r.id}</td>
        <td><span class="ban-ip-code">${escapeHtml(r.ip)}</span></td>
        <td style="white-space:normal; max-width:300px;">${escapeHtml(r.reason || "-")}</td>
        <td>${stBadge}</td>
        <td><span class="ban-time-main" title="${cf.full}">${cf.short}</span></td>
        <td>${actions}</td>
      </tr>
    `;
  }).join("");
}

async function handleUnbanDecision(id, approve) {
  const res = await api(approve ? "/api/v1/unban_requests/approve" : "/api/v1/unban_requests/reject", {
    method: "POST",
    body: JSON.stringify({ id }),
  });
  if (res.success) { showToast(res.message); refreshAll(); }
  else showToast(res.message || "操作失败", "error");
}

async function loadEvents() {
  const res = await api("/api/v1/events");
  if (!res.success) return;
  const list = document.getElementById("eventList");
  const evs = res.events || [];
  if (!evs.length) {
    list.innerHTML = `<div class="muted" style="text-align:center; padding:2rem;">暂无安全审计事件</div>`;
    return;
  }
  list.innerHTML = evs.map(e => {
    const f = formatDateTime(e.created_at);
    const badge = e.event_type === "ban" ? '<span class="badge badge-danger">封禁</span>'
      : e.event_type === "trap_hit" ? '<span class="badge badge-warning">诱捕触碰</span>'
      : e.event_type === "unban" ? '<span class="badge badge-outline">解封</span>'
      : '<span class="badge badge-success">白名单</span>';
    return `
      <div class="event-item">
        <div class="event-left">
          <div>${badge} <strong style="margin-left:0.35rem;">${escapeHtml(e.ip || "-")}</strong>${e.port ? ` <code>:${e.port}</code>` : ""}</div>
          <div class="muted">${escapeHtml(e.detail || "")}</div>
        </div>
        <div class="event-time" title="${f.full}">${f.short}</div>
      </div>
    `;
  }).join("");
}

// ----------------- Actions -----------------

async function submitAddBlacklist(e) {
  e.preventDefault();
  const res = await api("/api/v1/blacklist", {
    method: "POST",
    body: JSON.stringify({
      ip: document.getElementById("blIpInput").value,
      reason: document.getElementById("blReasonInput").value,
      expire_seconds: parseInt(document.getElementById("blDurationInput").value, 10),
    }),
  });
  if (res.success) {
    showToast(res.message);
    document.getElementById("blIpInput").value = "";
    closeModal("addBlacklistModal");
    refreshAll();
  } else {
    showToast(res.message || "封禁失败", "error");
  }
}

async function deleteBan(id, ip) {
  if (!confirm(`确认解封 IP ${ip}？`)) return;
  const res = await api("/api/v1/blacklist/delete", { method: "POST", body: JSON.stringify({ id, ip }) });
  if (res.success) { showToast(res.message); refreshAll(); }
  else showToast(res.message || "解封失败", "error");
}

async function clearAutoBans() {
  if (!confirm("确认清空所有自动防扫描/爆破拦截的记录（保留手动封禁）？")) return;
  const res = await api("/api/v1/blacklist/clear", { method: "POST", body: JSON.stringify({ source: "auto" }) });
  if (res.success) { showToast(res.message); refreshAll(); }
}

async function syncKernelFirewall() {
  const res = await api("/api/v1/blacklist/sync", { method: "POST", body: "{}" });
  if (res.success) { showToast(res.message); refreshAll(); }
}

async function submitAddWhitelist(e) {
  e.preventDefault();
  const res = await api("/api/v1/whitelist", {
    method: "POST",
    body: JSON.stringify({
      entry: document.getElementById("wlEntryInput").value,
      note: document.getElementById("wlNoteInput").value,
    }),
  });
  if (res.success) {
    showToast(res.message);
    document.getElementById("wlEntryInput").value = "";
    document.getElementById("wlNoteInput").value = "";
    closeModal("addWhitelistModal");
    refreshAll();
  } else {
    showToast(res.message || "添加白名单失败", "error");
  }
}

async function deleteWhitelist(id, entry) {
  if (!confirm(`确认将 ${entry} 移出白名单？`)) return;
  const res = await api("/api/v1/whitelist/delete", { method: "POST", body: JSON.stringify({ id, entry }) });
  if (res.success) { showToast(res.message); refreshAll(); }
}

function fillTrapPreset(ports, note) {
  document.getElementById("trapPortInput").value = ports;
  document.getElementById("trapNoteInput").value = note;
}

async function submitAddTrap(e) {
  e.preventDefault();
  const res = await api("/api/v1/trap_ports", {
    method: "POST",
    body: JSON.stringify({
      ports: document.getElementById("trapPortInput").value,
      note: document.getElementById("trapNoteInput").value,
    }),
  });
  if (res.success) {
    showToast(res.message);
    document.getElementById("trapPortInput").value = "";
    document.getElementById("trapNoteInput").value = "";
    closeModal("addTrapModal");
    refreshAll();
  } else {
    showToast(res.message || "添加诱捕端口失败", "error");
  }
}

async function toggleTrap(id, enabled) {
  const res = await api("/api/v1/trap_ports/toggle", { method: "POST", body: JSON.stringify({ id, enabled }) });
  if (res.success) { showToast(res.message); refreshAll(); }
}

async function deleteTrap(id, port) {
  if (!confirm(`确认删除诱捕端口 :${port}？`)) return;
  const res = await api("/api/v1/trap_ports/delete", { method: "POST", body: JSON.stringify({ id }) });
  if (res.success) { showToast(res.message); refreshAll(); }
}

async function saveSettings(e) {
  e.preventDefault();
  const payload = {
    defense_enabled: document.getElementById("setEnabled").checked ? "1" : "0",
    full_port_conntrack: document.getElementById("setFullPort").checked ? "1" : "0",
    sshd_monitor: document.getElementById("setSshd").checked ? "1" : "0",
    web_monitor: document.getElementById("setWeb").checked ? "1" : "0",
    auto_unban_enabled: document.getElementById("setAutoUnban").checked ? "1" : "0",
    threshold: document.getElementById("setThreshold").value,
    window_sec: document.getElementById("setWindow").value,
    ban_duration: document.getElementById("setBanDuration").value,
    trusted_service_ports: document.getElementById("setTrustedPorts").value,
  };
  const res = await api("/api/v1/settings", { method: "POST", body: JSON.stringify(payload) });
  if (res.success) { showToast(res.message); refreshAll(); }
  else showToast(res.message || "保存失败", "error");
}

async function handleChangePassword(e) {
  e.preventDefault();
  const res = await api("/api/v1/auth/password", {
    method: "POST",
    body: JSON.stringify({
      old_password: document.getElementById("oldPwd").value,
      new_password: document.getElementById("newPwd").value,
    }),
  });
  if (res.success) {
    showToast(res.message);
    document.getElementById("oldPwd").value = "";
    document.getElementById("newPwd").value = "";
  } else {
    showToast(res.message || "修改失败", "error");
  }
}

async function checkSystemUpdate(switchToTab = false) {
  if (switchToTab) switchTab("settings");
  const titleEl = document.getElementById("updateStatusTitle");
  const descEl = document.getElementById("updateStatusDesc");
  const btnCheck = document.getElementById("btnCheckUpdate");
  const btnUp = document.getElementById("btnDoUpgrade");
  const topBtn = document.getElementById("topUpdateBtn");

  if (btnCheck) { btnCheck.disabled = true; btnCheck.textContent = "检测中..."; }
  if (titleEl) titleEl.textContent = "正在连接 GitHub 检测最新版本...";
  if (btnUp) btnUp.style.display = "none";

  const res = await api("/api/v1/system/check_update");
  if (btnCheck) { btnCheck.disabled = false; btnCheck.textContent = "🔍 检测更新"; }

  if (!res.success) {
    if (titleEl) titleEl.textContent = "检测更新失败";
    if (descEl) descEl.textContent = res.message || "请检查服务器网络连接";
    showToast(res.message || "检测更新失败", "error");
    return;
  }

  const localVer = res.local?.commit || "unknown";
  const remoteVer = res.remote?.commit || "unknown";
  const remoteMsg = res.remote?.message ? ` · ${res.remote.message}` : "";

  if (res.has_update) {
    if (titleEl) titleEl.innerHTML = `<span style="color:var(--warning);">🚀 发现新版本 (${escapeHtml(remoteVer)})</span>`;
    if (descEl) descEl.textContent = `当前版本: ${localVer} → 最新版本: ${remoteVer}${remoteMsg}`;
    if (btnUp && res.can_online_upgrade) btnUp.style.display = "inline-flex";
    if (topBtn) topBtn.textContent = "🚀 有新版本";
    showToast(`发现新版本 ${remoteVer}，可一键在线更新`);
  } else {
    if (titleEl) titleEl.innerHTML = `<span style="color:var(--success);">✅ 当前已是最新版本 (${escapeHtml(localVer)})</span>`;
    if (descEl) descEl.textContent = res.local?.message ? `最近提交: ${res.local.message} (${res.local.date || ""})` : `本地与远端提交一致 (${remoteVer})`;
    if (topBtn) topBtn.textContent = "🔍 检测更新";
    showToast("当前已是最新版本");
  }
}

async function triggerSystemUpgrade() {
  if (!confirm("确认拉取 GitHub 最新版本并重启 Cosmo Firewall？（您的黑名单、白名单与诱捕端口数据将被完整保留）")) return;
  const btnUp = document.getElementById("btnDoUpgrade");
  if (btnUp) { btnUp.disabled = true; btnUp.textContent = "更新中..."; }

  const res = await api("/api/v1/system/upgrade", { method: "POST", body: "{}" });
  if (res.success) {
    showToast(res.message || "更新成功，页面即将自动刷新...");
    setTimeout(() => window.location.reload(), 3500);
  } else {
    if (btnUp) { btnUp.disabled = false; btnUp.textContent = "⬆️ 一键在线更新"; }
    showToast(res.message || "在线更新失败", "error");
  }
}

// Init
(async function init() {
  const savedTheme = localStorage.getItem("cosmo_fw_theme") || "dark";
  document.documentElement.setAttribute("data-theme", savedTheme);
  document.getElementById("themeBtn").textContent = savedTheme === "dark" ? "☀️ 浅色" : "🌙 深色";

  if (authToken) {
    const me = await api("/api/v1/auth/me");
    if (me.success && me.user) {
      showApp(me.user);
      return;
    }
  }
  showLogin();
})();
