"use strict";

const $ = (id) => document.getElementById(id);

function showNotice(message) {
  const notice = $("notice");
  notice.textContent = message;
  notice.hidden = !message;
}

function setRows(target, rows, emptyText) {
  target.replaceChildren();
  if (!rows.length) {
    target.className = "list empty";
    target.textContent = emptyText;
    return;
  }
  target.className = "list";
  for (const row of rows) {
    const item = document.createElement("div");
    item.className = "row";
    const copy = document.createElement("div");
    const title = document.createElement("strong");
    const detail = document.createElement("small");
    const state = document.createElement("span");
    title.textContent = row.title;
    detail.textContent = row.detail;
    state.textContent = row.state;
    state.className = `state ${row.tone || ""}`;
    copy.append(title, detail);
    item.append(copy, state);
    target.append(item);
  }
}

async function getJson(path) {
  const response = await fetch(path, { credentials: "same-origin", cache: "no-store" });
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  return response.json();
}

async function refresh() {
  showNotice("");
  try {
    const dashboard = await getJson("/api/dashboard");
    const summary = dashboard.summary || {};
    $("mode").textContent = dashboard.mode || "unknown";
    $("version").textContent = summary.version ?? "—";
    $("routes").textContent = summary.routes ?? "—";
    $("services").textContent = summary.upstream_services ?? "—";
    $("ready").textContent = dashboard.ready ? "READY" : "NOT READY";
    $("ready").style.color = dashboard.ready ? "var(--cyan)" : "var(--red)";
    setRows(
      $("health"),
      (dashboard.health || []).map((service) => ({
        title: service.service,
        detail: `${service.healthy}/${service.total} instances healthy`,
        state: service.total > 0 && service.healthy === service.total ? "HEALTHY" : "DEGRADED",
        tone: service.total > 0 && service.healthy === service.total ? "" : "bad",
      })),
      "暂无健康探测数据",
    );
    const events = (dashboard.history?.events || []).slice(-8).reverse();
    setRows(
      $("history"),
      events.map((event) => ({
        title: `${event.trigger} · v${event.new_version ?? event.candidate_version ?? "?"}`,
        detail: event.error || `from v${event.old_version}`,
        state: event.status,
        tone: event.status === "rejected" ? "bad" : "",
      })),
      "暂无配置事件",
    );
    try {
      const audit = await getJson("/api/audit");
      setRows(
        $("audit"),
        (audit.events || []).slice(-10).reverse().map((event) => ({
          title: `${event.payload.principal} · ${event.payload.action}`,
          detail: `${event.payload.method} ${event.payload.path} · ${event.payload.phase}`,
          state: event.payload.status ?? "PENDING",
          tone: event.payload.status >= 400 ? "bad" : "",
        })),
        "暂无审计事件",
      );
    } catch (error) {
      setRows($("audit"), [], "审计数据不可用或当前角色无权限");
    }
  } catch (error) {
    showNotice(error instanceof Error ? error.message : String(error));
  }
}

// ── P0-2 配置发布闭环:载入(带 ETag)→ 编辑 → If-Match CAS 发布 → 确认生效 ──
//
// ETag 是发布的**唯一并发凭据**:它由服务端按整份配置集(含依赖文件)算出。这里只保存
// 载入时拿到的那一个,发布成功后立刻用响应里的新 ETag 覆盖——绝不自己拼造或复用旧值,
// 否则等于把 CAS 变成盲写。
let configEtag = null;

function setConfigMeta(text, tone) {
  const meta = $("config-meta");
  meta.textContent = text;
  meta.className = tone ? `muted ${tone}` : "muted";
}

async function loadCurrentConfig() {
  showNotice("");
  try {
    const response = await fetch("/api/config/current", {
      credentials: "same-origin",
      cache: "no-store",
    });
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
    $("candidate").value = payload.content || "";
    configEtag = payload.etag || response.headers.get("etag");
    $("config-publish").disabled = !configEtag;
    setConfigMeta(`v${payload.version} · ${payload.source} · ${configEtag}`);
  } catch (error) {
    configEtag = null;
    $("config-publish").disabled = true;
    setConfigMeta("载入失败", "bad");
    showNotice(error instanceof Error ? error.message : String(error));
  }
}

async function publishCurrentConfig() {
  showNotice("");
  if (!configEtag) {
    showNotice("请先载入当前配置以取得 ETag(发布必须携带 If-Match)");
    return;
  }
  const button = $("config-publish");
  button.disabled = true;
  try {
    const response = await fetch("/api/config/current", {
      method: "PUT",
      headers: { "content-type": "application/yaml", "if-match": configEtag },
      credentials: "same-origin",
      body: $("candidate").value,
    });
    const payload = await response.json();
    if (response.status === 412) {
      // 别人先改了:服务端回带当前 ETag,提示用户 rebase,而不是让他反复盲发。
      configEtag = payload.etag || configEtag;
      setConfigMeta("配置已被他人更新", "bad");
      showNotice("发布冲突:配置在你编辑期间已变更。请重新载入当前配置后再改(rebase)。");
      return;
    }
    if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
    if (payload.status === "applied") {
      configEtag = payload.etag || response.headers.get("etag");
      setConfigMeta(`v${payload.version} · applied · ${configEtag}`);
      showNotice(`已生效:版本 v${payload.version}(网关已确认换版,非仅调度 reload)`);
    } else if (payload.status === "published") {
      // 集群(Nacos)路径:CAS 已写回事实源,各节点靠 watch 收敛,这里只能说"已发布"。
      setConfigMeta(`rollout ${payload.rollout_id}`, "");
      showNotice(`已 CAS 发布到集群(rollout ${payload.rollout_id});下方 rollout 面板显示各节点收敛进度`);
    } else {
      setConfigMeta(payload.status || "pending", "bad");
      showNotice(`发布已提交但尚未确认生效(${payload.status});可查看最近变更或稍后刷新`);
    }
    await refresh();
  } catch (error) {
    setConfigMeta("发布被拒绝", "bad");
    showNotice(error instanceof Error ? error.message : String(error));
  } finally {
    button.disabled = !configEtag;
  }
}

// ── P0-3 集群页:节点收敛 + rollout 进度 ──
//
// 收敛判据与后端一致:**版本一致还不够,指纹也必须一致**——同版本不同内容意味着某节点
// 从别处物化了不同配置,只看版本号会把分叉误显示成"已收敛"。
async function refreshCluster() {
  try {
    const cluster = await getJson("/admin/cluster/consistency");
    const nodes = cluster.nodes || [];
    let state = cluster.converged ? "CONVERGED" : "DIVERGED";
    if (cluster.fingerprint_unknown) state = "UNKNOWN FINGERPRINT";
    $("cluster-state").textContent = `${state} · ${nodes.length} 节点`;
    $("cluster-state").className = cluster.converged ? "muted" : "muted bad";
    setRows(
      $("cluster-nodes"),
      nodes.map((node) => ({
        title: `${node.node_id || `${node.ip}:${node.port}`}`,
        detail: `v${node.version ?? "?"} · fp ${node.fingerprint ?? "未上报"}`
          + (node.started_at_ms ? ` · 启动 ${new Date(node.started_at_ms).toLocaleString()}` : ""),
        state: node.enabled ? (node.healthy ? "UP" : "UNHEALTHY") : "DISABLED",
        tone: node.enabled && node.healthy ? "" : "bad",
      })),
      "集群成员为空",
    );
  } catch (error) {
    $("cluster-state").textContent = "不可用";
    setRows($("cluster-nodes"), [], "仅 Nacos 自注册集群可见(单机部署无此视图)");
  }
  try {
    const rollout = await getJson("/api/cluster/rollout");
    $("rollout-state").textContent = `${rollout.status} · base v${rollout.rollout?.base_version ?? "?"}`;
    $("rollout-state").className = rollout.converged ? "muted" : "muted bad";
    const pending = rollout.pending_nodes || [];
    setRows(
      $("rollout-nodes"),
      (rollout.cluster?.nodes || []).map((node) => {
        const label = node.node_id || `${node.ip}:${node.port}`;
        return {
          title: label,
          detail: `v${node.version ?? "?"} · fp ${node.fingerprint ?? "未上报"}`,
          state: pending.includes(label) ? "PENDING" : "APPLIED",
          tone: pending.includes(label) ? "bad" : "",
        };
      }),
      "本次 rollout 无成员数据",
    );
  } catch (error) {
    $("rollout-state").textContent = "无";
    setRows($("rollout-nodes"), [], "本节点尚未发起集群发布");
  }
}

// ── P0-3 C2b 上游拓扑:服务 / 来源 / LB 策略 / 实例 / 健康 ──
//
// 口径必须说清楚,否则这个面板会骗人:`/admin/upstreams` 的 `healthy` 是**发现态**
// (静态 yml 的标记,或注册中心 last-known-good),**不含主动探测结果**——后端注释明确
// 说明主动探测判死由 `/metrics` 的 `gw_upstream_healthy{service}` 反映,不并入此视图,
// 以免管理视图与探测器强耦合。所以这里一律用"可选"而非"健康"措辞,并在空态里点明差异。
async function refreshTopology() {
  try {
    const payload = await getJson("/admin/upstreams");
    const services = payload.services || [];
    const degraded = services.filter((svc) => (svc.selectable_count ?? 0) < (svc.instance_count ?? 0));
    $("topology-state").textContent = `${services.length} 服务 · ${degraded.length} 有不可选实例`;
    $("topology-state").className = degraded.length ? "muted bad" : "muted";
    const rows = [];
    for (const svc of services) {
      const selectable = svc.selectable_count ?? 0;
      const total = svc.instance_count ?? 0;
      const refs = svc.route_refs || [];
      rows.push({
        title: svc.service + (svc.critical ? " (critical)" : ""),
        detail: `${svc.source} · ${svc.lb_policy || "?"} · `
          + (refs.length ? `引用 ${refs.join(", ")}` : "无路由引用"),
        state: `${selectable}/${total} 可选`,
        // critical 服务一个可选实例都没有就是 readyz 会翻红的那种状态,单独标出来。
        tone: selectable === 0 ? "bad" : selectable < total ? "warn" : "",
      });
      for (const inst of svc.instances || []) {
        const flags = [];
        if (inst.backup) flags.push("backup");
        if (inst.tls) flags.push(inst.tls_server_name ? `tls→${inst.tls_server_name}` : "tls");
        if (inst.weight !== undefined && inst.weight !== 1) flags.push(`w=${inst.weight}`);
        rows.push({
          title: `↳ ${inst.uri}`,
          detail: flags.length ? flags.join(" · ") : "—",
          state: inst.down ? "DOWN" : inst.healthy ? "可选" : "不可选",
          tone: inst.down || !inst.healthy ? "bad" : "",
        });
      }
    }
    setRows($("topology"), rows, "未配置任何上游服务");
  } catch (error) {
    $("topology-state").textContent = "不可用";
    setRows($("topology"), [], "无法读取 /admin/upstreams(主动探测结果见 /metrics 的 gw_upstream_healthy)");
  }
}

$("config-load").addEventListener("click", loadCurrentConfig);
$("config-publish").addEventListener("click", publishCurrentConfig);
$("refresh").addEventListener("click", refresh);
$("dry-run").addEventListener("click", async () => {
  showNotice("");
  try {
    const candidate = $("candidate").value;
    const result = candidate.trim()
      ? await fetch("/api/config/dry-run", {
          method: "POST",
          headers: { "content-type": "application/yaml" },
          credentials: "same-origin",
          body: candidate,
        }).then(async (response) => {
          const payload = await response.json();
          if (!response.ok) throw new Error(payload.error || `HTTP ${response.status}`);
          return payload;
        })
      : await getJson("/admin/config/dry-run");
    showNotice(`Dry run 通过：候选版本 v${result.summary?.version ?? "?"}`);
  } catch (error) {
    showNotice(error instanceof Error ? error.message : String(error));
  }
});

function refreshAll() {
  refresh();
  refreshCluster();
  refreshTopology();
}

refreshAll();
window.setInterval(refreshAll, 15000);
