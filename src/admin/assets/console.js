"use strict";

/**
 * 业务作用：按页面固定标识取得控件，不解析服务端提供的选择器。
 *
 * 参数说明：
 * - `id`：固定控件标识。
 *
 * 返回：返回对应 DOM 元素；不存在时为 null。
 */
const $ = (id) => document.getElementById(id);

/**
 * 业务作用：以纯文本展示当前操作提示，空提示隐藏通知区。
 *
 * 参数说明：
 * - `message`：当前低敏操作提示。
 *
 * 返回：更新通知文本与可见性。
 */
function showNotice(message) {
  const notice = $("notice");
  notice.textContent = message;
  notice.hidden = !message;
}

/**
 * 业务作用：将低敏读模型渲染为文本列表，空结果明确展示为空而不保留旧数据。
 *
 * 参数说明：
 * - `target`：本地固定列表容器。
 * - `rows`：已读取的低敏行模型。
 * - `emptyText`：无记录时展示的文本。
 *
 * 返回：替换目标区域中的列表或空状态。
 */
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

/**
 * 业务作用：以当前同源会话读取管理 JSON，失败状态不当成成功数据。
 *
 * 参数说明：
 * - `path`：页面固定的同源管理路径。
 *
 * 返回：返回解析后的 JSON；HTTP 或解析失败抛出错误。
 */
async function getJson(path) {
  const response = await fetch(path, {
    credentials: "same-origin",

    cache: "no-store",
  });
  if (!response.ok) {
    throw new Error(`${path}: HTTP ${response.status}`);
  }
  return response.json();
}

/**
 * 业务作用：从公开管理读模型更新运行概况和治理目录，读取失败不保留为成功状态。
 *
 * 参数说明: 无。
 *
 * 返回：更新页面状态；权限不足时展示对应读面不可用，不触发配置变更。
 */
async function refresh() {
  showNotice("");
  try {
    const dashboard = await getJson("/api/dashboard");
    const summary = dashboard.summary || {};
    renderTelemetry(dashboard.telemetry);
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

        state:
          service.total > 0 && service.healthy === service.total
            ? "HEALTHY"
            : "DEGRADED",

        tone:
          service.total > 0 && service.healthy === service.total ? "" : "bad",
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
        (audit.events || [])
          .slice(-10)
          .reverse()
          .map((event) => ({
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

/**
 * 业务作用：从公开固定指标目录展示治理概况，不读取路由内部状态或内容。
 *
 * 参数说明：
 * - `profile`：可选的 schema_version=1 固定指标读模型。
 *
 * 返回：更新低敏计数；关闭或未知 schema 时隐藏面板并清除旧值。
 */
function renderTelemetry(profile) {
  const active =
    profile?.schema_version === 1 && Array.isArray(profile.metrics);
  $("telemetry-panel").hidden = !active;
  if (!active) {
    $("telemetry").replaceChildren();
    return;
  }
  const fixed = [
    ["gw_telemetry_export_total", "遥测出口"],
    ["gw_admission_events_total", "重试预算与自适应并发"],
    ["gw_ext_proc_exchange_total", "外部处理相位"],
    ["gw_waf_requests_total", "WAF 介入"],
    ["gw_ai_operations_summary_total", "AI / MCP / A2A"],
    ["gw_rollout_transitions_total", "发布状态迁移"],
  ];
  setRows(
    $("telemetry"),
    fixed.map(([name, title]) => {
      const points = profile.metrics.filter(
        (point) =>
          point.name === name &&
          typeof point.value === "number" &&
          Number.isFinite(point.value),
      );
      const activePoints = points.filter((point) => point.value > 0);
      return {
        title,

        detail:
          activePoints
            .slice(0, 12)
            .map(
              (point) =>
                `${Object.values(point.labels).join(" / ")}: ${point.value}`,
            )
            .join(" · ") || "暂无事件",

        state: String(points.reduce((sum, point) => sum + point.value, 0)),
      };
    }),
    "暂无遥测数据",
  );
}

// 配置发布闭环：载入 ETag → 编辑 → If-Match CAS 发布 → 确认生效。
//
// ETag 是发布的**唯一并发凭据**:它由服务端按整份配置集(含依赖文件)算出。这里只保存
// 载入时拿到的那一个,发布成功后立刻用响应里的新 ETag 覆盖——绝不自己拼造或复用旧值,
// 否则等于把 CAS 变成盲写。
let configEtag = null;

/**
 * 业务作用：以文本标记配置基线与发布状态，不将服务端内容解释为 HTML。
 *
 * 参数说明：
 * - `text`：配置版本、ETag 或发布状态文本。
 * - `tone`：本地预定义状态样式。
 *
 * 返回：更新基线文本与状态样式。
 */
function setConfigMeta(text, tone) {
  const meta = $("config-meta");
  meta.textContent = text;
  meta.className = tone ? `muted ${tone}` : "muted";
}

/**
 * 业务作用：载入当前配置与服务端 ETag，只有取得并发基线后才允许发布。
 *
 * 参数说明: 无。
 *
 * 返回：成功时更新编辑器与基线；失败清空 ETag 并关闭发布入口。
 */
async function loadCurrentConfig() {
  showNotice("");
  try {
    const response = await fetch("/api/config/current", {
      credentials: "same-origin",

      cache: "no-store",
    });
    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload.error || `HTTP ${response.status}`);
    }
    $("candidate").value = payload.content || "";
    configEtag = payload.etag || response.headers.get("etag");
    $("config-publish").disabled = !configEtag;
    $("config-diff").disabled = !configEtag;
    setConfigMeta(`v${payload.version} · ${payload.source} · ${configEtag}`);
  } catch (error) {
    configEtag = null;
    $("config-publish").disabled = true;
    $("config-diff").disabled = true;
    setConfigMeta("载入失败", "bad");
    showNotice(error instanceof Error ? error.message : String(error));
  }
}

/**
 * 业务作用：携带已读取的 ETag 提交候选配置，并区分应用成功、审批等待与并发冲突。
 *
 * 参数说明: 无。
 *
 * 返回：显示服务端真实提交状态；失败或冲突不自动重试发布。
 */
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

      headers: {
        "content-type": "application/yaml",
        "if-match": configEtag,
      },

      credentials: "same-origin",

      body: $("candidate").value,
    });
    const payload = await response.json();
    if (response.status === 412) {
      // 别人先改了:服务端回带当前 ETag,提示用户 rebase,而不是让他反复盲发。
      configEtag = payload.etag || configEtag;
      setConfigMeta("配置已被他人更新", "bad");
      showNotice(
        "发布冲突:配置在你编辑期间已变更。请重新载入当前配置后再改(rebase)。",
      );
      return;
    }
    if (!response.ok) {
      throw new Error(payload.error || `HTTP ${response.status}`);
    }
    if (payload.status === "applied") {
      configEtag = payload.etag || response.headers.get("etag");
      setConfigMeta(`v${payload.version} · applied · ${configEtag}`);
      showNotice(
        `已生效:版本 v${payload.version}(网关已确认换版,非仅调度 reload)`,
      );
    } else if (
      payload.status === "published" ||
      payload.status === "canary_published"
    ) {
      // 集群(Nacos)路径:CAS 已写回事实源,各节点靠 watch 收敛,这里只能说"已发布"。
      setConfigMeta(`rollout ${payload.rollout_id}`, "");
      showNotice(
        `已 CAS 发布到集群(rollout ${payload.rollout_id});下方 rollout 面板显示各节点收敛进度`,
      );
    } else if (payload.status === "awaiting_approval") {
      setConfigMeta(`change ${payload.change_id}`, "");
      showNotice(
        `变更 ${payload.change_id} 已登记，需另一名有权主体复核后执行`,
      );
    } else {
      setConfigMeta(payload.status || "pending", "bad");
      showNotice(
        `发布已提交但尚未确认生效(${payload.status});可查看最近变更或稍后刷新`,
      );
    }
    await refresh();
  } catch (error) {
    setConfigMeta("发布被拒绝", "bad");
    showNotice(error instanceof Error ? error.message : String(error));
  } finally {
    button.disabled = !configEtag;
  }
}

// 集群页：节点收敛与 rollout 进度。
//
// 收敛判据与后端一致:**版本一致还不够,指纹也必须一致**——同版本不同内容意味着某节点
// 从别处物化了不同配置,只看版本号会把分叉误显示成"已收敛"。
/**
 * 业务作用：展示集群成员的版本与内容指纹，避免把同版本的配置分叉误判为收敛。
 *
 * 参数说明: 无。
 *
 * 返回：更新成员和收敛视图，读取失败显示不可用。
 */
async function refreshCluster() {
  try {
    const cluster = await getJson("/admin/cluster/consistency");
    const nodes = cluster.nodes || [];
    let state = cluster.converged ? "CONVERGED" : "DIVERGED";
    if (cluster.fingerprint_unknown) {
      state = "UNKNOWN FINGERPRINT";
    }
    $("cluster-state").textContent = `${state} · ${nodes.length} 节点`;
    $("cluster-state").className = cluster.converged ? "muted" : "muted bad";
    setRows(
      $("cluster-nodes"),
      nodes.map((node) => ({
        title: `${node.node_id || `${node.ip}:${node.port}`}`,

        detail:
          `v${node.version ?? "?"} · fp ${node.fingerprint ?? "未上报"}` +
          (node.started_at_ms
            ? ` · 启动 ${new Date(node.started_at_ms).toLocaleString()}`
            : ""),

        state: node.enabled ? (node.healthy ? "UP" : "UNHEALTHY") : "DISABLED",

        tone: node.enabled && node.healthy ? "" : "bad",
      })),
      "集群成员为空",
    );
  } catch (error) {
    $("cluster-state").textContent = "不可用";
    setRows(
      $("cluster-nodes"),
      [],
      "仅 Nacos 自注册集群可见(单机部署无此视图)",
    );
  }
  try {
    const rollout = await getJson("/api/cluster/rollout");
    $("rollout-state").textContent =
      `${rollout.status} · base v${rollout.rollout?.base_version ?? "?"}`;
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

// 上游拓扑：服务、来源、负载策略、实例和健康事实。
//
// 口径必须说清楚,否则这个面板会骗人:`/admin/upstreams` 的 `healthy` 是**发现态**
// (静态 yml 的标记,或注册中心 last-known-good),**不含主动探测结果**——后端注释明确
// 说明主动探测判死由 `/metrics` 的 `gw_upstream_healthy{service}` 反映,不并入此视图,
// 以免管理视图与探测器强耦合。所以这里一律用"可选"而非"健康"措辞,并在空态里点明差异。
/**
 * 业务作用：展示路由与上游可选拓扑，将静态可选状态与主动健康结果区分。
 *
 * 参数说明: 无。
 *
 * 返回：更新可选拓扑与明确空态，不据此宣称上游探测健康。
 */
async function refreshTopology() {
  try {
    const payload = await getJson("/admin/upstreams");
    const services = payload.services || [];
    const degraded = services.filter(
      (svc) => (svc.selectable_count ?? 0) < (svc.instance_count ?? 0),
    );
    $("topology-state").textContent =
      `${services.length} 服务 · ${degraded.length} 有不可选实例`;
    $("topology-state").className = degraded.length ? "muted bad" : "muted";
    const rows = [];
    for (const svc of services) {
      const selectable = svc.selectable_count ?? 0;
      const total = svc.instance_count ?? 0;
      const refs = svc.route_refs || [];
      rows.push({
        title: svc.service + (svc.critical ? " (critical)" : ""),

        detail:
          `${svc.source} · ${svc.lb_policy || "?"} · ` +
          (refs.length ? `引用 ${refs.join(", ")}` : "无路由引用"),

        state: `${selectable}/${total} 可选`,
        // critical 服务一个可选实例都没有就是 readyz 会翻红的那种状态,单独标出来。

        tone: selectable === 0 ? "bad" : selectable < total ? "warn" : "",
      });
      for (const inst of svc.instances || []) {
        const flags = [];
        if (inst.backup) {
          flags.push("backup");
        }
        if (inst.tls) {
          flags.push(
            inst.tls_server_name ? `tls→${inst.tls_server_name}` : "tls",
          );
        }
        if (inst.weight !== undefined && inst.weight !== 1) {
          flags.push(`w=${inst.weight}`);
        }
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
    setRows(
      $("topology"),
      [],
      "无法读取 /admin/upstreams(主动探测结果见 /metrics 的 gw_upstream_healthy)",
    );
  }
}

// ── 节点流量：各节点 QPS / 5xx / 活跃连接 ──
//
// 数据来自本节点用**自己的 admin 凭据**抓取同集群其它节点的 /metrics(需显式开启
// `admin.auth.allow_cluster_metrics_scrape`)。抓不到的节点显示失败原因而**不显示 0**——
// 把抓不到画成"没流量"会让运维得出完全相反的结论。
/**
 * 业务作用：展示逐节点流量采集结果，保留不可抓取与真实零流量的区别。
 *
 * 参数说明: 无。
 *
 * 返回：更新节点采集状态与流量，未启用时给出配置条件。
 */
async function refreshNodeTraffic() {
  try {
    const payload = await getJson("/api/cluster/metrics");
    const nodes = payload.nodes || [];
    $("node-traffic-state").textContent =
      `${payload.reachable}/${payload.total} 可达`;
    $("node-traffic-state").className =
      payload.reachable === payload.total ? "muted" : "muted bad";
    setRows(
      $("node-traffic"),
      nodes.map((node) => {
        if (!node.ok) {
          return {
            title: node.node_id,

            detail: `${node.admin_listen} · ${node.reason}`,

            state: "抓取失败",

            tone: "bad",
          };
        }
        const qps = Number.isFinite(node.qps) ? node.qps.toFixed(2) : "?";
        const errorRate = Number.isFinite(node.responses_5xx_per_second)
          ? node.responses_5xx_per_second.toFixed(2)
          : "?";
        return {
          title: node.node_id,

          detail: `${node.admin_listen} · QPS ${qps} · 5xx/s ${errorRate}`,

          state: `${node.active_connections ?? "?"} 活跃`,

          tone:
            Number.isFinite(node.responses_5xx_per_second) &&
            node.responses_5xx_per_second > 0
              ? "warn"
              : "",
        };
      }),
      "集群成员为空",
    );
  } catch (error) {
    // 409 = 开关未开或未启用自注册;两者都是配置问题,不是故障。
    $("node-traffic-state").textContent = "未启用";
    setRows(
      $("node-traffic"),
      [],
      "需 discovery.nacos.self_register 与 admin.auth.allow_cluster_metrics_scrape 同时开启",
    );
  }
}

/**
 * 业务作用：向同源管理 API 提交显式请求，只有成功 HTTP 状态才交付 JSON。
 *
 * 参数说明：
 * - `path`：页面固定的同源管理路径。
 * - `options`：由显式页面动作提供的方法、请求头与正文。
 *
 * 返回：返回原 Response 与 JSON；非成功状态或解析失败抛出错误。
 */
async function requestJson(path, options = {}) {
  const response = await fetch(path, {
    credentials: "same-origin",

    cache: "no-store",

    ...options,
  });
  const payload = await response.json();
  if (!response.ok) {
    throw new Error(payload.error || `${path}: HTTP ${response.status}`);
  }
  return {
    response,
    payload,
  };
}

/**
 * 业务作用：以纯文本显示结构化结果，避免服务端字段注入页面标记。
 *
 * 参数说明：
 * - `target`：本地固定结果容器。
 * - `value`：准备以文本显示的低敏 JSON 值。
 *
 * 返回：打开结果区域并显示格式化文本。
 */
function renderJson(target, value) {
  target.hidden = false;
  target.textContent = JSON.stringify(value, null, 2);
}

/**
 * 业务作用：对编辑中的完整候选执行只读语义差异分析，不提交配置。
 *
 * 参数说明: 无。
 *
 * 返回：显示差异结果；失败只显示错误，不修改配置。
 */
async function runConfigDiff() {
  showNotice("");
  try {
    const { payload } = await requestJson("/api/config/all/diff", {
      method: "POST",

      headers: { "content-type": "application/yaml" },

      body: $("candidate").value,
    });
    renderJson($("config-diff-result"), payload.diff);
  } catch (error) {
    showNotice(error instanceof Error ? error.message : String(error));
  }
}

/**
 * 业务作用：用页面声明的方法、路径与 Host 请求路由解释，不转发真实业务请求。
 *
 * 参数说明: 无。
 *
 * 返回：显示匹配路径与策略解释，失败展示错误。
 */
async function runExplain() {
  showNotice("");
  const headers = {};
  if ($("explain-host").value.trim()) {
    headers.host = $("explain-host").value.trim();
  }
  try {
    const { payload } = await requestJson("/api/explain", {
      method: "POST",

      headers: { "content-type": "application/json" },

      body: JSON.stringify({
        method: $("explain-method").value,

        path: $("explain-path").value || "/",

        headers,
      }),
    });
    renderJson($("explain-result"), payload);
  } catch (error) {
    $("explain-result").textContent =
      error instanceof Error ? error.message : String(error);
  }
}

/**
 * 业务作用：载入 Sentinel 规则与整体配置 ETag，为后续 CAS 发布取得基线。
 *
 * 参数说明: 无。
 *
 * 返回：成功后允许携带基线发布；读取失败禁用发布并提示。
 */
async function loadSentinel() {
  showNotice("");
  try {
    const { response, payload } = await requestJson("/api/sentinel");
    $("sentinel-candidate").value = payload.content || "";
    configEtag = payload.etag || response.headers.get("etag");
    $("sentinel-publish").disabled = !configEtag;
  } catch (error) {
    $("sentinel-publish").disabled = true;
    showNotice(error instanceof Error ? error.message : String(error));
  }
}

/**
 * 业务作用：以整体配置 ETag 提交 Sentinel 候选，保留四眼审批和并发拒绝语义。
 *
 * 参数说明: 无。
 *
 * 返回：显示生效或待审批状态并刷新读面；异常不自动重放。
 */
async function publishSentinel() {
  if (!configEtag) {
    showNotice("请先载入 Sentinel 文档以取得整体配置 ETag");
    return;
  }
  const button = $("sentinel-publish");
  button.disabled = true;
  try {
    const { payload } = await requestJson("/api/sentinel", {
      method: "PUT",

      headers: {
        "content-type": "application/yaml",
        "if-match": configEtag,
      },

      body: $("sentinel-candidate").value,
    });
    showNotice(
      payload.status === "awaiting_approval"
        ? `Sentinel 变更 ${payload.change_id} 等待另一主体复核`
        : `Sentinel 变更状态：${payload.status || "applied"}`,
    );
    await refreshAdvanced();
  } catch (error) {
    showNotice(error instanceof Error ? error.message : String(error));
  } finally {
    button.disabled = !configEtag;
  }
}

/**
 * 业务作用：展示待复核变更并将按钮绑定到服务端候选身份，终态记录不开放复核。
 *
 * 参数说明：
 * - `changes`：服务端返回的可见变更摘要。
 *
 * 返回：替换审批列表，只有 pending 记录生成操作按钮。
 */
function setApprovalRows(changes) {
  const target = $("approvals");
  target.replaceChildren();
  if (!changes.length) {
    target.className = "list empty";
    target.textContent = "没有可复核变更";
    return;
  }
  target.className = "list";
  for (const change of changes.slice().reverse()) {
    const item = document.createElement("div");
    item.className = "row";
    const copy = document.createElement("div");
    const title = document.createElement("strong");
    const detail = document.createElement("small");
    title.textContent = `${change.id} · ${change.resource}`;
    detail.textContent = `${change.initiator} · base v${change.base_version} · ${change.status}`;
    copy.append(title, detail);
    if (change.status === "pending") {
      const actions = document.createElement("div");
      actions.className = "row-actions";
      for (const action of ["approve", "reject"]) {
        const button = document.createElement("button");
        button.type = "button";
        button.textContent = action === "approve" ? "批准" : "拒绝";
        if (action === "approve") {
          button.className = "primary";
        }
        button.addEventListener("click", () => reviewChange(change, action));
        actions.append(button);
      }
      item.append(copy, actions);
    } else {
      const status = document.createElement("span");
      status.className = `state ${["failed", "stale", "expired", "rejected"].includes(change.status) ? "bad" : ""}`;
      status.textContent = change.status;
      item.append(copy, status);
    }
    target.append(item);
  }
}

/**
 * 业务作用：携带候选 ETag 执行批准或拒绝，动作完成后重新读取审批与运行状态。
 *
 * 参数说明：
 * - `change`：包含固定候选标识与 ETag 的变更摘要。
 * - `action`：按钮固定的 approve 或 reject 动作。
 *
 * 返回：成功后显示动作结果；过期或越权由服务端拒绝并显示错误。
 */
async function reviewChange(change, action) {
  showNotice("");
  try {
    const { payload } = await requestJson(
      `/api/changes/${encodeURIComponent(change.id)}/${action}`,
      {
        method: "POST",

        headers: { "if-match": change.candidate_etag },
      },
    );
    showNotice(`变更 ${change.id}：${payload.status || action}`);
    await refreshAdvanced();
    await refresh();
  } catch (error) {
    showNotice(error instanceof Error ? error.message : String(error));
  }
}

/**
 * 业务作用：独立刷新消费者、审批与扩展管理读面，一个读面不可用不冒充为空。
 *
 * 参数说明: 无。
 *
 * 返回：逐项更新可用数据或明确不可用状态。
 */
async function refreshAdvanced() {
  try {
    const consumers = await getJson("/api/consumers");
    const rows = consumers.consumers || [];
    $("consumer-state").textContent = `${rows.length} 个`;
    setRows(
      $("consumers"),
      rows.map((consumer) => ({
        title: consumer.id,

        detail: `plan ${consumer.plan || "未绑定"}`,

        state: `${consumer.key_count || 0} keys`,
      })),
      "尚未配置消费者",
    );
  } catch (error) {
    $("consumer-state").textContent = "不可用";
    setRows($("consumers"), [], "无查看权限或配置不可用");
  }
  try {
    const certs = await getJson("/api/certs");
    const rows = certs.certificates || [];
    $("cert-state").textContent = `${rows.length} 张`;
    setRows(
      $("certificates"),
      rows.map((cert) => ({
        title: `${cert.proxy} · ${cert.entry}`,

        detail: `${(cert.domains || []).join(", ") || "default"} · ${cert.source}`,

        state: cert.ok ? `${cert.status?.days_remaining ?? "?"} 天` : "INVALID",

        tone:
          !cert.ok || (cert.status?.days_remaining ?? 999) < 14 ? "bad" : "",
      })),
      "未配置 TLS 证书",
    );
  } catch (error) {
    $("cert-state").textContent = "不可用";
    setRows($("certificates"), [], "无查看权限或证书不可用");
  }
  try {
    const payload = await getJson("/api/changes");
    const changes = payload.changes || [];
    $("approval-state").textContent =
      `${changes.filter((change) => change.status === "pending").length} 待复核`;
    setApprovalRows(changes);
  } catch (error) {
    $("approval-state").textContent = "未启用或无权限";
    setApprovalRows([]);
  }
}

$("config-load").addEventListener("click", loadCurrentConfig);
$("config-publish").addEventListener("click", publishCurrentConfig);
$("config-diff").addEventListener("click", runConfigDiff);
$("explain-run").addEventListener("click", runExplain);
$("sentinel-load").addEventListener("click", loadSentinel);
$("sentinel-publish").addEventListener("click", publishSentinel);
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
          if (!response.ok) {
            throw new Error(payload.error || `HTTP ${response.status}`);
          }
          return payload;
        })
      : await getJson("/admin/config/dry-run");
    showNotice(`Dry run 通过：候选版本 v${result.summary?.version ?? "?"}`);
  } catch (error) {
    showNotice(error instanceof Error ? error.message : String(error));
  }
});

/**
 * 业务作用：刷新页面各管理读面，页面仅展示读取结果而不自动发起变更。
 *
 * 参数说明: 无。
 *
 * 返回：完成各读面刷新，错误由对应读面展示。
 */
function refreshAll() {
  refresh();
  refreshCluster();
  refreshTopology();
  refreshNodeTraffic();
  refreshAdvanced();
}

refreshAll();
window.setInterval(refreshAll, 15000);
