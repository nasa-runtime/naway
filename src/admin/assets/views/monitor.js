import { request } from "../core/http.js";
import { card, element, number } from "../core/dom.js";

const GROUPS = [
  ["all", "全部指标", () => true],
  [
    "traffic",
    "请求与上游",
    (name) => /requests|responses|upstream|duration|mirror|gw_http_/.test(name),
  ],
  [
    "protection",
    "流控与保护",
    (name) =>
      /rate_|circuit|conn_limited|traffic_wait|sentinel_queue/.test(name),
  ],
  [
    "security",
    "认证与安全",
    (name) => /acl_|blacklist|authz|waf_|opa_|casbin|schema|graphql/.test(name),
  ],
  [
    "cache",
    "缓存与内容",
    (name) => /cache|compression|response_codec|media|webdav/.test(name),
  ],
  [
    "protocol",
    "连接与内部 gRPC",
    (name) => /edge_|management_|stream_|connections|cgi/.test(name),
  ],
  [
    "extensions",
    "AI 与扩展",
    (name) => /ai_|llm_|wasm_|plugin|lua|script/.test(name),
  ],
  [
    "resource",
    "资源与控制",
    (name) =>
      /process_|config|provider|telemetry|governance|traffic_wait/.test(name),
  ],
];

/**
 * 业务作用：挂载只显示当前采样的实时页面，离开或撤权即停止请求并释放数据。
 * 参数说明：
 * - `root`：当前获授权视图的容器。
 * 返回：清理函数，撤销计时器、请求和当前样本。
 */
export function mount(root) {
  let current = null;
  let timer = null;
  let stopped = false;
  let paused = false;
  let inFlight = null;
  let generation = 0;
  let receivedAt = 0;
  let receivedAge = 0;
  let resumeAfter = 0;
  let resumeBoot = "";
  let selectedGroup = "all";
  const expandedNodes = new Set();
  const scope = element("select");
  scope.setAttribute("aria-label", "监控范围");
  for (const [value, label] of [
    ["cluster", "集群"],
    ["local", "接入节点"],
  ]) {
    const option = element("option", label);
    option.value = value;
    scope.append(option);
  }
  const toolbar = element("div", "", "monitor-toolbar");
  const state = element("span", "正在建立采样…", "status-pill");
  state.setAttribute("role", "status");
  const cadence = element("select");
  cadence.setAttribute("aria-label", "监控刷新周期");
  for (const seconds of [1, 2, 5, 10]) {
    const option = element("option", `${seconds} 秒刷新`);
    option.value = String(seconds);
    option.selected = seconds === 2;
    cadence.append(option);
  }
  const pause = element("button", "暂停");
  const description = element(
    "p",
    "默认展示集群当前状态，可下钻接入节点。不保存监控历史；响应头延迟不包含流结束时间。",
    "subtle",
  );
  toolbar.append(state, scope, cadence, pause);
  const meta = element(
    "p",
    "首个样本只建立基线，速率暂为未知。",
    "sample-meta",
  );
  const cards = element("div", "", "metric-grid");
  const panels = element("div", "", "monitor-panels");
  const distribution = element("section", "", "panel");
  const control = element("section", "", "panel");
  const tablePanel = element("section", "", "panel");
  const select = element("select");
  select.setAttribute("aria-label", "指标分类");
  for (const [value, label] of GROUPS) {
    const option = element("option", label);
    option.value = value;
    select.append(option);
  }
  const tableHead = element("div", "", "panel-heading");
  const metricPlane = element("select");
  metricPlane.setAttribute("aria-label", "指标节点角色");
  for (const [value, label] of [
    ["all", "全部角色（分别显示）"],
    ["data", "业务节点"],
    ["admin", "纯管理节点"],
  ]) {
    const option = element("option", label);
    option.value = value;
    metricPlane.append(option);
  }
  tableHead.append(element("h2", "当前指标"), metricPlane, select);
  const table = element("table", "", "metrics-table");
  const header = element("thead");
  const row = element("tr");
  for (const text of [
    "指标 / 固定维度",
    "当前值或每秒速率",
    "区间次数",
    "状态",
  ]) {
    const cell = element("th", text);
    cell.scope = "col";
    row.append(cell);
  }
  header.append(row);
  const body = element("tbody");
  table.append(header, body);
  const caption = element("p", "", "subtle");
  const scroll = element("div", "", "table-scroll");
  scroll.append(table);
  tablePanel.append(tableHead, caption, scroll);
  panels.append(distribution, control);
  root.replaceChildren(description, toolbar, meta, cards, panels, tablePanel);

  /**
   * 业务作用：释放本页当前样本并清除可能过期或已失权的业务内容。
   * 参数说明: 无。
   * 返回：界面保留结构和提示，不保留旧指标。
   */
  function clear() {
    current = null;
    expandedNodes.clear();
    cards.replaceChildren();
    distribution.replaceChildren();
    control.replaceChildren();
    body.replaceChildren();
    caption.textContent = "";
    meta.textContent = "当前没有有效采样。";
  }

  /**
   * 业务作用：展示当前区间固定指标目录，列表大小与筛选均保持有界。
   * 参数说明: 无。
   * 返回：最多128行当前指标，不累积此前Top结果。
   */
  function renderTable() {
    if (!current) {
      return;
    }
    const filter = GROUPS.find(([value]) => value === selectedGroup)[2];
    const sources =
      scope.value === "cluster"
        ? [
            ["data", "业务节点", current.metrics],
            ["admin", "纯管理节点", current.control_metrics ?? []],
          ]
        : [["local", "接入节点", current.metrics]];
    metricPlane.hidden = scope.value !== "cluster";
    const entries = sources
      .filter(
        ([role]) =>
          scope.value !== "cluster" ||
          metricPlane.value === "all" ||
          metricPlane.value === role,
      )
      .flatMap(([, plane, metrics]) =>
        metrics
          .filter((point) => filter(point.name))
          .map((point) => ({
            point,

            plane,
          })),
      );
    entries.sort(
      (a, b) =>
        (b.point.per_second ?? b.point.current ?? -1) -
        (a.point.per_second ?? a.point.current ?? -1),
    );
    const rows = document.createDocumentFragment();
    for (const { point, plane } of entries.slice(0, 128)) {
      const row = element("tr");
      const name = element("td", point.name);
      name.append(element("small", plane, "metric-dimension"));
      const labels = Object.entries(point.labels)
        .map(([key, value]) => `${key}=${value}`)
        .join(" · ");
      if (labels) {
        name.append(element("small", labels, "metric-dimension"));
      }
      row.append(
        name,
        element(
          "td",
          point.kind === "counter"
            ? `${number(point.per_second)} /s`
            : number(point.current),
        ),
        element("td", number(point.delta, 0)),
        element(
          "td",
          point.availability === "available"
            ? "有效"
            : point.availability === "partial"
              ? "部分节点"
              : "未知",
        ),
      );
      rows.append(row);
    }
    body.replaceChildren(rows);
    caption.textContent = `本区间 ${entries.length} 项，显示当前数值最高的 ${Math.min(entries.length, 128)} 项。计数器展示差值速率；瞬时指标展示当前值。`;
  }

  /**
   * 业务作用：把一个完整当前快照显示为运行卡片、分布和控制状态。
   * 参数说明: 无。
   * 返回：所有组件来自同一sample_id，未知字段保持未知。
   */
  function render() {
    const summary = current.summary;
    const httpStream = summary.http_stream ?? {};
    const circuit = summary.circuit ?? {};
    const buckets = summary.rate_buckets ?? {};
    const codec = summary.response_codec ?? {};
    const latency = current.latency;
    const node = current.node;
    const states = {
      available: "实时",

      sampling: "正在建立基线",

      partial: "部分可用",

      unavailable: "节点不可用",

      no_data_nodes: "尚未观测到数据节点",

      capacity: "超过采样容量",
    };
    state.textContent = `${states[current.availability] ?? "未知"} · ${scope.value === "cluster" ? "集群" : "本机"}`;
    state.className =
      current.availability === "available"
        ? "status-pill live"
        : "status-pill warning";
    cards.replaceChildren(
      card("请求速率", number(summary.requests_per_second), "请求 / 秒"),
      card(
        "服务端错误",
        summary.server_error_ratio === null
          ? "—"
          : number(summary.server_error_ratio * 100) + "%",
        "按已生成响应头统计的 5xx 比例",
      ),
      card("P95 响应头延迟", number(latency.p95_ms), "毫秒 · 至少 20 个样本"),
      card("活动 HTTP 连接", number(summary.connections, 0), "当前连接数量"),
      card(
        "进程 CPU",
        number(summary.cpu_percent_one_core) + "%",
        scope.value === "cluster"
          ? "有效节点合计，单核 = 100%"
          : "单核 = 100%，多核可超过 100%",
      ),
      card(
        "当前 RSS",
        number(
          summary.resident_bytes === null
            ? null
            : summary.resident_bytes / 1048576,
        ),
        scope.value === "cluster" ? "MiB · 有效节点合计" : "MiB · 当前驻留内存",
      ),
      card(
        "速率限制拒绝",
        number(summary.rate_rejections_per_second),
        "拒绝 / 秒",
      ),
      card(
        "熔断保护拒绝",
        number(summary.circuit_rejections_per_second),
        "拒绝 / 秒",
      ),
      card(
        "HTTP 入站正文",
        number(httpStream.request_bytes_per_second),
        "已消费编码实体字节 / 秒",
      ),
      card(
        "HTTP 出站正文",
        number(httpStream.response_bytes_per_second),
        "交付 HTTP adapter 的实体字节 / 秒",
      ),
      card(
        "等待响应结束",
        number(httpStream.inflight, 0),
        "等待响应头或正文 EOF 的请求",
      ),
      card(
        "P95 正文结束耗时",
        number(httpStream.p95_ms),
        "毫秒 · 从入口到本地 EOF · 至少 20 个样本",
      ),
      card("保留令牌桶", number(buckets.total, 0), "当前本地后端的桶实例合计"),
      card(
        "冷态预热桶",
        number(buckets.cold, 0),
        "达到空闲冷却期，等待下次请求",
      ),
      card("预热进行中", number(buckets.warming, 0), "按当前曲线增加准入速率"),
      card("预热已稳定", number(buckets.warm, 0), "达到基础速率的预热桶"),
      card("普通稳态桶", number(buckets.steady, 0), "未启用预热的本地桶"),
      card(
        "过期保留桶",
        number(buckets.expired, 0),
        "等待请求触发回收，观测不清理",
      ),
      card("开启保护", number(circuit.open, 0), "节点本地熔断状态实例"),
      card(
        "半开探测",
        number(circuit.half_open, 0),
        "当前持有探测权的本地实例",
      ),
      card(
        "保留关闭态",
        number(circuit.closed, 0),
        "含等待安全回收的旧策略实例",
      ),
      card(
        "熔断活动许可",
        number(circuit.active_calls, 0),
        "当前未归还的本地执行许可",
      ),
      card(
        "响应编码输入",
        number(codec.encode_input_bytes_per_second),
        "gzip / br 实际消费字节 / 秒",
      ),
      card(
        "响应编码输出",
        number(codec.encode_output_bytes_per_second),
        "gzip / br 实际产出字节 / 秒",
      ),
      card(
        "活动响应变换",
        number(
          Number.isFinite(codec.encode_inflight) &&
            Number.isFinite(codec.decode_inflight)
            ? codec.encode_inflight + codec.decode_inflight
            : null,
          0,
        ),
        `编码 ${number(codec.encode_inflight, 0)} · 解码 ${number(codec.decode_inflight, 0)}`,
      ),
      card(
        "成功编码节省率",
        Number.isFinite(codec.completed_encode_savings_ratio)
          ? number(codec.completed_encode_savings_ratio * 100) + "%"
          : "—",
        "按本区间完成集合计 · 膨胀可为负",
      ),
    );
    const distributionContent = document.createDocumentFragment();
    distributionContent.append(
      element("h2", "当前响应头延迟分布"),
      element(
        "p",
        `样本 ${number(latency.count, 0)} · 均值 ${number(latency.mean_ms)} ms · P50 ${number(latency.p50_ms)} · P99 ${number(latency.p99_ms)}`,
        "subtle",
      ),
    );
    if (latency.buckets) {
      for (let index = 0; index < latency.buckets.length; index += 1) {
        const line = element("div", "", "bucket");
        const meter = element("meter");
        meter.min = 0;
        meter.max = Math.max(latency.bucket_total ?? latency.count, 1);
        meter.value = latency.buckets[index];
        const bound = latency.bounds_ms[index];
        const label =
          bound === undefined
            ? `> ${number(latency.bounds_ms.at(-1), 0)} ms`
            : index === 0
              ? `≤ ${number(bound, 0)} ms`
              : `${number(latency.bounds_ms[index - 1], 0)} < t ≤ ${number(bound, 0)} ms`;
        const unit = latency.bucket_unit === "per_second" ? " /s" : " 次";
        meter.setAttribute("aria-label", `${label} 当前桶${unit}`);
        line.append(
          element("span", label),
          meter,
          element(
            "span",
            number(
              latency.buckets[index],
              latency.bucket_unit === "per_second" ? 2 : 0,
            ) + unit,
          ),
        );
        distributionContent.append(line);
      }
    } else {
      distributionContent.append(
        element("p", "分布基线尚未建立，或计数发生重置。", "empty-state"),
      );
    }
    distribution.replaceChildren(distributionContent);
    control.replaceChildren(
      element(
        "h2",
        scope.value === "cluster" ? "当前节点覆盖" : "当前配置与能力",
      ),
    );
    for (const [label, value] of node
      ? [
          ["数据面", node.ready ? "已就绪" : "未就绪"],
          ["部署模式", node.mode],
          ["配置版本", node.config_version],
          ["注册中心", node.discovery_enabled ? "启用" : "关闭"],
          ["配置中心", node.configuration_enabled ? "启用" : "关闭"],
          ["路由 / 上游服务", `${node.routes} / ${node.services}`],
          ["P99 样本要求", "至少 100 次；溢出桶无有限估值"],
        ]
      : [
          [
            "有效 / 可达 / 总节点",
            `${current.coverage.valid} / ${current.coverage.reachable} / ${current.coverage.total}`,
          ],
          [
            "数据 / 纯管理 / 角色未知",
            `${current.coverage.data_nodes ?? "—"} / ${current.coverage.control_nodes ?? "—"} / ${current.coverage.unclassified_nodes ?? "—"}`,
          ],
          [
            "成员发现",
            current.coverage.discovery_enabled
              ? current.coverage.discovery_available
                ? "自动发现可用"
                : "发现不可用"
              : "自动发现关闭，使用静态成员",
          ],
          [
            "成员目录",
            current.coverage.conflicting_ids
              ? "节点身份冲突"
              : current.coverage.directory_stale
                ? "沿用已知目录，当前发现失败"
                : current.coverage.truncated
                  ? "已截断，请减少单组节点"
                  : current.coverage.limited_to_local
                    ? "仅声明接入节点，尚未配置集群成员"
                    : "已声明成员",
          ],
          ["时延覆盖", `${latency.valid_nodes} / ${latency.total_nodes}`],
          [
            "有效区间范围",
            `${number(latency.min_interval_ms)}～${number(latency.max_interval_ms)} ms`,
          ],
          [
            "基线内存",
            `${number(current.coverage.baseline_bytes / 1048576)} / 8 MiB`,
          ],
        ]) {
      const line = element("div", "", "state-row");
      line.append(element("span", label), element("strong", String(value)));
      control.append(line);
    }
    control.append(
      element(
        "p",
        `本地桶覆盖：${
          {
            available: "完整",

            partial: "部分，未覆盖节点不计为零",

            unavailable: "本轮无法提供本地桶数",

            unknown: "尚未建立",
          }[buckets.availability] ?? "尚未提供"
        }。节点状态：本地 ${number(buckets.local_nodes, 0)}，共享 Redis ${number(buckets.shared_nodes, 0)}，批领 ${number(buckets.preallocated_nodes, 0)}，锁忙 ${number(buckets.busy_nodes, 0)}，超预算 ${number(buckets.capacity_nodes, 0)}，不支持 ${number(buckets.unsupported_nodes, 0)}，不可用 ${number(buckets.unavailable_nodes, 0)}。仅统计当前本地后端的桶实例，不等于规则数；共享后端不枚举 Redis 全局桶，不保留历史。`,
        "subtle",
      ),
      element(
        "p",
        `熔断状态覆盖：${
          {
            available: "完整",

            partial: "部分，未覆盖节点不计为零",

            unknown: "尚未建立",
          }[circuit.availability] ?? "尚未提供"
        }。按节点本地执行状态计数，包含尚未安全回收的旧策略；不等于当前配置规则数。Redis 共享统计不提供全局唯一半开权。`,
        "subtle",
      ),
      element(
        "p",
        `HTTP 正文指标覆盖：${
          {
            available: "完整",

            partial: "部分，未覆盖节点不计为零",

            inconsistent: "当前计数不一致，时延未知",

            unknown: "尚未建立",
          }[httpStream.availability] ?? "尚未提供"
        }。完整结束 ${number(httpStream.completed_per_second)} /s，正文错误 ${number(httpStream.errors_per_second)} /s，提前丢弃 ${number(httpStream.dropped_per_second)} /s，完整结束均值 ${number(httpStream.mean_ms)} ms。`,
        "subtle",
      ),
      element(
        "p",
        "正文字节不含协议开销；EOF 表示本地正文已交付，不表示对端确认。丢弃可能来自提前拒绝或取消；升级隧道另计。",
        "subtle",
      ),
      element(
        "p",
        `响应变换指标覆盖：${
          {
            available: "完整",

            partial: "部分，未覆盖节点不计为零",

            unknown: "尚未建立",

            inconsistent: "完成计数不一致，收益未知",
          }[codec.availability] ?? "尚未提供"
        }。成功编码 ${number(codec.completed_encode_per_second)} /s；按完成集合结算的节省量 ${number(codec.completed_encode_saved_bytes_per_second)} B/s，包含该变换在此前区间处理的字节，不等于本区间网络带宽节省或对端确认。解码实际输入 / 输出 ${number(codec.decode_input_bytes_per_second)} / ${number(codec.decode_output_bytes_per_second)} B/s。`,
        "subtle",
      ),
      element(
        "p",
        "按入口归属的请求、响应与流结束指标见路由实时流量页面，工作区需要独立读取权限。",
        "subtle",
      ),
    );
    if (scope.value === "cluster") {
      renderNodes();
    } else {
      renderManagement(summary.management, control);
    }
    renderTable();
    age();
  }

  /**
   * 业务作用：逐节点显示管理监听真实状态，不能把未配置或不可观测的接收端显示为健康。
   * 参数说明：
   * - `management`：当前节点的管理通信摘要。
   * - `target`：本节点明细容器。
   * 返回：追加固定状态行，不合计枚举或连续故障时间。
   */
  function renderManagement(management, target) {
    if (management?.receiver_enabled == null) {
      return;
    }
    const states = {
      bound: "已绑定",

      running: "运行中",

      draining: "排空中",

      closed: "已关闭",

      failed: "不可用",
    };
    for (const [label, value] of [
      [
        "管理 gRPC 接收",
        !management.receiver_enabled
          ? "未启用"
          : !management.receiver_observed
            ? "不可观测"
            : (states[management.receiver_state] ?? "未知"),
      ],
      ["受理管理连接", number(management.connections, 0)],
      ["连续接收失败", number(management.consecutive_accept_failures, 0)],
      ["接收停滞 / ms", number(management.accept_stall_milliseconds, 0)],
    ]) {
      const row = element("div", "", "state-row");
      row.append(element("span", label), element("strong", value));
      target.append(row);
    }
  }

  /**
   * 业务作用：显示当前有限成员的真实资源与流量，故障节点保留未知标识。
   * 参数说明: 无。
   * 返回：节点明细只属于当前样本，不累计节点历史。
   */
  function renderNodes() {
    const present = new Set((current.nodes ?? []).map((node) => node.id));
    for (const id of expandedNodes) {
      if (!present.has(id)) {
        expandedNodes.delete(id);
      }
    }
    const list = element("div", "", "node-list");
    for (const node of (current.nodes ?? []).slice(0, 128)) {
      const details = element("details");
      details.open = expandedNodes.has(node.id);
      details.addEventListener("toggle", () => {
        if (!details.isConnected) {
          return;
        }
        if (details.open) {
          expandedNodes.add(node.id);
        } else {
          expandedNodes.delete(node.id);
        }
      });
      const title = element(
        "summary",
        `${node.id} · ${node.availability === "available" ? "有效" : node.availability}`,
      );
      details.append(title);
      const source = element("div", "", "state-row");
      source.append(
        element("span", "指标来源"),
        element(
          "strong",
          {
            local: "本机采样",

            grpc: "管理 gRPC 上传",

            http: "授权 HTTP 抓取",
          }[node.source] ?? "未知",
        ),
      );
      details.append(source);
      if (node.summary) {
        for (const [label, value] of [
          ["请求 /s", number(node.summary.requests_per_second)],
          ["P95 / ms", number(node.latency.p95_ms)],
          ["HTTP 连接", number(node.summary.connections, 0)],
          ["CPU / %", number(node.summary.cpu_percent_one_core)],
          [
            "RSS / MiB",
            number(
              node.summary.resident_bytes === null
                ? null
                : node.summary.resident_bytes / 1048576,
            ),
          ],
          ["配置版本", node.state.config_version],
          ["样本年龄 / 秒", number(node.sample_age_ms / 1000)],
          ["运行角色", node.state.mode],
          ["服务就绪", node.state.ready ? "已就绪" : "未就绪"],
          [
            "注册 / 配置中心",
            `${node.state.discovery_enabled ? "启用" : "关闭"} / ${node.state.configuration_enabled ? "启用" : "关闭"}`,
          ],
        ]) {
          const row = element("div", "", "state-row");
          row.append(element("span", label), element("strong", String(value)));
          details.append(row);
        }
        renderManagement(node.summary.management, details);
      }
      list.append(details);
    }
    control.append(list);
  }

  /**
   * 业务作用：根据真实数据年龄标记过期，网络失败不能让旧数值继续冒充实时。
   * 参数说明: 无。
   * 返回：更新采样时间与新鲜度；超过三周期移除数值。
   */
  function age() {
    if (!current) {
      return;
    }
    const elapsed = receivedAge + performance.now() - receivedAt;
    if (elapsed > current.sampling_period_ms * 3) {
      clear();
      state.textContent = "数据已过期，等待新样本";
      state.className = "status-pill warning";
      return;
    }
    meta.textContent = `采样 ${new Date(current.sampled_at_ms).toLocaleTimeString("zh-CN")} · 区间 ${number(current.interval_ms)} ms · 数据年龄 ${number(elapsed / 1000)} 秒 · 有效节点 ${current.coverage.valid}/${current.coverage.total} · #${current.sample_id}`;
  }

  /**
   * 业务作用：串行读取共享最新快照，页面暂停、隐藏或切换后迟到数据不得回填。
   * 参数说明: 无。
   * 返回：刷新当前结果或明确失败状态，不重叠发起轮询。
   */
  async function poll() {
    if (stopped || paused || document.hidden || inFlight) {
      return;
    }
    const epoch = generation;
    const controller = new AbortController();
    inFlight = controller;
    try {
      const result = await request(`/api/monitor?scope=${scope.value}`, {
        signal: controller.signal,
      });
      if (epoch !== generation || stopped) {
        return;
      }
      if (
        result.status === 202 ||
        (result.data.boot_id === resumeBoot &&
          result.data.sample_id <= resumeAfter)
      ) {
        clear();
        state.textContent =
          result.data.availability === "disabled"
            ? "当前监控范围已关闭"
            : "正在建立新采样…";
        return;
      }
      if (
        result.data.schema_version !== 1 ||
        !Array.isArray(result.data.metrics) ||
        result.data.metrics.length > 1024
      ) {
        throw new Error("监控响应格式或容量不符合约定。");
      }
      current = result.data;
      receivedAt = performance.now();
      receivedAge = Number(result.headers.get("x-naway-sample-age-ms"));
      render();
    } catch (error) {
      if (epoch === generation && error.name !== "AbortError") {
        clear();
        state.textContent = error.message;
        state.className = "status-pill warning";
      }
    } finally {
      if (inFlight === controller) {
        inFlight = null;
      }
      if (!stopped && !paused && !document.hidden && epoch === generation) {
        timer = setTimeout(poll, Number(cadence.value) * 1000);
      }
    }
  }

  /**
   * 业务作用：停止本视图在途读取，撤销旧采样而不让暂停区间进入页面速率。
   * 参数说明: 无。
   * 返回：取消轮询并记住恢复时必须跨过的样本序号。
   */
  function suspend() {
    generation += 1;
    clearTimeout(timer);
    if (current) {
      resumeAfter = current.sample_id;
      resumeBoot = current.boot_id;
    }
    inFlight?.abort();
    inFlight = null;
    clear();
  }

  /**
   * 业务作用：响应用户暂停或恢复，仅保留当前操作意图。
   * 参数说明: 无。
   * 返回：暂停清除指标，恢复读取新的服务器采样。
   */
  function togglePause() {
    paused = !paused;
    suspend();
    pause.textContent = paused ? "恢复" : "暂停";
    state.textContent = paused ? "已暂停，未保留监控数据" : "正在恢复…";
    if (!paused) {
      void poll();
    }
  }

  /**
   * 业务作用：后台页面停止无用轮询，重新可见时丢弃旧区间。
   * 参数说明: 无。
   * 返回：可见且未暂停时恢复新采样。
   */
  function visibility() {
    suspend();
    if (!document.hidden && !paused) {
      void poll();
    }
  }

  /**
   * 业务作用：以用户选定周期重新安排单次轮询，保持服务器固定采样频率可见。
   * 参数说明: 无。
   * 返回：取消旧计划，当前请求不重复启动。
   */
  function cadenceChanged() {
    clearTimeout(timer);
    void poll();
  }

  /**
   * 业务作用：只在当前样本内筛选指标分类。
   * 参数说明: 无。
   * 返回：更新有限列表，不查询或保存历史。
   */
  function groupChanged() {
    selectedGroup = select.value;
    renderTable();
  }

  /**
   * 业务作用：切换有限监控范围时撤销旧请求和样本，防止本机结果回填到集群页面。
   * 参数说明: 无。
   * 返回：新范围从当前服务端采样开始，暂停状态保持。
   */
  function scopeChanged() {
    suspend();
    resumeBoot = "";
    resumeAfter = 0;
    state.textContent = paused ? "已暂停，未保留监控数据" : "正在切换采样范围…";
    void poll();
  }

  pause.addEventListener("click", togglePause);
  cadence.addEventListener("change", cadenceChanged);
  select.addEventListener("change", groupChanged);
  metricPlane.addEventListener("change", renderTable);
  scope.addEventListener("change", scopeChanged);
  document.addEventListener("visibilitychange", visibility);
  const freshness = setInterval(age, 1000);
  void poll();

  /**
   * 业务作用：离开页面时撤销所有请求和当前数据，阻止会话切换后的回填。
   * 参数说明: 无。
   * 返回：该视图不再持有计时器、监听器或采样对象。
   */
  return function dispose() {
    stopped = true;
    suspend();
    clearInterval(freshness);
    document.removeEventListener("visibilitychange", visibility);
    root.replaceChildren();
  };
}
