import { request } from "../core/http.js";
import { element } from "../core/dom.js";
import { field, proposalForm } from "./operations/form.js";
import { proposalDetail } from "./operations/detail.js";

/**
 * 业务作用：在同一集群范围内管理提案与原目标执行，未知提交始终保持原请求身份。
 * 参数说明：
 * - `root`：统一管理壳交付的视图容器。
 * - `session`：当前主体、授权工作区和持久操作资源边界。
 * 返回：取消请求、实时进度刷新并清空敏感内容的退出函数，不使用持久浏览器存储。
 */
export function mount(root, session) {
  if (!session.operations?.enabled) {
    root.replaceChildren(
      element(
        "section",
        "当前入口未启用共享持久提案。请由部署配置启用管理存储后使用。",
        "panel",
      ),
    );
    return () => {
      root.replaceChildren();
    };
  }
  const cluster = session.operations.cluster_id;
  const domains = [
    ["gateway", "网关配置", "config"],
    ["sentinel", "Sentinel", "sentinel"],
    ["interface-guard", "接口守卫", "interface-guard"],
  ];
  const platform = domains.some(([, , resource]) =>
    session.permissions?.[resource]?.includes("read"),
  );
  const scopes = element("select");
  scopes.setAttribute("aria-label", "提案范围");
  if (platform) {
    const option = element("option", "平台");
    option.value = "";
    scopes.append(option);
  }
  for (const workspace of session.workspaces ?? []) {
    const option = element(
      "option",
      `${workspace.id} · ${workspace.tenant} / ${workspace.environment}`,
    );
    option.value = workspace.id;
    scopes.append(option);
  }
  const domain = element("select");
  domain.setAttribute("aria-label", "提案领域");
  const toolbar = element("div", "", "monitor-toolbar");
  const refresh = element("button", "刷新提案");
  refresh.type = "button";
  toolbar.append(field("范围", scopes), field("领域", domain), refresh);
  const status = element("p", "正在读取共享提案…", "status-pill");
  status.setAttribute("role", "status");
  const list = element("section", "", "panel proposal-list");
  const detail = element("section", "", "panel proposal-detail");
  const previous = element("button", "上一页");
  const next = element("button", "下一页");
  previous.type = next.type = "button";
  const paging = element("div", "", "monitor-toolbar");
  paging.append(previous, next);
  const pendingPanel = element("section", "", "panel proposal-pending");
  const recovery = element("form", "", "panel proposal-recovery");
  const recoverKey = element("input");
  recoverKey.maxLength = 128;
  recoverKey.autocomplete = "off";
  recoverKey.required = true;
  const recoverEpoch = element("input");
  recoverEpoch.maxLength = 19;
  recoverEpoch.autocomplete = "off";
  recoverEpoch.required = true;
  const recover = element("button", "按原请求查找");
  recover.type = "submit";
  recovery.append(
    element("h2", "恢复原请求"),
    element(
      "p",
      "使用当前主体的原请求身份，从本集群任一 Admin 查询已保存记录。未找到不表示在途事务已回滚。",
      "subtle",
    ),
    field("原受理代际（兼容请求为 0）", recoverEpoch),
    field("原 Idempotency-Key", recoverKey),
    recover,
  );
  let alive = true;
  let generation = 0;
  let controller = null;
  let busy = false;
  let pending = null;
  let permissions = {};
  let accepting = false;
  let unresolvedReview = null;
  let unresolvedExecution = null;
  let executionCapability = {};
  let progressTimer = null;
  let detailRecord = null;
  let detailView = null;
  let workspace = scopes.value;
  let selectedDomain = "";
  let pages = [""];
  let page = 0;
  let nextAfter = null;
  const form = proposalForm(
    session.operations,
    submit,
    loadTargets,
    () => selectedDomain,
    editDraft,
  );
  root.replaceChildren(
    element(
      "p",
      `共享集群：${cluster} · 接入 Admin：${location.host}`,
      "proposal-context",
    ),
    element(
      "p",
      "此页管理集群提案和全部原目标的执行进度。保存与批准本身不执行发布；执行还需独立开关、当前授权和全部目标基线。",
      "subtle",
    ),
    toolbar,
    status,
    list,
    paging,
    detail,
    pendingPanel,
    form.node,
    recovery,
  );
  if (session.workspaces_truncated) {
    toolbar.append(
      element("p", "工作区目录已截断，仅展示本次授权返回的工作区。", "subtle"),
    );
  }

  /**
   * 业务作用：按平台资源权限或工作区范围提供领域选项，不能借切换领域扩大授权。
   * 参数说明: 无。
   * 返回：重建当前可选领域并冻结选中值。
   */
  function domainOptions() {
    domain.replaceChildren();
    for (const [value, label, resource] of domains) {
      if (!workspace && !session.permissions?.[resource]?.includes("read")) {
        continue;
      }
      const option = element("option", label);
      option.value = value;
      domain.append(option);
    }
    selectedDomain = domain.value;
    form.clearDraft();
  }

  /**
   * 业务作用：只从已选定的精确范围构造同源接口，不接受节点地址或其它主体身份。
   * 参数说明：
   * - `suffix`：页面确定的固定入口后缀或已验证提案 id。
   * - `after`：当前页的有限游标。
   * 返回：同源提案路径，幂等键不进入 URL。
   */
  function path(suffix = "", after = "") {
    const query = new URLSearchParams({ domain: selectedDomain });
    // 完整节点基线扩大了单条记录，固定小页保持最坏目标集合落在既有响应预算内。
    if (!suffix) {
      query.set("limit", "32");
    }
    if (workspace) {
      query.set("workspace", workspace);
    }
    if (after) {
      query.set("after", after);
    }
    return `/api/operations/proposals${suffix}?${query}`;
  }

  /**
   * 业务作用：拒绝把另一集群的响应发布为当前会话的提案事实。
   * 参数说明：
   * - `data`：来自当前请求的低敏 JSON。
   * 返回：集群一致时返回原数据；不一致时保留未知状态并要求重新核对入口。
   */
  function checked(data) {
    if (data.cluster_id !== cluster) {
      throw new Error("响应所属集群已变化，请核对入口并重新登录。");
    }
    return data;
  }

  /**
   * 业务作用：撤下原文及审阅资格，离开详情后旧读取不能恢复候选。
   * 参数说明: 无。
   * 返回：只清空当前详情，不改变数据库中的审阅记录。
   */
  function clearDetail() {
    clearTimeout(progressTimer);
    progressTimer = null;
    detailRecord = null;
    detailView?.clear();
    detailView = null;
    detail.replaceChildren();
  }

  /**
   * 业务作用：将并发门、当前受理状态与未知意图同步到所有操作控件。
   * 参数说明: 无。
   * 返回：不保留可双击提交的旧控件状态。
   */
  function controls() {
    form.discover(
      !workspace && session.permissions?.cluster?.includes("read") === true,
    );
    form.lock(
      busy || !!pending || !permissions.write || !accepting || document.hidden,
    );
    detailView?.lock(busy || document.hidden);
    refresh.disabled = busy || document.hidden;
    previous.disabled = busy || page === 0 || document.hidden;
    next.disabled = busy || !nextAfter || page >= 127 || document.hidden;
    recover.disabled = busy || document.hidden;
  }

  /**
   * 业务作用：按当前平台读取资格取得一次集群目录，复用页面取消与单在途门。
   * 参数说明: 无。
   * 返回：只发布仍属于当前页面的目标证据，工作区和无权限视图不发起请求。
   */
  async function loadTargets() {
    // 平台目录包含所有成员，不能借工作区提案权限读取其它范围的节点基线。
    if (workspace || !session.permissions?.cluster?.includes("read")) {
      form.clearTargets();
      return;
    }
    await run(async (signal, guard) => {
      const started = performance.now();
      try {
        const result = await request("/api/cluster/overview", { signal });
        guard();
        form.showTargets(result, started);
      } catch (error) {
        // 旧页面的失败也没有更新新范围状态的资格，先复验再给出当前失败提示。
        guard();
        form.clearTargets("集群目标读取未完成，请重新读取。");
        throw error;
      }
    });
  }

  /**
   * 业务作用：将草稿处理接入唯一请求链，完整复验当前范围和原文字节后才允许回填。
   * 参数说明：
   * - `candidate`：用户在本次操作开始时的原文。
   * - `action`：明确对象和字段动作。
   * - `receive`：当前页面的同步回填函数，不写任何目标文件。
   * 返回：仅当前且摘要一致的结果进入表单；失败不保存提案或重试写入。
   */
  async function editDraft(candidate, action, receive) {
    if (pending || !permissions.write || !accepting) {
      return;
    }
    await run(async (signal, guard) => {
      if (
        !candidate ||
        new TextEncoder().encode(candidate).byteLength >
          session.operations.max_candidate_bytes
      ) {
        throw new Error("候选为空或超过 UTF-8 字节上限。");
      }
      const originalDomain = selectedDomain;
      const originalScope = workspace ? `workspace.${workspace}` : "platform";
      const digest = await draftDigest(candidate);
      guard();
      const data = checked(
        (
          await request(path("/draft"), {
            method: "POST",

            headers: { "content-type": "application/json" },

            body: JSON.stringify({
              candidate,
              action,
            }),

            signal,
          })
        ).data,
      );
      guard();
      if (
        data.schema_version !== 1 ||
        data.validation !== "declaration_only" ||
        data.published !== false ||
        data.domain !== originalDomain ||
        data.scope !== originalScope ||
        data.base_sha256 !== digest
      ) {
        throw new Error("草稿响应的范围或原文身份不一致，已丢弃结果。");
      }
      if (action.type !== "inspect") {
        if (
          typeof data.candidate !== "string" ||
          typeof data.changed !== "boolean" ||
          new TextEncoder().encode(data.candidate).byteLength >
            session.operations.max_candidate_bytes ||
          (await draftDigest(data.candidate)) !== data.candidate_sha256
        ) {
          throw new Error("生成候选的容量或摘要不一致，已丢弃结果。");
        }
        guard();
      }
      receive(data);
      status.textContent = "草稿处理完成；候选尚未保存、预检或发布到任何目标。";
    });
  }

  /**
   * 业务作用：绑定草稿请求及回复的完整 UTF-8 字节，显示摘要不代替目标动作授权。
   * 参数说明：
   * - `value`：有界候选原文。
   * 返回：完整 SHA-256 小写十六进制身份。
   */
  async function draftDigest(value) {
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(value),
    );
    return Array.from(new Uint8Array(digest), (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
  }

  /**
   * 业务作用：集中限制页面为一个在途请求链，并在取消或范围换代后撤销旧响应显示权威。
   * 参数说明：
   * - `work`：只在当前信号及资格复验下运行的请求步骤。
   * 返回：当前步骤的结果或空；失败只显示低敏信息，不自动重试写入。
   */
  async function run(work) {
    if (!alive || busy || document.hidden) {
      return null;
    }
    const epoch = generation;
    const active = new AbortController();
    controller = active;
    busy = true;
    showPending();
    controls();
    /**
     * 业务作用：在每次异步边界后确认请求仍属于当前视图，尤其禁止旧 context 驱动新提交。
     * 参数说明: 无。
     * 返回：当前时继续，退休或取消时中断剩余步骤。
     */
    function guard() {
      if (
        !alive ||
        epoch !== generation ||
        active.signal.aborted ||
        document.hidden
      ) {
        throw new DOMException("页面已切换", "AbortError");
      }
    }
    try {
      const result = await work(active.signal, guard);
      guard();
      return result;
    } catch (error) {
      if (
        alive &&
        epoch === generation &&
        !document.hidden &&
        error.name !== "AbortError"
      ) {
        clearDetail();
        form.clearDraft();
        if (error.status === 403) {
          // 当前授权已拒绝后不能留下原文或沿用旧按钮资格。
          permissions = {};
          accepting = false;
          form.clear();
        }
        status.textContent = `${error.message}${pending ? " 原请求身份保留，请先查找或按原身份重试。" : ""}`;
      }
      return null;
    } finally {
      if (alive && epoch === generation) {
        busy = false;
        controller = null;
        showPending();
        controls();
        scheduleProgress();
      }
    }
  }

  /**
   * 业务作用：按当前共享事实显示详情，正文和审阅必须再次走各自的精确授权接口。
   * 参数说明：
   * - `record`：本集群、当前领域和范围下的记录。
   * 返回：挂接只属于该记录的详情句柄，不把批准解释为已发布。
   */
  function show(record) {
    if (
      !/^[0-9a-f]{32}$/.test(record.id) ||
      record.domain !== selectedDomain ||
      record.scope !== (workspace ? `workspace.${workspace}` : "platform")
    ) {
      throw new Error("提案身份或领域与当前范围不一致。");
    }
    clearDetail();
    detailRecord = record;
    detailView = proposalDetail(
      detail,
      record,
      {
        ...permissions,

        principal: session.principal,

        accept_proposals: accepting,

        ...executionCapability,

        execution_pending: !!unresolvedExecution,
      },
      loadSource,
      review,
      execute,
    );
    controls();
  }

  /**
   * 业务作用：重新读取单个持久事实，审阅未知时由明确状态决定后续操作。
   * 参数说明：
   * - `id`：当前列表给出的提案身份。
   * 返回：显示当前记录，失败后撤下旧详情。
   */
  async function readRecord(id) {
    await run(async (signal, guard) => {
      const { data } = await request(path(`/${id}`), { signal });
      guard();
      show(checked(data).proposal);
      if (unresolvedReview === id) {
        unresolvedReview = null;
      }
      if (unresolvedExecution?.id === id && recordStarted(data.proposal)) {
        unresolvedExecution = null;
      }
      status.textContent = "已读取当前提案；审阅状态与目标执行状态分开。";
    });
  }

  /**
   * 业务作用：按有界游标展示低敏列表，不预取任何候选原文。
   * 参数说明：
   * - `data`：服务器已按领域和工作区过滤的一页记录。
   * 返回：替换本页内容并更新后续页能力。
   */
  function draw(data) {
    list.replaceChildren(element("h2", `共享提案 · 第 ${page + 1} 页`));
    nextAfter = data.next_after;
    for (const record of data.proposals) {
      const row = element("article", "", "proposal-row");
      const open = element("button", `查看提案 ${record.id.slice(0, 8)}`);
      open.type = "button";
      open.addEventListener("click", () => {
        readRecord(record.id);
      });
      row.append(
        element("strong", record.status),
        element(
          "span",
          `${record.creator} · ${record.targets.length} 个声明目标 · ${record.candidate_bytes} B`,
        ),
        element("small", record.id),
        open,
      );
      list.append(row);
    }
    if (!data.proposals.length) {
      list.append(element("p", "当前范围没有可见的保留提案。"));
    }
  }

  /**
   * 业务作用：先读取当前范围资格，再刷新共享列表；受理关闭不会阻止授权读取。
   * 参数说明: 无。
   * 返回：显示当前集群和权限一致的记录，不创建周期采样或历史。
   */
  async function reload() {
    clearDetail();
    await run(async (signal, guard) => {
      const context = checked(
        (await request(path("/context"), { signal })).data,
      );
      guard();
      permissions = context.permissions;
      accepting = context.accept_proposals === true;
      executionCapability = capability(context);
      if (!permissions.write || !accepting) {
        form.clear();
      }
      const { data } = await request(path("", pages[page]), { signal });
      guard();
      draw(checked(data));
      status.textContent =
        context.capacity?.matches_config === false
          ? "共享容量合同已变化，请更新本入口配置并重启；仍可读取已有提案。"
          : accepting
            ? `已读取集群共享提案；执行${context.execution_ready ? "当前就绪" : "当前不可用"}。`
            : "当前入口暂停新提案及审阅，仍可读取共享记录。";
    });
  }

  /**
   * 业务作用：显式读取一次原文并比对详情摘要，网络错误不能留下已确认状态。
   * 参数说明：
   * - `record`：当前详情冻结的提案身份及摘要。
   * 返回：摘要一致的原始文本，取消或失败时为空。
   */
  async function loadSource(record) {
    return run(async (signal, guard) => {
      const value = await request(path(`/${record.id}/candidate`), {
        signal,

        responseType: "text",
      });
      guard();
      if (
        value.headers.get("etag") !== `"sha256-${record.candidate_sha256}"` ||
        !value.headers.get("content-type")?.startsWith("application/yaml")
      ) {
        throw new Error("候选原文与当前摘要不一致，不能继续审阅。");
      }
      status.textContent = "原文已读取；请核对目标意图和候选摘要。";
      return value.data;
    });
  }

  /**
   * 业务作用：提交绑定原摘要的一次审阅，未收到明确结果时只允许回读而不自动重审。
   * 参数说明：
   * - `record`：已显式读取原文的记录。
   * - `decision`：当前主体允许的批准、拒绝或取消动作。
   * 返回：明确保存后显示新事实；未知时提醒按原 id 刷新。
   */
  async function review(record, decision) {
    await run(async (signal, guard) => {
      unresolvedReview = record.id;
      status.textContent = `正在保存审阅；若结果未知，请刷新提案 ${record.id}。`;
      const { data } = await request(path(`/${record.id}/review`), {
        method: "POST",

        headers: { "content-type": "application/json" },

        body: JSON.stringify({
          decision,

          candidate_sha256: record.candidate_sha256,
        }),

        signal,
      });
      guard();
      show(checked(data).proposal);
      unresolvedReview = null;
      status.textContent = "审阅记录已保存；未执行目标配置发布。";
    });
  }

  /**
   * 业务作用：将服务器当前能力与范围权限投影为详情动作门。
   * 参数说明：
   * - `context`：同一集群和范围的服务端能力响应。
   * 返回：仅显式为真的能力位，不把缺失字段当作授权。
   */
  function capability(context) {
    return {
      execution_supported: context.execution_supported === true,

      execution_enabled: context.execution_enabled === true,

      execution_ready: context.execution_ready === true,
    };
  }

  /**
   * 业务作用：识别明确持久创建的执行，空值与未启动不能消除未知提交提示。
   * 参数说明：
   * - `record`：本次回读的原提案。
   * 返回：服务端明确标记已创建时为真。
   */
  function recordStarted(record) {
    return record?.execution_started === true;
  }

  /**
   * 业务作用：显式提交原摘要确认，未知结果保留原身份而不自动重试写请求。
   * 参数说明：
   * - `record`：已经显式读取原文并确认摘要的原批准提案。
   * 返回：提交后回读原记录；任何失败都保留查询身份。
   */
  async function execute(record) {
    await run(async (signal, guard) => {
      unresolvedExecution = {
        id: record.id,

        digest: record.candidate_sha256,
      };
      status.textContent = `正在创建执行；结果未知时请读取原提案 ${record.id}。`;
      const { data } = await request(path(`/${record.id}/execute`), {
        method: "POST",

        headers: { "content-type": "application/json" },

        body: JSON.stringify({ candidate_sha256: record.candidate_sha256 }),

        signal,
      });
      guard();
      const result = checked(data);
      if (
        result.operation_id !== record.id ||
        result.candidate_sha256 !== record.candidate_sha256
      ) {
        throw new Error("执行确认身份与原请求不同，请读取原记录。");
      }
      const current = checked(
        (await request(path(`/${record.id}`), { signal })).data,
      );
      guard();
      if (!recordStarted(current.proposal)) {
        throw new Error("执行确认与当前记录不一致，请继续核查原身份。");
      }
      unresolvedExecution = null;
      show(current.proposal);
      status.textContent = "执行已持久创建；请按完整原目标进度核对生效和释放。";
    });
  }

  /**
   * 业务作用：只在当前详情可见且没有请求时安排一次实时读取，避免后台或多请求累积。
   * 参数说明: 无。
   * 返回：至多一个定时器；页面退休与范围切换由详情清理撤销。
   */
  function scheduleProgress() {
    clearTimeout(progressTimer);
    progressTimer = null;
    if (
      !alive ||
      busy ||
      document.hidden ||
      !detailRecord ||
      !executionCapability.execution_supported
    ) {
      return;
    }
    const record = detailRecord;
    progressTimer = setTimeout(() => {
      progressTimer = null;
      if (detailRecord === record) {
        readProgress(record);
      }
    }, 2000);
  }

  /**
   * 业务作用：先复验当前范围权限再读取一致进度，页面换代后旧数据不能更新原文或目标。
   * 参数说明：
   * - `record`：安排本次读取时仍在详情中的原提案。
   * 返回：更新全部原目标事实与按钮资格；失败撤下旧详情，不发起自动写入。
   */
  async function readProgress(record) {
    await run(async (signal, guard) => {
      const context = checked(
        (await request(path("/context"), { signal })).data,
      );
      guard();
      if (detailRecord !== record) {
        return;
      }
      permissions = context.permissions;
      accepting = context.accept_proposals === true;
      executionCapability = capability(context);
      detailView.authorize({
        ...permissions,

        ...executionCapability,

        accept_proposals: accepting,

        execution_pending: !!unresolvedExecution,
      });
      const value = checked(
        (await request(path(`/${record.id}/execution`), { signal })).data,
      );
      guard();
      if (detailRecord === record) {
        detailView.execution(value);
      }
    });
  }

  /**
   * 业务作用：复用冻结的原始提交身份，所有未知重试保持同一字节意图和代际。
   * 参数说明：
   * - `signal`：当前请求链的取消信号。
   * - `guard`：异步后确认当前页面仍持显示及后续动作资格。
   * 返回：成功才清除未知意图；失败不生成替代键。
   */
  async function sendPending(signal, guard) {
    const original = pending;
    const { data } = await request(path(), {
      method: "POST",

      headers: {
        "content-type": "application/json",

        "idempotency-key": original.key,
      },

      body: original.body,

      signal,
    });
    guard();
    const record = checked(data).proposal;
    show(record);
    pending = null;
    form.clear();
    status.textContent = "提案已保存到共享集群，尚未执行目标动作。";
  }

  /**
   * 业务作用：取得当前准入窗口后冻结新意图，context失败不会生成已提交状态。
   * 参数说明: 无。
   * 返回：显式保存一次；已有未知意图时只提供原身份恢复入口。
   */
  async function submit() {
    if (pending) {
      return;
    }
    await run(async (signal, guard) => {
      const draft = form.read();
      const context = checked(
        (await request(path("/context"), { signal })).data,
      );
      guard();
      if (
        !context.permissions.write ||
        !context.accept_proposals ||
        !Number.isSafeInteger(context.admission_epoch) ||
        context.admission_epoch <= 0
      ) {
        throw new Error("当前入口没有可用的新提案受理资格，请刷新状态。");
      }
      const digest = await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(draft.candidate),
      );
      guard();
      const candidateSha256 = Array.from(new Uint8Array(digest), (byte) =>
        byte.toString(16).padStart(2, "0"),
      ).join("");
      pending = {
        key: crypto.randomUUID(),

        epoch: context.admission_epoch,

        candidateSha256,

        targets: JSON.stringify(
          [...draft.targets].sort((left, right) =>
            left.node_id < right.node_id ? -1 : 1,
          ),
        ),

        ttlSeconds: draft.ttl_seconds,

        body: JSON.stringify({
          ...draft,

          domain: selectedDomain,

          admission_epoch: context.admission_epoch,
        }),
      };
      showPending();
      status.textContent = "正在保存提案；请保留原请求身份直到结果明确。";
      await sendPending(signal, guard);
    });
  }

  /**
   * 业务作用：用原身份读取共享记录，查询不会重新执行提案保存或修改候选。
   * 参数说明：
   * - `key`：原 Idempotency-Key。
   * - `epoch`：原代际的十进制文本，兼容请求为零。
   * 返回：当前主体存在保留记录时显示该记录；缺失不推断提交已回滚。
   */
  async function resolve(key, epoch) {
    await run(async (signal, guard) => {
      if (
        !/^[A-Za-z0-9_.-]{1,128}$/.test(key) ||
        !/^[0-9]{1,19}$/.test(epoch)
      ) {
        throw new Error("请输入完整的原受理代际和幂等键。");
      }
      const { data } = await request(path("/resolve"), {
        signal,

        headers: {
          "idempotency-key": key,

          "naway-admission-epoch": epoch,
        },
      });
      guard();
      const record = checked(data).proposal;
      if (pending?.key === key && String(pending.epoch) === epoch) {
        if (
          record.candidate_sha256 !== pending.candidateSha256 ||
          JSON.stringify(record.targets) !== pending.targets ||
          record.domain !== selectedDomain ||
          record.expires_at_ms - record.created_at_ms !==
            pending.ttlSeconds * 1000
        ) {
          throw new Error(
            "原键对应的记录与本页冻结意图不同，请核查原记录；不能把它认定为本次草稿成功。",
          );
        }
      }
      show(record);
      if (pending?.key === key && String(pending.epoch) === epoch) {
        pending = null;
        form.clear();
      }
      status.textContent =
        "已找到当前主体的原提案；这只证明记录已保存，不表示目标已执行。";
    });
  }

  /**
   * 业务作用：在离开页面前持续提示未知提交的恢复身份，避免用新键掩盖原结果。
   * 参数说明: 无。
   * 返回：仅展示低敏身份，不显示或持久保存冻结的候选正文。
   */
  function showPending() {
    pendingPanel.replaceChildren();
    pendingPanel.hidden =
      (!pending && !unresolvedReview && !unresolvedExecution) ||
      document.hidden;
    if (document.hidden) {
      return;
    }
    if (unresolvedExecution) {
      const original = unresolvedExecution;
      const reread = element("button", "读取原执行状态");
      reread.type = "button";
      reread.disabled = busy;
      reread.addEventListener("click", () => {
        readRecord(original.id);
      });
      const clear = element("button", "清空本页执行身份");
      clear.type = "button";
      clear.disabled = busy;
      clear.addEventListener("click", () => {
        if (!busy && unresolvedExecution === original) {
          unresolvedExecution = null;
          clearDetail();
          showPending();
          status.textContent = `本页提示已清空，未撤销执行。请继续核查原提案 ${original.id}。`;
        }
      });
      pendingPanel.append(
        element(
          "p",
          `执行结果需要确认：${original.id} · SHA-256 ${original.digest}。请保留原身份，只读查询；未找到不能证明在途提交已回滚。`,
          "proposal-digest",
        ),
        reread,
        clear,
      );
    }
    if (unresolvedReview) {
      const id = unresolvedReview;
      const reread = element("button", "读取原审阅结果");
      reread.type = "button";
      reread.disabled = busy;
      reread.addEventListener("click", () => {
        readRecord(id);
      });
      const clearReview = element("button", "清空本页审阅身份");
      clearReview.type = "button";
      clearReview.disabled = busy;
      clearReview.addEventListener("click", () => {
        if (!busy && unresolvedReview === id) {
          unresolvedReview = null;
          showPending();
          status.textContent = `已清空本页提示，未撤销审阅。请继续核查原提案 ${id}。`;
        }
      });
      pendingPanel.append(
        element(
          "p",
          `审阅结果需要确认：${id}。先读取原记录，未找到或仍为待审不能证明原事务已回滚。`,
        ),
        reread,
        clearReview,
      );
    }
    if (!pending) {
      return;
    }
    const identity = element("textarea");
    identity.readOnly = true;
    identity.rows = 4;
    identity.value = JSON.stringify({
      cluster_id: cluster,

      workspace,

      domain: selectedDomain,

      admission_epoch: pending.epoch,

      idempotency_key: pending.key,

      candidate_sha256: pending.candidateSha256,
    });
    const lookup = element("button", "查找这个原请求");
    const retry = element("button", "按原身份重试保存");
    const clear = element("button", "清空本页原请求");
    lookup.type = retry.type = clear.type = "button";
    lookup.disabled = retry.disabled = clear.disabled = busy;
    retry.disabled ||= !accepting || !permissions.write;
    const original = pending;
    lookup.addEventListener("click", () => {
      if (pending === original) {
        resolve(original.key, String(original.epoch));
      }
    });
    retry.addEventListener("click", () => {
      if (pending === original) {
        run(sendPending);
      }
    });
    clear.addEventListener("click", () => {
      if (busy || pending !== original) {
        return;
      }
      pending = null;
      form.clear();
      showPending();
      controls();
      status.textContent =
        "已清空本页意图，未撤销可能已经保存的提案。请用原身份核查原结果。";
    });
    pendingPanel.append(
      element("h2", "原请求结果需要确认"),
      element(
        "p",
        "离开页面或退出会清空内存。请先复制下面的原身份；不要自动换新键或新代际重新创建操作。",
        "subtle",
      ),
      field("原请求身份（可复制到另一 Admin 核查）", identity),
      lookup,
      retry,
      clear,
    );
  }

  /**
   * 业务作用：切换授权范围时取消旧读取并清空原文；未知提交须先查找或明确清空。
   * 参数说明: 无。
   * 返回：新范围重新获取服务器权限，不沿用另一域的按钮资格。
   */
  function scopeChanged() {
    if (pending || unresolvedReview || unresolvedExecution) {
      scopes.value = workspace;
      domain.value = selectedDomain;
      status.textContent =
        "原请求结果尚需确认，请先查找或明确清空原请求，再切换范围。";
      return;
    }
    generation += 1;
    controller?.abort();
    busy = false;
    clearDetail();
    form.clear();
    permissions = {};
    accepting = false;
    executionCapability = {};
    pages = [""];
    page = 0;
    nextAfter = null;
    if (workspace !== scopes.value) {
      workspace = scopes.value;
      domainOptions();
    } else {
      selectedDomain = domain.value;
      form.clearDraft();
    }
    list.replaceChildren();
    reload();
  }

  /**
   * 业务作用：后台隐藏时取消读取并清空可见原文，未知意图只留内存供显式恢复。
   * 参数说明: 无。
   * 返回：重新可见后只刷新读取，不自动重试保存或审阅。
   */
  function visibility() {
    generation += 1;
    controller?.abort();
    busy = false;
    clearDetail();
    form.clear();
    list.replaceChildren();
    showPending();
    controls();
    if (!document.hidden) {
      reload();
    }
  }

  /**
   * 业务作用：销毁当前页的网络资格、草稿和原请求内存，旧响应不能跨会话回填。
   * 参数说明: 无。
   * 返回：全部可见敏感内容与监听移除，不改变任何数据库事实。
   */
  function dispose() {
    alive = false;
    generation += 1;
    controller?.abort();
    pending = null;
    unresolvedReview = null;
    unresolvedExecution = null;
    form.clear();
    clearDetail();
    recoverKey.value = recoverEpoch.value = "";
    document.removeEventListener("visibilitychange", visibility);
    root.replaceChildren();
  }

  scopes.addEventListener("change", scopeChanged);
  domain.addEventListener("change", scopeChanged);
  refresh.addEventListener("click", () => {
    if (!busy) {
      pages = [""];
      page = 0;
      reload();
    }
  });
  previous.addEventListener("click", () => {
    if (page > 0 && !busy) {
      page -= 1;
      reload();
    }
  });
  next.addEventListener("click", () => {
    if (nextAfter && !busy) {
      pages = pages.slice(0, page + 1);
      pages.push(nextAfter);
      page += 1;
      reload();
    }
  });
  recovery.addEventListener("submit", (event) => {
    event.preventDefault();
    resolve(recoverKey.value.trim(), recoverEpoch.value.trim());
  });
  document.addEventListener("visibilitychange", visibility);
  domainOptions();
  if (selectedDomain) {
    reload();
  } else {
    status.textContent = "当前主体没有可读取的提案范围。";
    controls();
  }
  return dispose;
}
