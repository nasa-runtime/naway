import { request } from "../core/http.js";
import { element } from "../core/dom.js";
import {
  button,
  checkedRecord,
  epoch,
  field,
  hex,
  token,
} from "./materials/common.js";
import { materialApi } from "./materials/api.js";
import { materialForm } from "./materials/form.js";
import { materialDetail } from "./materials/detail.js";
import { checkedImpact } from "./materials/impact.js";
import { recoveryView } from "./materials/recovery.js";

/**
 * 业务作用：在独立材料域协调完整目标、秘密提交、双人审批与原任务读取，所有迟到响应受同一页面代约束。
 * 参数说明：
 * - `root`：统一管理壳的当前视图容器。
 * - `session`：真实认证主体、授权工作区及共享集群。
 * 返回：退出时取消请求并清空秘密和事实的函数；未知提交仅保留隔离的低敏原身份。
 */
export function mount(root, session) {
  const cluster = session.operations?.cluster_id;
  const platform = ["certificate-proposals", "certs", "cluster"].every(
    (resource) => session.permissions?.[resource]?.includes("read"),
  );
  if (
    !session.operations?.enabled ||
    !token(cluster) ||
    (!platform && !session.workspaces?.length)
  ) {
    root.replaceChildren(
      element(
        "section",
        "当前入口没有可用的共享材料管理范围。请使用已启用材料存储且获授权的管理入口。",
        "panel",
      ),
    );
    return () => {
      root.replaceChildren();
    };
  }
  const scopes = element("select");
  scopes.setAttribute("aria-label", "材料范围");
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
  let workspace = scopes.value;
  let alive = true;
  let generation = 0;
  let controller = null;
  let busy = false;
  let context = {};
  let record = null;
  let detailView = null;
  let pages = [""];
  let page = 0;
  let nextAfter = null;
  let poll = false;
  let timer = null;
  const status = element("p", "正在读取共享材料…", "status-pill");
  status.setAttribute("role", "status");
  const list = element("section", "", "panel proposal-list");
  const detail = element("section", "", "panel proposal-detail");
  const refresh = button("刷新材料提案", () => {
    if (!busy) {
      resetPage();
      loadScope();
    }
  });
  const previous = button("上一页", () => {
    if (!busy && page > 0) {
      page -= 1;
      loadPage();
    }
  });
  const next = button("下一页", () => {
    if (!busy && nextAfter) {
      pages = pages.slice(0, page + 1);
      pages.push(nextAfter);
      page += 1;
      loadPage();
    }
  });
  const toolbar = element("div", "", "monitor-toolbar");
  toolbar.append(field("材料范围", scopes), refresh);
  const paging = element("div", "", "monitor-toolbar");
  paging.append(previous, next);
  const recovery = recoveryView(cluster, session.principal, scope, resolve);
  const form = materialForm(cluster, scope, {
    load: loadTargets,

    inspect: inspectTargets,

    submit: submitMaterial,
  });
  root.replaceChildren(
    element(
      "p",
      `共享集群：${cluster} · 接入Admin：${location.host}`,
      "proposal-context",
    ),
    element(
      "p",
      "材料保存、pair审阅、完整影响审批和执行是独立动作。原任务包含全部原节点及实际协议证据；结果未知时只按原身份回读。",
      "subtle",
    ),
    toolbar,
    status,
    list,
    paging,
    detail,
    recovery.node,
    form.node,
  );
  if (session.workspaces_truncated) {
    toolbar.append(
      element("p", "授权工作区目录已截断，仅展示本次返回的范围。", "subtle"),
    );
  }

  /**
   * 业务作用：表达当前唯一材料域，不借平台范围读取工作区对象。
   * 参数说明: 无。
   * 返回：平台或精确工作区scope。
   */
  function scope() {
    return workspace ? `workspace.${workspace}` : "platform";
  }

  /**
   * 业务作用：把独立材料权限与未决身份传播到所有控件，只读恢复不被未决写入阻断。
   * 参数说明: 无。
   * 返回：更新表单、详情、分页及原请求恢复资格。
   */
  function access() {
    const pending = recovery.entries().length > 0;
    const value = {
      ...context,
      principal: session.principal,
      pending,
    };
    form.access(context.material ?? null, busy || pending);
    recovery.access(context.material?.access?.read === true, busy);
    detailView?.access(value, busy);
    refresh.disabled = busy;
    previous.disabled = busy || page === 0 || !context.material?.access?.read;
    next.disabled = busy || !nextAfter || !context.material?.access?.read;
    for (const control of list.querySelectorAll("button")) {
      control.disabled = busy;
    }
  }

  /**
   * 业务作用：撤销当前详情的全部确认与实时读取，列表或范围切换不能保留旧执行资格。
   * 参数说明: 无。
   * 返回：清空原详情并取消进度计时，不改变服务端任务。
   */
  function clearDetail() {
    clearTimeout(timer);
    timer = null;
    poll = false;
    detailView?.clear();
    detailView = null;
    record = null;
    detail.replaceChildren();
  }

  /**
   * 业务作用：新列表读取撤销旧页和详情，失败时不把旧记录保留为当前范围事实。
   * 参数说明: 无。
   * 返回：恢复第一页游标并清空全部旧列表事实。
   */
  function resetPage() {
    clearDetail();
    pages = [""];
    page = 0;
    nextAfter = null;
    list.replaceChildren();
  }

  /**
   * 业务作用：在唯一请求链中冻结范围、取消信号与显示代，隐藏或切换后旧结果不能回填。
   * 参数说明：
   * - `job`：本次明确动作或只读任务。
   * - `label`：当前请求的业务说明。
   * 返回：当前有效链完成时为真；拒绝、取消或过期响应不发布旧数据。
   */
  async function run(job, label) {
    if (!alive || busy || document.hidden) {
      return false;
    }
    clearTimeout(timer);
    timer = null;
    const current = ++generation;
    const abort = new AbortController();
    controller = abort;
    busy = true;
    status.textContent = label;
    access();
    /**
     * 业务作用：确认当前请求仍持有可见页面的显示权威，已取消或跨范围响应不得发布。
     * 参数说明: 无。
     * 返回：页面、请求代和取消状态全部仍有效才为真。
     */
    const valid = () =>
      alive &&
      current === generation &&
      !document.hidden &&
      !abort.signal.aborted;
    /**
     * 业务作用：请求前后复验同一页面代，防止隐藏或换域期间的旧数据恢复交互资格。
     * 参数说明：
     * - `path`：当前材料域的同源入口。
     * - `options`：固定动作参数，取消信号由本次请求链统一提供。
     * 返回：仍属于当前页面的完整响应；失权时拒绝回填。
     */
    const send = async (path, options = {}) => {
      if (!valid()) {
        throw new DOMException("页面已切换", "AbortError");
      }
      const result = await request(path, {
        ...options,
        signal: abort.signal,
      });
      if (!valid()) {
        throw new DOMException("页面已切换", "AbortError");
      }
      return result;
    };
    const api = materialApi(send, cluster, workspace);
    try {
      await job(api, send);
      if (valid()) {
        status.textContent = recovery.entries().length
          ? "仍有原请求结果待确认，请按原身份查询。"
          : "已读取当前范围的完整事实。";
        return true;
      }
    } catch (error) {
      if (valid()) {
        if (error.status === 403 || error.status === 401) {
          context = {};
          form.clear();
          resetPage();
          recovery.clear();
        }
        status.textContent =
          error.name === "AbortError"
            ? "请求已取消或超时；若曾发送写入，请按原身份查询。"
            : error.message;
      }
    } finally {
      if (alive && current === generation) {
        busy = false;
        controller = null;
        access();
        schedule();
      }
    }
    return false;
  }

  /**
   * 业务作用：页面只对已经显示的原任务进行有界只读刷新，写入和恢复身份从不自动重放。
   * 参数说明: 无。
   * 返回：当前可见、获权且无请求占用时安排一次进度查询。
   */
  function schedule() {
    clearTimeout(timer);
    timer = null;
    if (
      alive &&
      !busy &&
      !document.hidden &&
      poll &&
      record &&
      context.material?.access?.read
    ) {
      timer = setTimeout(() => {
        loadProgress(record);
      }, 2000);
    }
  }

  /**
   * 业务作用：展示经过完整范围核对的单页材料，选择动作只引用原提案身份。
   * 参数说明：
   * - `data`：完整分页结果。
   * 返回：替换列表与下一游标，空列表明确显示。
   */
  function showPage(data) {
    list.replaceChildren(element("h2", `材料提案 · 第 ${page + 1} 页`));
    nextAfter = data.next_after;
    for (const value of data.proposals) {
      const row = element("article", "", "proposal-row");
      row.append(
        element("strong", value.id),
        element(
          "span",
          `${value.status} · ${value.creator} · ${value.targets.length}个原逻辑目标`,
        ),
        button("查看此材料", () => openRecord(value.id)),
      );
      list.append(row);
    }
    if (!data.proposals.length) {
      list.append(element("p", "此页没有材料记录。", "subtle"));
    }
  }

  /**
   * 业务作用：重新读取当前材料与独立能力，再加载第一页，不从session角色猜测可写动作。
   * 参数说明: 无。
   * 返回：当前范围的上下文与有限目录；失败保持无旧授权事实。
   */
  function loadScope() {
    run(async (api) => {
      context = await api.capabilities();
      showPage(await api.list());
    }, "正在读取当前材料范围与独立能力…");
  }

  /**
   * 业务作用：按已验证游标读取另一完整页，跳页不保留旧详情的动作按钮。
   * 参数说明: 无。
   * 返回：刷新当前页与同范围能力。
   */
  function loadPage() {
    clearDetail();
    list.replaceChildren();
    nextAfter = null;
    run(async (api) => {
      context = await api.capabilities();
      showPage(await api.list(pages[page]));
    }, "正在读取材料目录…");
  }

  /**
   * 业务作用：给完整原记录装配彼此独立的pair、影响和执行动作，当前主体来自真实session。
   * 参数说明：
   * - `value`：本次完整读取并验证的原材料记录。
   * 返回：替换详情并绑定全部动作到该原记录。
   */
  function showRecord(value) {
    clearDetail();
    record = value;
    detailView = materialDetail(
      detail,
      value,
      {
        ...context,

        principal: session.principal,

        pending: recovery.entries().length > 0,
      },
      {
        review: reviewMaterial,

        progress: loadProgress,

        impact: {
          read: loadImpact,

          register: registerImpact,

          review: reviewImpact,

          execute: startExecution,
        },
      },
    );
  }

  /**
   * 业务作用：一次读链中核对原材料及可用的完整影响和任务，缺新执行开关仍允许原任务读取。
   * 参数说明：
   * - `api`：本次固定范围的客户端。
   * - `value`：已经验证的原材料记录。
   * 返回：显示当前完整详情；任务读取失败撤下旧进度。
   */
  async function hydrate(api, value) {
    showRecord(value);
    if (context.impact?.access?.read) {
      detailView.impact.show(await api.impact(value));
    }
    if (context.execution?.execution_supported) {
      const execution = await api.execution(value);
      detailView.execution(execution);
      poll =
        execution !== null &&
        ["running", "releasing"].includes(execution.lifecycle);
    }
  }

  /**
   * 业务作用：显式打开一个原材料的最新完整详情，旧列表状态不直接产生审批资格。
   * 参数说明：
   * - `id`：用户选中的原材料身份。
   * 返回：读取当前能力和原详情。
   */
  function openRecord(id) {
    if (busy) {
      return;
    }
    clearDetail();
    run(async (api) => {
      context = await api.capabilities();
      await hydrate(api, await api.record(id));
    }, "正在读取原材料与完整影响…");
  }

  /**
   * 业务作用：读取当前范围完整成员或单节点原声明，选择入口不借用平台目录权限。
   * 参数说明：
   * - `node`：规范原节点身份，空文本表示成员清单。
   * 返回：同代目标观察交给有年龄门的表单。
   */
  function loadTargets(node) {
    run(async (api, send) => {
      const started = performance.now();
      const result = await send(
        api.path(`/targets${node ? `/${encodeURIComponent(node)}` : ""}`),
      );
      form.targets.show(result, started, node);
    }, "正在读取材料原目标…");
  }

  /**
   * 业务作用：只查询已经冻结的完整原目标，再核对每个节点的原基线和实际来源条件。
   * 参数说明：
   * - `targets`：表单发出前的全部原目标引用。
   * 返回：整批条件成功才开放提交；不会采用未受管材料。
   */
  function inspectTargets(targets) {
    run(async (_api, send) => {
      const query = workspace
        ? `?workspace=${encodeURIComponent(workspace)}`
        : "";
      const result = await send(`/api/certificate-conditions${query}`, {
        method: "POST",

        headers: { "Content-Type": "application/json" },

        body: JSON.stringify({ targets }),
      });
      form.targets.freeze(result.data, targets);
    }, "正在查询全部原材料条件…");
  }

  /**
   * 业务作用：同一链中重新获取写入能力并保留原请求身份，未知提交从不自动换键重传。
   * 参数说明：
   * - `entry`：首次发送前登记的低敏原身份。
   * - `sendAction`：调用一次POST的明确动作。
   * - `accept`：验证并显示对应原结果的回调。
   * 返回：已明确结果时结束原台账；取消、超时或未知响应继续保留。
   */
  async function mutate(entry, sendAction, accept) {
    await run(async (api) => {
      let sent = false;
      try {
        context = await api.capabilities();
        const write =
          entry.kind === "material"
            ? context.material?.access?.write &&
              context.material.accept_proposals
            : entry.kind === "impact"
              ? context.impact?.access?.write && context.impact.accept_proposals
              : entry.kind === "execution"
                ? context.execution?.can_request_execution
                : (entry.kind === "material_review"
                    ? context.material
                    : context.impact
                  )?.access?.[entry.decision === "cancel" ? "write" : "review"];
        // 获取新上下文后的撤权不能沿用旧按钮资格，未发送的意图无需保留为未知提交。
        if (!write) {
          throw new Error("当前独立材料动作资格已变化，未发送写入请求。");
        }
        sent = true;
        const value = await sendAction(api);
        await accept(api, value);
        recovery.complete(entry);
      } catch (error) {
        // 只有尚未发送或服务端明确的受理前拒绝可结束本次身份；传输失败与503不能推定回滚。
        if (
          !sent ||
          ([400, 409, 410, 413, 429].includes(error.status) &&
            error.code !== "outcome_unknown")
        ) {
          recovery.complete(entry);
        }
        throw error;
      }
    }, "正在提交原材料动作；结果未知时保留原身份…");
  }

  /**
   * 业务作用：首次提交前冻结唯一原键与受理代，立即撤去PEM输入，后续只读恢复原结果。
   * 参数说明: 无。
   * 返回：最多发送一次完整材料正文，不在台账中保留秘密或重试副本。
   */
  async function submitMaterial() {
    if (!alive || busy || document.hidden || recovery.entries().length) {
      return;
    }
    let value = null;
    try {
      value = form.read();
      const entry = recovery.begin("material", {
        epoch: String(value.admission_epoch),

        key: crypto.randomUUID(),
      });
      form.clearSecrets();
      await mutate(
        entry,
        (api) => api.post("", value, { "Idempotency-Key": entry.key }),
        async (api, data) => {
          const saved = checkedRecord(data.proposal, cluster, scope());
          if (
            saved.creator !== session.principal ||
            String(saved.admission_epoch) !== entry.epoch
          ) {
            throw new Error("材料保存响应不属于原主体或原受理代。");
          }
          form.clear();
          await hydrate(api, saved);
        },
      );
    } catch (error) {
      status.textContent = error.message;
    } finally {
      value = null;
      form.clearSecrets();
    }
  }

  /**
   * 业务作用：用原证书链摘要提交一次pair审阅，双人约束仍由服务端当前权限复验。
   * 参数说明：
   * - `value`：当前原材料记录。
   * - `decision`：明确批准、拒绝或本人取消。
   * 返回：保存审阅事实后重新读取原详情，不开始实际交付。
   */
  function reviewMaterial(value, decision) {
    if (busy || recovery.entries().length) {
      return;
    }
    const entry = recovery.begin("material_review", {
      proposal: value.id,

      digest: value.certificate.certificate_sha256,

      decision,
    });
    mutate(
      entry,
      (api) =>
        api.post(`/${value.id}/review`, {
          decision,
          certificate_sha256: entry.digest,
        }),
      async (api, data) => {
        const saved = checkedRecord(data.proposal, cluster, scope());
        if (
          saved.id !== value.id ||
          saved.certificate.certificate_sha256 !== entry.digest
        ) {
          throw new Error("审阅响应替换了原材料或公开摘要。");
        }
        await hydrate(api, saved);
      },
    );
  }

  /**
   * 业务作用：显式回读原材料的唯一完整影响，失败先撤下旧审批资格。
   * 参数说明：
   * - `value`：当前原材料记录。
   * 返回：完整原影响或明确本次未找到。
   */
  function loadImpact(value) {
    run(async (api) => {
      context = await api.capabilities();
      detailView.impact.show(await api.impact(value));
    }, "正在读取完整共享影响…");
  }

  /**
   * 业务作用：用独立影响受理代和原键登记服务端全目标预检，不接受客户端提供的替代来源证明。
   * 参数说明：
   * - `value`：当前完整原材料记录。
   * 返回：完整影响登记；未知时保留原键与代际供只读恢复。
   */
  function registerImpact(value) {
    if (
      busy ||
      recovery.entries().length ||
      !context.impact?.access?.write ||
      !context.impact.accept_proposals
    ) {
      return;
    }
    if (
      !epoch(context.impact.admission_epoch) ||
      Date.now() >= context.impact.epoch_expires_at_ms
    ) {
      status.textContent = "影响受理窗口已结束，请刷新当前范围后重新确认。";
      return;
    }
    const entry = recovery.begin("impact", {
      proposal: value.id,

      epoch: context.impact.admission_epoch,

      key: crypto.randomUUID(),
    });
    mutate(
      entry,
      (api) =>
        api.post(
          `/${value.id}/impact`,
          {},
          {
            "Idempotency-Key": entry.key,
            "Naway-Admission-Epoch": entry.epoch,
          },
        ),
      async (_api, data) => {
        const saved = checkedImpact(data.impact, value, cluster, scope());
        if (
          saved.creator !== session.principal ||
          saved.admission_epoch !== entry.epoch
        ) {
          throw new Error("影响登记响应不属于原请求。");
        }
        detailView.impact.show(saved);
      },
    );
  }

  /**
   * 业务作用：提交明确的原完整影响审阅，原影响身份和摘要共同固定，不从后来预检替换。
   * 参数说明：
   * - `value`：原材料记录。
   * - `impact`：已经完整展示并确认的影响。
   * - `decision`：明确的双人审批决定或本人取消。
   * 返回：同一影响的新持久状态，不触发节点交付。
   */
  function reviewImpact(value, impact, decision) {
    if (busy || recovery.entries().length) {
      return;
    }
    const entry = recovery.begin("impact_review", {
      proposal: value.id,

      impact: impact.id,

      digest: impact.impact_sha256,

      decision,
    });
    mutate(
      entry,
      (api) =>
        api.post(`/${value.id}/impact/review`, {
          decision,

          impact_id: entry.impact,

          impact_sha256: entry.digest,
        }),
      async (_api, data) => {
        const saved = checkedImpact(data.impact, value, cluster, scope());
        if (saved.id !== entry.impact || saved.impact_sha256 !== entry.digest) {
          throw new Error("影响审阅响应替换了原批准对象。");
        }
        detailView.impact.show(saved);
      },
    );
  }

  /**
   * 业务作用：只执行用户确认的原完整批准，回包未知时保留原提案和影响而不创建第二任务。
   * 参数说明：
   * - `value`：原材料记录。
   * - `impact`：已批准且完整确认的原影响。
   * 返回：唯一任务创建后开始只读进度刷新。
   */
  function startExecution(value, impact) {
    if (
      busy ||
      recovery.entries().length ||
      !context.execution?.can_request_execution
    ) {
      return;
    }
    const entry = recovery.begin("execution", {
      proposal: value.id,

      impact: impact.id,

      digest: impact.impact_sha256,
    });
    mutate(
      entry,
      (api) =>
        api.post(`/${value.id}/execution`, {
          impact_id: entry.impact,

          impact_sha256: entry.digest,
        }),
      async (api, data) => {
        api.scoped(data);
        if (
          data.proposal_id !== value.id ||
          data.impact_id !== entry.impact ||
          !hex(data.operation_id, 32) ||
          data.target_count !== value.targets.length ||
          data.node_count !==
            new Set(value.targets.map((target) => target.node_id)).size
        ) {
          throw new Error("执行创建响应没有确认原完整任务。");
        }
        const execution = await api.execution(value);
        if (
          !execution ||
          execution.operation_id !== data.operation_id ||
          execution.impact_id !== entry.impact
        ) {
          throw new Error(
            "原任务已返回身份，但完整状态尚未确认，请继续按原身份查询。",
          );
        }
        detailView.execution(execution);
        detailView.impact.retire();
        poll = true;
      },
    );
  }

  /**
   * 业务作用：读取原任务全部节点与协议进度，失败或失权立即撤下旧结果并停止自动刷新。
   * 参数说明：
   * - `value`：当前详情绑定的原材料记录。
   * 返回：完整事实更新；从不自动发出写入请求。
   */
  function loadProgress(value) {
    if (busy || record !== value) {
      return;
    }
    detailView.clearProgress("正在读取原任务的全部节点…");
    run(async (api) => {
      try {
        const execution = await api.execution(value);
        detailView.execution(execution);
        poll =
          execution !== null &&
          ["running", "releasing"].includes(execution.lifecycle);
      } catch (error) {
        poll = false;
        detailView?.clearProgress(
          "当前任务读取失败，旧进度已撤下；请显式重新读取。",
        );
        throw error;
      }
    }, "正在读取原任务进度…");
  }

  /**
   * 业务作用：只读恢复低敏原身份，未找到或仍待审阅时继续保留未知，不自动新建键或重传正文。
   * 参数说明：
   * - `entry`：当前主体、集群和范围匹配的原请求身份。
   * 返回：确认原事实后结束对应台账；其它未决身份保持不变。
   */
  function resolve(entry) {
    if (
      entry.cluster !== cluster ||
      entry.principal !== session.principal ||
      entry.scope !== scope()
    ) {
      return;
    }
    run(async (api) => {
      context = await api.capabilities();
      const value =
        entry.kind === "material"
          ? await api.resolveMaterial(entry)
          : await api.record(entry.proposal);
      showRecord(value);
      let confirmed = entry.kind === "material";
      if (entry.kind === "material_review") {
        if (value.certificate.certificate_sha256 !== entry.digest) {
          throw new Error("原审阅材料的公开摘要不一致。");
        }
        confirmed = value.status !== "awaiting_approval";
      } else if (["impact", "impact_review"].includes(entry.kind)) {
        const impact = await api.impact(
          value,
          entry.kind === "impact" ? entry : null,
        );
        if (
          impact &&
          entry.kind === "impact_review" &&
          (impact.id !== entry.impact || impact.impact_sha256 !== entry.digest)
        ) {
          throw new Error("原影响审阅身份不一致。");
        }
        detailView.impact.show(impact);
        confirmed =
          impact !== null &&
          (entry.kind === "impact" || impact.status !== "awaiting_approval");
      } else if (entry.kind === "execution") {
        const execution = await api.execution(value);
        if (execution && entry.impact && execution.impact_id !== entry.impact) {
          throw new Error("原执行使用了不同的完整影响，不能代替此请求恢复。");
        }
        detailView.execution(execution);
        confirmed = execution !== null;
        poll =
          execution !== null &&
          ["running", "releasing"].includes(execution.lifecycle);
      }
      if (confirmed) {
        recovery.complete(entry);
      }
    }, "正在按原身份回读；未找到仍保持未知…");
  }

  /**
   * 业务作用：隐藏、换域或退出前先撤销请求显示权，再清空秘密和旧范围事实。
   * 参数说明: 无。
   * 返回：旧响应不能回填，低敏未决身份仍按原主体和范围隔离保留。
   */
  function retire() {
    generation += 1;
    controller?.abort();
    controller = null;
    busy = false;
    context = {};
    form.clear();
    recovery.clear();
    resetPage();
    access();
  }

  /**
   * 业务作用：切换范围时先清空旧秘密与动作资格，再读取新范围真实权限。
   * 参数说明: 无。
   * 返回：新范围没有旧详情、条件或请求结果。
   */
  function changeScope() {
    retire();
    workspace = scopes.value;
    loadScope();
  }

  /**
   * 业务作用：后台页面不保留秘密与实时事实，返回可见状态只重新读取当前范围。
   * 参数说明: 无。
   * 返回：隐藏时全部退休，可见后不重传任何原写入。
   */
  function visibility() {
    retire();
    if (!document.hidden) {
      loadScope();
    }
  }

  /**
   * 业务作用：退出视图时释放全部页面引用、计时器和监听器，原未决身份不携带秘密正文。
   * 参数说明: 无。
   * 返回：旧视图永久失去回填和动作权威。
   */
  function dispose() {
    alive = false;
    retire();
    recovery.dispose();
    document.removeEventListener("visibilitychange", visibility);
    root.replaceChildren();
  }

  scopes.addEventListener("change", changeScope);
  document.addEventListener("visibilitychange", visibility);
  access();
  loadScope();
  return dispose;
}
