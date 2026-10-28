import { createCatalog } from "/ui/workspaces/catalog.js";

("use strict");

/**
 * 业务作用：按页面固定标识取控件。
 *
 * 参数说明：
 * - `id`：本地固定控件标识。
 *
 * 返回：对应页面元素。
 */
const element = (id) => document.getElementById(id);
let token = "",
  generation = 0,
  etag = null,
  offset = 0,
  watching = null;
let pending = new AbortController();
/**
 * 业务作用：以纯文本展示操作结果。
 *
 * 参数说明：
 * - `text`：当前低敏操作提示。
 *
 * 返回：只更新通知区。
 */
const notify = (text) => {
  element("notice").textContent = text;
};

// 凭据或选择范围改变时清空所有旧视图；迟到响应不能重新填入先前工作区的数据。
/**
 * 业务作用：撤销当前视图代际并清空数据。
 *
 * 参数说明: 无。
 *
 * 返回：旧请求失去显示权威。
 */
function clearView() {
  catalog.clear();
  generation += 1;
  pending.abort();
  pending = new AbortController();
  watching?.abort();
  watching = null;
  etag = null;
  offset = 0;
  element("mutation").value = "";
  for (const id of [
    "objects",
    "changes",
    "rollouts",
    "audit",
    "result",
    "owner",
  ]) {
    element(id).replaceChildren();
  }
  element("next").disabled = true;
}

/**
 * 业务作用：删除页面内存凭据并退出工作区。
 *
 * 参数说明: 无。
 *
 * 返回：隐藏并清空所有授权视图。
 */
function logout() {
  clearView();
  token = "";
  element("token").value = "";
  element("workspace").replaceChildren();
  element("workspace-panel").hidden = true;
}

/**
 * 业务作用：只向同源授权 API 发起有界读取。
 *
 * 参数说明：
 * - `path`：当前授权范围内的固定同源路径。
 * - `options`：显式动作的方法、头部、正文与取消信号。
 *
 * 返回：成功 JSON；拒绝或超限抛出低敏错误。
 */
async function request(path, options = {}) {
  const headers = new Headers(options.headers);
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }
  const response = await fetch(path, {
    ...options,

    signal: options.signal
      ? AbortSignal.any([
          pending.signal,
          options.signal,
          AbortSignal.timeout(15000),
        ])
      : AbortSignal.any([pending.signal, AbortSignal.timeout(15000)]),

    headers,

    credentials: "same-origin",

    cache: "no-store",

    redirect: "error",
  });
  if (response.status === 304) {
    return {
      response,

      value: null,
    };
  }
  const reader = response.body?.getReader(),
    decoder = new TextDecoder();
  let text = "",
    bytes = 0;
  if (reader) {
    try {
      for (;;) {
        const part = await reader.read();
        if (part.done) {
          break;
        }
        bytes += part.value.byteLength;
        if (bytes > 4 * 1024 * 1024) {
          await reader.cancel();
          throw new Error("响应超过页面预算");
        }
        text += decoder.decode(part.value, { stream: true });
      }
      text += decoder.decode();
    } finally {
      reader.releaseLock();
    }
  }
  if (!response.ok) {
    if (
      response.status === 401 ||
      response.status === 403 ||
      response.status === 404
    ) {
      clearView();
    }
    throw new Error(`操作未完成：HTTP ${response.status}，请刷新权限或基线`);
  }
  return {
    response,

    value: JSON.parse(text),
  };
}

/**
 * 业务作用：固定当前工作区 API 前缀。
 *
 * 参数说明: 无。
 *
 * 返回：编码后的同源路径。
 */
function base() {
  return `/api/workspaces/${encodeURIComponent(element("workspace").value)}`;
}

/**
 * 业务作用：展示本区审批与发布动作。
 *
 * 参数说明：
 * - `id`：本地固定列表容器标识。
 * - `records`：当前工作区可见的操作记录。
 * - `kind`：固定的 changes 或 rollouts 目录类型。
 * - `stamp`：发起读取时冻结的页面代际。
 * - `endpoint`：已授权工作区的固定 API 前缀。
 *
 * 返回：按服务端摘要绑定按钮，迟到动作不执行。
 */
function displayActions(id, records, kind, stamp, endpoint) {
  const target = element(id);
  target.replaceChildren();
  if (!records.length) {
    target.textContent = "暂无本区记录";
    return;
  }
  for (const record of records) {
    const row = document.createElement("div");
    row.className = "row";
    const detail = document.createElement("pre");
    detail.textContent = JSON.stringify(record, null, 2);
    row.append(detail);
    const changeId = record.id;
    for (const action of ["approve", "reject"]) {
      const button = document.createElement("button");
      button.type = "button";
      button.textContent = action === "approve" ? "批准" : "拒绝";
      button.disabled =
        kind === "changes"
          ? record.status !== "pending"
          : !["canary_published", "observing", "awaiting_approval"].includes(
              record.phase,
            );
      button.addEventListener("click", () =>
        run(async () => {
          if (stamp !== generation) {
            return;
          }
          button.disabled = true;
          const { value } = await request(
            `${endpoint}/${kind}/${encodeURIComponent(changeId)}/${action}`,
            {
              method: "POST",

              headers: { "If-Match": record.candidate_etag },
            },
          );
          if (stamp !== generation) {
            return;
          }
          element("result").textContent = JSON.stringify(value, null, 2);
          offset = 0;
          await refresh();
        }),
      );
      row.append(button);
    }
    target.append(row);
  }
}

/**
 * 业务作用：读取同代分页与本域操作记录。
 *
 * 参数说明: 无。
 *
 * 返回：成功更新视图；基线漂移或撤权时保留拒绝语义。
 */
async function refresh() {
  const stamp = generation,
    endpoint = base();
  const headers = offset && etag ? { "If-Match": etag } : {};
  const { response, value } = await request(
    `${endpoint}/objects?offset=0&limit=1`,
    { headers },
  );
  if (stamp !== generation) {
    return;
  }
  etag = response.headers.get("etag");
  await catalog.load(endpoint);
  if (stamp !== generation) {
    return;
  }
  element("owner").textContent =
    `工作区 ${element("workspace").value} · 当前接入节点的操作基线 ${value.configuration_version}`;
  // 单页面按顺序读取，避免浏览器自身抢满本域控制操作槽。
  for (const kind of ["changes", "rollouts", "audit"]) {
    const { value: data } = await request(`${endpoint}/${kind}`);
    if (stamp !== generation) {
      return;
    }
    if (kind === "audit") {
      element("audit").textContent = JSON.stringify(data, null, 2);
    } else {
      displayActions(kind, data[kind] || [], kind, stamp, endpoint);
    }
  }
}

/**
 * 业务作用：收束页面异步动作的拒绝结果。
 *
 * 参数说明：
 * - `action`：用户显式发起的异步动作。
 *
 * 返回：异常只显示纯文本，取消不产生误报。
 */
async function run(action) {
  try {
    await action();
  } catch (error) {
    if (error.name !== "AbortError") {
      notify(error.message);
    }
  }
}

const catalog = createCatalog({
  request,

  element,

  notify,
});

// 隐藏页面时不保留租户对象或在途读取；重新可见后重新认证并读取当前事实。
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    clearView();
  } else if (token && element("workspace").value) {
    run(refresh);
  }
});

// 登录时先取输入再清理旧会话，避免旧认证与新目录混用。
element("login").onsubmit = (event) => {
  event.preventDefault();
  const entered = element("token").value;
  run(async () => {
    if (
      location.protocol !== "https:" &&
      !["localhost", "127.0.0.1", "[::1]"].includes(location.hostname)
    ) {
      throw new Error("远程工作区管理需要 HTTPS");
    }
    logout();
    token = entered;
    const stamp = generation;
    const { value } = await request("/api/workspaces");
    if (stamp !== generation) {
      return;
    }
    for (const workspace of value.workspaces) {
      const option = document.createElement("option");
      option.value = workspace.id;
      option.textContent = `${workspace.id} · ${workspace.role}`;
      element("workspace").append(option);
    }
    element("workspace-panel").hidden = !value.workspaces.length;
    notify(
      value.workspaces.length
        ? "已连接授权工作区"
        : "当前主体没有工作区成员关系",
    );
    if (value.workspaces.length) {
      await refresh();
    }
  });
};
element("disconnect").onclick = () => {
  logout();
  notify("已清除页面凭据与工作区数据");
};
element("workspace").onchange = () => {
  clearView();
  run(refresh);
};
element("refresh").onclick = () => {
  offset = 0;
  run(refresh);
};
element("export").onclick = () =>
  run(async () => {
    const stamp = generation;
    const { value } = await request(
      `${base()}/export?offset=${offset}&limit=64`,
      { headers: { "If-Match": etag } },
    );
    if (stamp === generation) {
      element("result").textContent = JSON.stringify(value, null, 2);
    }
  });
element("submit").onclick = () =>
  run(async () => {
    const stamp = generation,
      text = element("mutation").value;
    if (!etag || new TextEncoder().encode(text).length > 65536) {
      throw new Error("请先载入基线，候选不得超过 64 KiB");
    }
    JSON.parse(text);
    const { value } = await request(`${base()}/changes`, {
      method: "POST",

      headers: {
        "Content-Type": "application/json",

        "If-Match": etag,
      },

      body: text,
    });
    if (stamp !== generation) {
      return;
    }
    element("result").textContent = JSON.stringify(value, null, 2);
    await refresh();
  });
element("watch").onclick = () =>
  run(async () => {
    watching?.abort();
    watching = new AbortController();
    const stamp = generation;
    const { response } = await request(`${base()}/watch`, {
      headers: { "If-None-Match": etag },

      signal: watching.signal,
    });
    if (stamp !== generation) {
      return;
    }
    notify(
      response.status === 304
        ? "观察窗口内无配置变更"
        : "配置已变化，已重新读取本区目录",
    );
    if (response.status !== 304) {
      offset = 0;
      await refresh();
    }
  });
