/**
 * 业务作用：管理工作区集群目录的分页与当前采样，所有请求固定在已授权工作区路径。
 *
 * 参数说明：
 * - `request`：同源有界认证读取函数。
 * - `element`：固定页面控件查找函数。
 * - `notify`：低敏错误提示函数。
 *
 * 返回：载入与清空控制器；退出、隐藏或范围变化取消旧请求并丢弃旧数据。
 */
export function createCatalog({ request, element, notify }) {
  let endpoint = "",
    generation = 0,
    controller = null,
    timer = null;
  let offset = 0,
    next = null,
    etag = null;
  let search = "";

  /**
   * 业务作用：清除当前目录的读取权威和可见数据，迟到响应不能跨工作区回填。
   *
   * 参数说明: 无。
   *
   * 返回：取消请求、定时器与游标，所有对象和节点状态被移除。
   */
  function clear() {
    generation += 1;
    controller?.abort();
    clearTimeout(timer);
    controller = null;
    timer = null;
    endpoint = "";
    offset = 0;
    next = null;
    etag = null;
    for (const id of ["objects", "catalog-coverage", "catalog-nodes"]) {
      element(id).replaceChildren();
    }
    element("next").disabled = true;
    element("first").disabled = true;
  }

  /**
   * 业务作用：把授权成员覆盖和对象分布展示为纯文本，并保留同页展开详情。
   *
   * 参数说明：
   * - `value`：服务端按工作区过滤的当前完整响应。
   *
   * 返回：仅更新当前对象视图，不保存历史样本。
   */
  function render(value) {
    const expanded = new Set(
      [...element("objects").querySelectorAll("details[open]")].map(
        (item) => item.dataset.key,
      ),
    );
    const focused = element("objects").contains(document.activeElement)
      ? document.activeElement.closest("details")?.dataset.key
      : null;
    const coverage = value.coverage;
    const status = {
      unconfigured: "尚未配置工作区集群节点范围",

      available: "授权节点目录完整",

      partial: "部分节点未知，不能认定对象缺失",
    };
    element("catalog-coverage").textContent =
      `${status[value.availability] || "等待目录"} · 完整 ${coverage.complete}/${coverage.total} · 未知 ${coverage.unknown} · 对象 ${value.total_objects} · 页偏移 ${offset}`;
    const labels = {
      available: "可读",

      unknown: "未观察到",

      unavailable: "不可用",

      authority_mismatch: "权限不一致",

      unsupported: "不支持工作区目录",

      pending: "目录接收中",

      capacity: "目录容量不足",

      identity_conflict: "节点身份冲突",
    };
    element("catalog-nodes").replaceChildren();
    for (const node of value.nodes) {
      const item = document.createElement("span");
      item.className = "catalog-node";
      item.textContent = `${node.id} · ${labels[node.availability] || "未知"}`;
      element("catalog-nodes").append(item);
    }
    element("objects").replaceChildren();
    for (const object of value.objects) {
      const detail = document.createElement("details"),
        summary = document.createElement("summary"),
        body = document.createElement("pre");
      detail.dataset.key = JSON.stringify([
        object.kind,
        object.parent,
        object.id,
      ]);
      detail.open = expanded.has(detail.dataset.key);
      summary.textContent = `${object.parent ? object.parent + " / " : ""}${object.id} · 存在 ${object.present} · 缺失 ${object.missing.length} · 未知 ${object.unknown.length}`;
      body.textContent = JSON.stringify(object, null, 2);
      detail.append(summary, body);
      element("objects").append(detail);
      if (focused === detail.dataset.key) {
        summary.focus({ preventScroll: true });
      }
    }
    if (!value.objects.length) {
      element("objects").textContent =
        value.availability === "available"
          ? "当前查询没有对象"
          : "尚无可确认的对象；请结合节点覆盖判断";
    }
    next = value.next_offset;
    element("next").disabled = next == null;
    element("first").disabled = offset === 0;
  }

  /**
   * 业务作用：串行刷新当前授权页，以同一目录ETag约束后续分页并限制请求存活时间。
   *
   * 参数说明：
   * - `reset`：查询条件或用户选择变更时回到首页。
   *
   * 返回：成功显示当前事实，失败清除旧对象；可见且仍有范围时安排下一次采样。
   */
  async function refresh(reset = false) {
    if (!endpoint || document.hidden) {
      return;
    }
    clearTimeout(timer);
    controller?.abort();
    controller = new AbortController();
    const stamp = ++generation;
    if (reset) {
      search = element("catalog-search").value;
      offset = 0;
      etag = null;
      element("objects").replaceChildren();
    }
    try {
      const query = new URLSearchParams({
        domain: element("catalog-domain").value,

        search,

        offset: String(offset),

        limit: "25",
      });
      const { response, value } = await request(
        `${endpoint}/cluster/catalog?${query}`,
        {
          headers: offset && etag ? { "If-Match": etag } : {},

          signal: controller.signal,
        },
      );
      if (stamp !== generation) {
        return;
      }
      etag = response.headers.get("etag");
      render(value);
    } catch (error) {
      if (stamp === generation && error.name !== "AbortError") {
        element("objects").replaceChildren();
        element("catalog-nodes").replaceChildren();
        element("catalog-coverage").textContent =
          "当前目录不可确认，等待重新读取";
        offset = 0;
        next = null;
        etag = null;
        element("next").disabled = true;
        notify(error.message);
      }
    } finally {
      if (stamp === generation && endpoint && !document.hidden) {
        timer = setTimeout(refresh, 2000);
      }
    }
  }

  /**
   * 业务作用：把对象读取切换到当前授权工作区，跨范围状态不能继续复用。
   *
   * 参数说明：
   * - `path`：工作区入口生成的固定同源API前缀。
   *
   * 返回：开始读取首页；相同范围显式刷新时保留当前页与展开状态。
   */
  async function load(path) {
    if (endpoint !== path) {
      clear();
      endpoint = path;
      search = element("catalog-search").value;
    }
    await refresh();
  }

  element("catalog-domain").onchange = () => refresh(true);
  element("catalog-query").onsubmit = (event) => {
    event.preventDefault();
    refresh(true);
  };
  element("next").onclick = () => {
    if (next != null) {
      offset = next;
      element("objects").replaceChildren();
      refresh();
    }
  };
  element("first").onclick = () => refresh(true);
  return {
    load,

    clear,
  };
}
