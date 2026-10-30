import { card, element } from "../../core/dom.js";

const states = {
  available: "目录完整",
  partial: "部分覆盖",
  pending: "目录接收中",
  sampling: "等待节点报告",
  unsupported: "未提供消费者目录",
  stale: "节点事实已过期",
  unknown: "缺少节点事实",
  capacity: "目录容量不足",
  identity_conflict: "节点身份冲突",
  authority_mismatch: "工作区权限不一致",
  unconfigured: "未声明成员",
  not_ready: "节点尚未就绪",
};

/**
 * 业务作用：用完整覆盖和逐节点变体呈现当前凭据绑定，不将未知解释成密钥已撤销。
 * 参数说明：
 * - `view`：通过范围和年龄校验的当前响应。
 * - `cards`：覆盖摘要容器。
 * - `nodes`：完整授权成员状态容器。
 * - `bindings`：当前页绑定容器。
 * 返回：纯文本展示节点、来源、启用状态和套餐，不解释任何身份内容为HTML。
 */
export function render(view, cards, nodes, bindings) {
  cards.replaceChildren(
    card(
      "完整目录节点",
      `${view.coverage.complete} / ${view.coverage.total}`,
      "全部声明成员作为分母",
    ),
    card("未知节点", String(view.coverage.unknown), "不作为凭据缺失证据"),
    card(
      "匹配绑定",
      String(view.total_bindings),
      states[view.availability] ?? "当前无法确认",
    ),
  );
  nodes.replaceChildren();
  for (const node of view.nodes) {
    nodes.append(
      element(
        "p",
        `${node.id} · ${states[node.availability] ?? "当前无法确认"}`,
        "state-row",
      ),
    );
  }
  bindings.replaceChildren();
  for (const row of view.bindings) {
    const panel = element("article", "", "panel");
    panel.append(element("h2", row.consumer));
    panel.append(
      element("p", `${row.proxy} / ${row.route} · 本代凭据序号 ${row.ordinal}`),
    );
    for (const variant of row.variants) {
      const binding = variant.binding;
      const details = element("div", "", "state-row");
      details.append(element("strong", variant.nodes.join(" / ")));
      details.append(
        element(
          "span",
          `${binding.enabled ? "已启用" : "已禁用"} · ${binding.source}:${binding.name}`,
        ),
      );
      details.append(
        element(
          "span",
          binding.plan ? `路由套餐 ${binding.plan}` : "本路由未选择套餐",
        ),
      );
      details.append(
        element(
          "span",
          `${binding.workspace} · ${binding.tenant || "—"} / ${binding.environment || "—"}`,
        ),
      );
      panel.append(details);
    }
    panel.append(
      element(
        "p",
        `已确认存在：${row.present} · 未声明此绑定：${row.missing.join(" / ") || "无"} · 无法确认：${row.unknown.join(" / ") || "无"}`,
        "subtle",
      ),
    );
    bindings.append(panel);
  }
  if (!view.bindings.length) {
    bindings.append(
      element(
        "p",
        "当前有证据的节点中没有匹配的原生 API-Key consumer 绑定；未知节点仍需等待。",
        "subtle",
      ),
    );
  }
}
