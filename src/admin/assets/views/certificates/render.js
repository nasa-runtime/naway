import { card, element } from "../../core/dom.js";

const states = {
  available: "目录完整",
  partial: "部分覆盖",
  pending: "等待安装事实",
  sampling: "等待节点报告",
  unsupported: "未提供证书目录",
  stale: "节点事实已过期",
  unknown: "缺少节点事实",
  capacity: "观察容量不足",
  identity_conflict: "节点身份冲突",
  authority_mismatch: "工作区权限不一致",
  unconfigured: "未声明成员",
  not_ready: "节点尚未就绪",
  not_serving: "纯管理节点，不承载业务 TLS",
  complete: "材料已安装",
  waiting: "等待首张可用证书",
  unavailable: "公开证书事实不可用",
  unauthorized: "动态身份已失权或到期",
};
const sources = {
  file: "静态文件",
  manifest: "原子材料指针",
  acme: "ACME",
  sds: "SDS 内存",
  spire: "SPIRE Workload API",
};

/**
 * 业务作用：以明确时区展示证书绝对时刻，非法日期不能中断整页节点覆盖展示。
 * 参数说明：
 * - `seconds`：证书或 OCSP 中的 Unix 秒。
 * 返回：UTC 时间文本；超出浏览器日期范围时明确不可展示。
 */
function instant(seconds) {
  const value = new Date(seconds * 1000);
  return Number.isFinite(value.getTime())
    ? value.toISOString()
    : "时间超出可显示范围";
}

/**
 * 业务作用：展示实际安装身份、有效期与授权门，未知节点不得成为证书已删除的证据。
 * 参数说明：
 * - `view`：通过授权范围及有效年龄检查的当前目录页。
 * - `cards`：完整节点分母摘要容器。
 * - `nodes`：全部授权成员状态容器。
 * - `bindings`：当前页逐节点身份变体容器。
 * 返回：只通过文本节点呈现公开证书事实，不插入来源字符串中的 HTML。
 */
export function render(view, cards, nodes, bindings) {
  cards.replaceChildren(
    card(
      "完整目录节点",
      `${view.coverage.complete} / ${view.coverage.total}`,
      "保留全部声明成员",
    ),
    card("未知节点", String(view.coverage.unknown), "无法据此确认缺失"),
    card(
      "匹配选证绑定",
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
    panel.append(element("h2", `${row.listener} · ${row.protocol}`));
    panel.append(element("p", row.binding ? `SNI ${row.binding}` : "默认身份"));
    for (const variant of row.variants) {
      const binding = variant.binding;
      const details = element("div", "", "state-row");
      details.append(element("strong", variant.nodes.join(" / ")));
      details.append(
        element(
          "span",
          `${states[binding.state] ?? "当前无法确认"} · ${sources[binding.source] ?? "来源待确认"}`,
        ),
      );
      if (binding.selection_order > 0) {
        details.append(
          element("span", `通配后缀匹配顺序 ${binding.selection_order}`),
        );
      }
      const leaf = binding.leaf;
      if (leaf) {
        details.append(element("code", `SHA-256 ${leaf.sha256}`));
        details.append(
          element(
            "span",
            `生效 ${instant(leaf.not_before)} · 到期 ${instant(leaf.not_after)}`,
          ),
        );
        const now = Date.now() / 1000;
        const validity =
          now < leaf.not_before
            ? "证书尚未生效"
            : now >= leaf.not_after
              ? "证书已过期"
              : `预计剩余 ${Math.floor((leaf.not_after - now) / 86400)} 天`;
        details.append(element("span", `${validity}（按当前查看设备时钟）`));
        details.append(
          element("span", leaf.names.join(" / ") || "没有 DNS、URI 或 IP SAN"),
        );
      }
      if (binding.ocsp_valid_until !== null) {
        details.append(
          element(
            "span",
            `OCSP 截止 ${instant(binding.ocsp_valid_until)} · ${binding.ocsp_required ? "过期拒绝新握手" : "过期允许不携带 staple"}`,
          ),
        );
      }
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
        `确认已安装：${row.present} · 未声明此绑定：${row.missing.join(" / ") || "无"} · 不承载 TLS：${row.not_serving.join(" / ") || "无"} · 无法确认：${row.unknown.join(" / ") || "无"}`,
        "subtle",
      ),
    );
    bindings.append(panel);
  }
  if (!view.bindings.length) {
    bindings.append(
      element(
        "p",
        "当前有证据的节点中没有匹配的安装绑定；未知节点仍需等待。",
        "subtle",
      ),
    );
  }
}
