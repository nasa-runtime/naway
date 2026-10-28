const numberFormats = [0, 1, 2].map(
  (digits) => new Intl.NumberFormat("zh-CN", { maximumFractionDigits: digits }),
);

/**
 * 业务作用：构造纯文本UI节点，配置名称和远端错误不能成为HTML或脚本。
 * 参数说明：
 * - `tag`：页面代码中的固定标签。
 * - `text`：不可信文本或当前数字。
 * - `className`：页面代码中的固定样式类。
 * 返回：未挂载的安全节点。
 */
export function element(tag, text = "", className = "") {
  const node = document.createElement(tag);
  node.textContent = text;
  if (className) {
    node.className = className;
  }
  return node;
}

/**
 * 业务作用：让未知与真实零在指标展示中保持区别。
 * 参数说明：
 * - `value`：后端可选有限数值。
 * - `digits`：当前指标需要的小数位上限。
 * 返回：本地化数字或未知占位。
 */
export function number(value, digits = 1) {
  return typeof value === "number" && Number.isFinite(value)
    ? (
        numberFormats[digits] ??
        new Intl.NumberFormat("zh-CN", { maximumFractionDigits: digits })
      ).format(value)
    : "—";
}

/**
 * 业务作用：以当前值绘制指标卡，不保留此前采样数据。
 * 参数说明：
 * - `label`：指标业务名称。
 * - `value`：已格式化的当前结果。
 * - `detail`：单位、边界或未知原因。
 * 返回：可直接挂载的语义卡片。
 */
export function card(label, value, detail) {
  const node = element("article", "", "metric-card");
  node.append(
    element("span", label, "metric-label"),
    element("strong", value),
    element("small", detail),
  );
  return node;
}
