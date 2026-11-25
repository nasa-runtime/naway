const indentation = "  ";
const pairs = new Map([
  ["[", "]"],
  ["{", "}"],
  ['"', '"'],
  ["'", "'"],
]);
const enhanced = new WeakSet();
const scalarHeaderPattern =
  /(?:^ *-\s+|:\s+)(?:(?:&\S+|!\S+)\s+)*[|>]([1-9+-]*)$/;
const completionKeyPattern =
  /^ *(?:-[ \t]+)?(?:"([A-Za-z_][\w.-]*)"|'([A-Za-z_][\w.-]*)'|([A-Za-z_][\w.-]*))[ \t]*:(?=[ \t\r]|$)/;
export const yamlEditingHelp =
  "换行自动缩进；Tab 两空格，Shift+Tab 反缩进；括号与引号成对补全；Ctrl+Space 补齐唯一匹配的键名或 true/false/null，大文档仅补齐常量；按 Escape 后再按 Tab 跳出编辑区。";

/**
 * 业务作用：识别当前行的引号和注释边界，使输入辅助不把字符串中的冒号当作层级。
 * 参数说明：
 * - `line`：光标前的单行原文。
 * - `initialQuote`：上一行尚未关闭的引号；空字符串表示未处于跨行字符串。
 * 返回：行外层文本、尚未关闭的引号及注释状态；不解析或求值配置。
 */
function lineContext(line, initialQuote = "") {
  let quote = initialQuote;
  let text = "";
  let comment = false;
  for (let index = 0; index < line.length; index += 1) {
    const character = line[index];
    if (quote) {
      if (quote === '"' && character === "\\") {
        index += 1;
      } else if (quote === character) {
        if (quote === "'" && line[index + 1] === "'") {
          index += 1;
        } else {
          quote = "";
        }
      }
      text += "_";
    } else if (
      character === "#" &&
      (index === 0 || /\s/.test(line[index - 1]))
    ) {
      comment = true;
      break;
    } else if (
      (character === '"' || character === "'") &&
      (index === 0 || /[\s:[{,?-]/.test(line[index - 1]))
    ) {
      quote = character;
      text += "_";
    } else {
      text += character;
    }
  }
  return {
    text,
    quote,
    comment,
  };
}

/**
 * 业务作用：沿用跨行字符串的解析上下文，只从配置结构中收集供编辑器补齐的键名。
 * 参数说明：
 * - `value`：当前编辑区原文。
 * - `limit`：当前行的起始位置，或收集文档键名时的原文长度。
 * - `keyScan`：可选的键名集合及正在编辑的行起点，收集时跳过该行、块正文和跨行引号的后续内容。
 * 返回：扫描边界处的引号和块标量状态，供当前行输入辅助复用。
 */
function priorLineContext(value, limit, keyScan) {
  let quote = "";
  let scalar = null;
  let cursor = 0;
  while (cursor < limit) {
    const lineStart = cursor;
    const nextLine = value.indexOf("\n", lineStart);
    const end = nextLine < 0 ? limit : Math.min(nextLine, limit);
    const line = value.slice(lineStart, end);
    cursor = end + 1;
    const width = line.match(/^ */)[0].length;
    if (scalar !== null) {
      if (!line.trim()) {
        continue;
      }
      if (scalar.contentIndent === null && width > scalar.baseIndent) {
        scalar.contentIndent = width;
        continue;
      }
      if (scalar.contentIndent !== null && width >= scalar.contentIndent) {
        continue;
      }
      scalar = null;
    }
    if (keyScan && keyScan.lineStart !== lineStart && !quote) {
      const key = completionKeyPattern.exec(line);
      if (key) {
        keyScan.candidates.add(key[1] ?? key[2] ?? key[3]);
      }
    }
    const context = lineContext(line, quote);
    quote = context.quote;
    const text = context.text.trimEnd();
    const header = text.match(scalarHeaderPattern);
    if (!quote && header) {
      const sequence = /^ *-[ \t]+/.exec(line);
      // 序列标记与映射键可以隔多个空格；正文相对于实际键列缩进。
      const baseIndent =
        sequence && /:\s/.test(text) ? sequence[0].length : width;
      const explicitIndent = header[1].match(/[1-9]/)?.[0];
      scalar = {
        baseIndent,
        contentIndent: explicitIndent
          ? baseIndent + Number(explicitIndent)
          : null,
      };
    }
  }
  return {
    quote,
    scalar,
  };
}

/**
 * 业务作用：按块标量实际正文缩进核对当前行，避免正文触发结构补齐或吞掉其后的同级配置。
 * 参数说明：
 * - `scalar`：当前行开始时的块标量状态；没有待续正文时为 null。
 * - `indent`：当前正文行的缩进列数。
 * 返回：当前缩进仍处于块正文时为true；明确退回配置层级时为false。
 */
function blockContent(scalar, indent) {
  return (
    scalar !== null &&
    (scalar.contentIndent === null
      ? indent > scalar.baseIndent
      : indent >= scalar.contentIndent)
  );
}

/**
 * 业务作用：为明确的编辑按键计算局部文本替换，保持未选中的原文和UTF-16光标位置。
 * 参数说明：
 * - `value`：编辑区当前原文，不执行imports、占位符或环境求值。
 * - `start`：当前选择起点。
 * - `end`：当前选择终点。
 * - `key`：当前编辑按键。
 * - `shift`：是否请求反缩进。
 * 返回：单次局部替换及替换后的选择范围；不适用时为null，交回浏览器原生编辑。
 */
export function yamlEdit(value, start, end, key, shift = false) {
  if (
    !["Tab", "Enter", "Backspace", "]", "}"].includes(key) &&
    !pairs.has(key)
  ) {
    return null;
  }
  const lineStart = start === 0 ? 0 : value.lastIndexOf("\n", start - 1) + 1;
  const prefix = value.slice(lineStart, start);
  const leading = prefix.match(/^ */)[0];
  const before = value[start - 1] ?? "";
  const after = value[end] ?? "";
  const prior = priorLineContext(value, lineStart);
  const context = lineContext(prefix, prior.quote);
  const scalar = blockContent(prior.scalar, leading.length);
  /**
   * 业务作用：把一次局部变更与光标位置组成不可分割的文本编辑计划。
   * 参数说明：
   * - `from`：替换起点。
   * - `to`：替换终点。
   * - `text`：需要写入的纯文本。
   * - `anchor`：写入后的选择起点。
   * - `focus`：写入后的选择终点。
   * 返回：不执行DOM写入的编辑计划。
   */
  const edit = (
    from,
    to,
    text,
    anchor = from + text.length,
    focus = anchor,
  ) => ({
    from,
    to,
    text,
    anchor,
    focus,
  });
  if (key === "Tab") {
    if (start === end && !shift) {
      return edit(start, end, indentation);
    }
    const stop = end > start && value[end - 1] === "\n" ? end - 1 : end;
    const found = value.indexOf("\n", stop);
    const lineEnd = found < 0 ? value.length : found;
    const lines = value.slice(lineStart, lineEnd).split("\n");
    let firstDelta = 0;
    let totalDelta = 0;
    const text = lines
      .map((line, index) => {
        const removed = shift ? Math.min(2, line.match(/^ */)[0].length) : 0;
        const delta = shift ? -removed : 2;
        if (index === 0) {
          firstDelta = delta;
        }
        totalDelta += delta;
        return shift ? line.slice(removed) : indentation + line;
      })
      .join("\n");
    return edit(
      lineStart,
      lineEnd,
      text,
      Math.max(lineStart, start + firstDelta),
      Math.max(lineStart, end + totalDelta),
    );
  }
  if (key === "Enter") {
    if (context.quote || scalar) {
      return edit(start, end, "\n" + leading);
    }
    const text = context.text.trimEnd();
    const sequence = /^ *-[ \t]+/.exec(prefix);
    const found = value.indexOf("\n", end);
    const lineEnd = found < 0 ? value.length : found;
    if (/^ *-\s*$/.test(prefix) && !value.slice(end, lineEnd).trim()) {
      return edit(lineStart, lineEnd, "\n" + leading);
    }
    if (start === end && pairs.get(before) === after && /[\[{]/.test(before)) {
      const inside = "\n" + leading + indentation;
      return edit(start, end, inside + "\n" + leading, start + inside.length);
    }
    const scalarHeader = text.match(scalarHeaderPattern);
    if (/:$/.test(text) || scalarHeader) {
      const width = Number(scalarHeader?.[1].match(/[1-9]/)?.[0] ?? 2);
      const base =
        sequence && /:(?:\s|$)/.test(text)
          ? sequence[0].length
          : leading.length;
      return edit(start, end, "\n" + " ".repeat(base + width));
    }
    const continuation = sequence
      ? /:(?:\s|$)/.test(text)
        ? " ".repeat(sequence[0].length)
        : sequence[0]
      : leading;
    return edit(start, end, "\n" + continuation);
  }
  if (key === "Backspace" && start === end) {
    if (
      pairs.get(before) === after &&
      before &&
      !context.comment &&
      !scalar &&
      (!context.quote || before === context.quote)
    ) {
      return edit(start - 1, end + 1, "");
    }
    if (prefix && /^ +$/.test(prefix)) {
      return edit(
        start - Math.min(prefix.length % 2 || 2, prefix.length),
        end,
        "",
      );
    }
  }
  if (context.comment || scalar) {
    return null;
  }
  const escaped = (prefix.match(/\\+$/)?.[0].length ?? 0) % 2 === 1;
  if (
    start === end &&
    after === key &&
    ((!context.quote && "]}".includes(key)) ||
      (context.quote === key && !escaped))
  ) {
    return edit(start, end, "", end + 1);
  }
  const closing = pairs.get(key);
  if (!closing || context.quote) {
    return null;
  }
  if (start !== end) {
    return edit(
      start,
      end,
      key + value.slice(start, end) + closing,
      start + 1,
      end + 1,
    );
  }
  if (after && !/[\s\]}:,]/.test(after)) {
    return null;
  }
  if ((key === "'" || key === '"') && before && !/[\s:[{,?-]/.test(before)) {
    return null;
  }
  return edit(start, end, key + closing, start + 1);
}

/**
 * 业务作用：只按用户当前文档的键名和YAML基本常量提供显式唯一补齐，不推测业务默认值。
 * 参数说明：
 * - `value`：当前编辑原文。
 * - `position`：当前无选区的光标位置。
 * 返回：匹配光标前后完整文本的唯一候选及局部替换；歧义、引号、注释、块标量或扫描超限时保持原文。
 */
export function yamlCompletion(value, position) {
  const lineStart =
    position === 0 ? 0 : value.lastIndexOf("\n", position - 1) + 1;
  const line = value.slice(lineStart, position);
  const prior = priorLineContext(value, lineStart);
  const context = lineContext(line, prior.quote);
  if (
    context.quote ||
    context.comment ||
    blockContent(prior.scalar, line.match(/^ */)[0].length)
  ) {
    return null;
  }
  const key = line.match(/^ *(?:- )?([A-Za-z_][\w.-]*)$/)?.[1];
  const literal = line.match(/:[ \t]+([a-z]{2,5})$/)?.[1];
  const prefix = key ?? literal;
  if (!prefix) {
    return null;
  }
  // 键名只在完整扫描预算内判断唯一性，不能忽略文档后半段的同前缀声明。
  if (key && value.length > 65536) {
    return null;
  }
  const choices = new Set();
  if (key) {
    priorLineContext(value, value.length, {
      candidates: choices,
      lineStart,
    });
  } else {
    choices.add("true").add("false").add("null");
  }
  const suffix = value.slice(position);
  const to = position + suffix.match(/^[\w.-]*/)[0].length;
  const from = position - prefix.length;
  // 光标右侧未选中的文本也属于当前键名或常量，补齐只能在完整词尾追加字符。
  const token = value.slice(from, to);
  const matches = [...choices].filter((name) => name.startsWith(token));
  if (matches.length !== 1 || (literal && token === matches[0])) {
    return null;
  }
  const hasDelimiter = /^[ \t]*:/.test(value.slice(to));
  const text = matches[0] + (key && !hasDelimiter ? ": " : "");
  return {
    from,
    to,
    text,
    anchor: from + text.length,
    focus: from + text.length,
  };
}

/**
 * 业务作用：以浏览器原生文本事务应用一次辅助编辑，保留撤销记录并只通知现有候选监听器一次。
 * 参数说明：
 * - `editor`：当前获得焦点且允许编辑的textarea。
 * - `change`：已计算的局部替换与选择范围。
 * 返回：支持原生insertText时更新原文与光标；能力缺失或事务拒绝时不消费原生按键。
 */
function applyEdit(editor, change) {
  const document = editor.ownerDocument;
  if (!document.queryCommandSupported?.("insertText")) {
    return false;
  }
  if (
    editor.maxLength >= 0 &&
    editor.value.length - (change.to - change.from) + change.text.length >
      editor.maxLength
  ) {
    // 长度不足时不提交半段补全，仍由原生控件执行自己的录入上限。
    return false;
  }
  const originalStart = editor.selectionStart;
  const originalEnd = editor.selectionEnd;
  if (change.from === change.to && !change.text) {
    editor.setSelectionRange(change.anchor, change.focus);
    return true;
  }
  let notified = false;
  /**
   * 业务作用：识别浏览器是否已通知当前原文变更，避免重复触发候选失效流程。
   * 参数说明: 无。
   * 返回：记录本次事务已经发出input事件。
   */
  const observed = () => {
    notified = true;
  };
  editor.addEventListener("input", observed);
  editor.setSelectionRange(change.from, change.to);
  let applied;
  try {
    // insertText只插入纯文本，并沿浏览器撤销栈提交；不能用innerHTML或整段value赋值替代。
    applied = document.execCommand("insertText", false, change.text);
  } finally {
    editor.removeEventListener("input", observed);
  }
  if (!applied) {
    editor.setSelectionRange(originalStart, originalEnd);
    return false;
  }
  editor.setSelectionRange(change.anchor, change.focus);
  if (!notified) {
    editor.dispatchEvent(new Event("input", { bubbles: true }));
  }
  return true;
}

/**
 * 业务作用：在用户明确采用格式化预览后，以同一原生文本事务替换全文并保留撤销。
 * 参数说明：
 * - `editor`：当前可写的YAML编辑区。
 * - `value`：已校验容量的格式化原文。
 * 返回：事务成功时为true；只读、隐藏或浏览器不支持原生事务时不修改原文。
 */
export function replaceYamlText(editor, value) {
  if (
    editor.disabled ||
    editor.readOnly ||
    editor.ownerDocument.hidden ||
    typeof value !== "string"
  ) {
    return false;
  }
  editor.focus({ preventScroll: true });
  return applyEdit(editor, {
    from: 0,
    to: editor.value.length,
    text: value,
    anchor: 0,
    focus: 0,
  });
}

/**
 * 业务作用：让快捷键和显式按钮使用同一补齐规则，系统占用快捷键时仍可发起补齐。
 * 参数说明：
 * - `editor`：当前可写的 YAML 编辑区。
 * 返回：存在唯一候选且浏览器提交文本事务时返回 true；其它情况保留原文。
 */
export function completeYamlText(editor) {
  if (
    editor.disabled ||
    editor.readOnly ||
    editor.ownerDocument.hidden ||
    editor.selectionStart !== editor.selectionEnd
  ) {
    return false;
  }
  const change = yamlCompletion(editor.value, editor.selectionStart);
  if (!change) {
    return false;
  }
  editor.focus({ preventScroll: true });
  return applyEdit(editor, change);
}

/**
 * 业务作用：为明确的YAML录入框提供两空格编辑辅助，不接管只读、输入法或系统快捷键。
 * 参数说明：
 * - `editor`：需要增强的YAML textarea；JSON、证书和普通多行字段不使用此入口。
 * 返回：原控件；监听器只与控件同寿命，隐藏或撤权后的既有清空及权限门保持生效。
 */
export function yamlEditor(editor) {
  if (enhanced.has(editor)) {
    return editor;
  }
  enhanced.add(editor);
  editor.wrap = "off";
  editor.spellcheck = false;
  editor.autocomplete = "off";
  editor.setAttribute("autocapitalize", "off");
  editor.setAttribute("data-yaml-editor", "true");
  editor.setAttribute("aria-description", yamlEditingHelp);
  editor.title = yamlEditingHelp;
  let composing = false;
  let escapeTab = false;
  editor.addEventListener("compositionstart", () => {
    composing = true;
  });
  editor.addEventListener("compositionend", () => {
    composing = false;
  });
  editor.addEventListener("blur", () => {
    escapeTab = false;
  });
  editor.addEventListener("keydown", (event) => {
    // 组合输入、写资格撤销和已消费的事件不能再次改变候选或光标。
    if (
      editor.disabled ||
      editor.readOnly ||
      event.defaultPrevented ||
      composing ||
      event.isComposing ||
      event.keyCode === 229 ||
      event.altKey ||
      event.metaKey
    ) {
      return;
    }
    if (event.ctrlKey) {
      if (event.key === " " && !event.shiftKey && completeYamlText(editor)) {
        event.preventDefault();
      }
      return;
    }
    if (event.key === "Escape") {
      escapeTab = true;
      return;
    }
    if (event.key === "Tab" && escapeTab) {
      escapeTab = false;
      return;
    }
    escapeTab = false;
    const change = yamlEdit(
      editor.value,
      editor.selectionStart,
      editor.selectionEnd,
      event.key,
      event.shiftKey,
    );
    if (change && applyEdit(editor, change)) {
      event.preventDefault();
    }
  });
  return editor;
}
