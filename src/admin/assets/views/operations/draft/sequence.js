import { element } from "../../../core/dom.js";
import { draftFields } from "./schema.js";
import { draftFieldPanel } from "./fields.js";
import { fieldRow } from "./controls.js";
import { fieldAction } from "./nested.js";
import { tlsDraftLists } from "./tls.js";
import { listenerDraftLists } from "./listener.js";
import { mqttDraftLists } from "./mqtt.js";
import { kafkaDraftLists } from "./kafka.js";
import { upstreamTlsDraftLists } from "./upstream_tls.js";
import { upstreamLocalityDraftLists } from "./upstream_locality.js";
import { routeWafDraftLists } from "./route_waf.js";
import { routeBotDraftLists } from "./route_bot.js";
import { routeBotTrustedDraftLists } from "./route_bot_trusted.js";
import { routeDlpDraftLists } from "./route_dlp.js";
import { routeCsrfDraftLists } from "./route_csrf.js";
import { routeGeoipDraftLists } from "./route_geoip.js";
import { routeCasbinDraftLists } from "./route_casbin.js";
import { routeOpaDraftLists } from "./route_opa.js";
import { routeExternalPluginDraftLists } from "./route_external_plugin.js";
import { routeExtProcDraftLists } from "./route_ext_proc.js";
import { routeGrpcTranscodingDraftLists } from "./route_grpc_transcoding.js";
import { routeGrpcEdgeDraftLists } from "./route_grpc_edge.js";
import { routeWasmDraftLists } from "./route_wasm.js";
import { routeScriptDraftLists } from "./route_script.js";
import { routeBffDraftLists } from "./route_bff.js";
import { routeLlmDraftLists } from "./route_llm.js";
import { routeAiSecurityDraftLists } from "./route_ai_security.js";
import { routeRagDraftLists } from "./route_rag.js";
import { routeAgentDraftLists } from "./route_agent.js";
import { routeAgentToolDraftLists } from "./route_agent_tools.js";
import { routeAgentServerDraftLists } from "./route_agent_servers.js";
import { routeAgentOpenApiDraftLists } from "./route_agent_openapi.js";
import { routeAgentA2aDraftLists } from "./route_agent_a2a.js";
import { routeTrafficQuotaDraftLists } from "./route_traffic_quota.js";
import { routeStaticServeDraftLists } from "./route_static_serve.js";
import { routeCgiDraftLists } from "./route_cgi.js";
import { routeWebdavDraftLists } from "./route_webdav.js";
import {
  routeLayerDraftLists,
  validateLayerMatchDeclaration,
} from "./route_layer.js";
import { routeDubboDraftLists } from "./route_dubbo.js";
import { routeWsFrameDraftLists } from "./route_ws_frame.js";
import { routeForwardProxyDraftLists } from "./route_forward_proxy.js";
import { routeWebTransportDraftLists } from "./route_webtransport.js";
import { routeResponseContractDraftLists } from "./route_response_contract.js";
import {
  routeBodyTransformDraftLists,
  bodyTransformEntryLabel,
} from "./route_body_transform.js";

/**
 * 业务作用：列出常用列表与原文已声明的扩展数组，不把未知值转换成列表。
 * 参数说明：
 * - `kind`：当前对象类别。
 * - `values`：只用于展示的原始字段投影。
 * 返回：有界列表位置、元素控件类型和原始展示值。
 */
function lists(kind, values) {
  const result = draftFields(kind)
    .filter((field) => field[2] === "lines")
    .map(([key, title]) => ({
      path: [key],
      title,
      type: "string",
    }));
  if (kind === "service") {
    result.push({
      path: ["instances"],
      title: "静态上游实例",
      type: "instance",
    });
  }
  if (kind === "stream") {
    result.push({
      path: ["routes"],
      title: "流路由",
      type: "stream_route",
    });
  }
  result.push(...routeExternalPluginDraftLists(kind));
  result.push(...routeWasmDraftLists(kind));
  result.push(...routeScriptDraftLists(kind));
  result.push(...routeBffDraftLists(kind));
  result.push(...routeLlmDraftLists(kind));
  result.push(...routeAiSecurityDraftLists(kind));
  result.push(...routeRagDraftLists(kind));
  result.push(...routeAgentDraftLists(kind));
  result.push(...routeAgentToolDraftLists(kind));
  result.push(...routeAgentServerDraftLists(kind));
  result.push(...routeAgentOpenApiDraftLists(kind, values));
  result.push(...routeAgentA2aDraftLists(kind));
  result.push(...routeTrafficQuotaDraftLists(kind));
  result.push(...routeStaticServeDraftLists(kind));
  result.push(...routeLayerDraftLists(kind));
  result.push(...routeCgiDraftLists(kind));
  result.push(...routeWebdavDraftLists(kind));
  result.push(...routeDubboDraftLists(kind));
  result.push(...routeWsFrameDraftLists(kind));
  result.push(...routeForwardProxyDraftLists(kind));
  result.push(...routeWebTransportDraftLists(kind));
  for (const [key, value] of Object.entries(values)) {
    if (
      key !== "id" &&
      Array.isArray(value) &&
      !result.some((item) => item.path[0] === key)
    ) {
      result.push({
        path: [key],
        title: key,
        type: "json",
      });
    }
  }
  if (kind === "interface_rule") {
    result.push({
      path: ["match", "methods"],
      title: "接口请求方法",
      type: "string",
    });
  }
  if (kind === "proxy") {
    result.push({
      path: ["http3", "capabilities"],
      title: "HTTP/3 协议扩展",
      type: "string",
    });
  }
  result.push(...tlsDraftLists(kind));
  result.push(...listenerDraftLists(kind));
  result.push(...mqttDraftLists(kind));
  result.push(...kafkaDraftLists(kind));
  result.push(...upstreamTlsDraftLists(kind));
  result.push(...upstreamLocalityDraftLists(kind));
  result.push(...routeWafDraftLists(kind));
  result.push(...routeBotDraftLists(kind));
  result.push(...routeBotTrustedDraftLists(kind));
  result.push(...routeDlpDraftLists(kind));
  result.push(...routeCsrfDraftLists(kind));
  result.push(...routeGeoipDraftLists(kind));
  result.push(...routeCasbinDraftLists(kind));
  result.push(...routeOpaDraftLists(kind));
  result.push(...routeExtProcDraftLists(kind));
  result.push(...routeGrpcTranscodingDraftLists(kind));
  result.push(...routeGrpcEdgeDraftLists(kind));
  result.push(...routeResponseContractDraftLists(kind));
  result.push(...routeBodyTransformDraftLists(kind));
  return result.map((item) => {
    let current = values;
    let valid = true;
    for (const key of item.path) {
      if (current === undefined) {
        continue;
      }
      if (!current || Array.isArray(current) || typeof current !== "object") {
        valid = false;
        break;
      }
      current = Object.hasOwn(current, key) ? current[key] : undefined;
    }
    for (const parent of item.parents ?? []) {
      // 内层名单只从当前原文的明确数组位置显示，父项缺席或类型不符时禁止推断另一份目录。
      if (
        !valid ||
        !Array.isArray(current) ||
        !Number.isInteger(parent.index) ||
        parent.index < 0 ||
        parent.index >= current.length
      ) {
        valid = false;
        break;
      }
      current = current[parent.index];
      for (const key of parent.path) {
        if (current === undefined) {
          continue;
        }
        if (!current || Array.isArray(current) || typeof current !== "object") {
          valid = false;
          break;
        }
        current = Object.hasOwn(current, key) ? current[key] : undefined;
      }
    }
    return {
      ...item,
      values: current,
      valid: valid && (current === undefined || Array.isArray(current)),
    };
  });
}

/**
 * 业务作用：为当前对象提供单个列表动作，原始子树留在服务端，索引只绑定当前候选。
 * 参数说明：
 * - `object`：已读取并冻结的对象身份。
 * - `values`：列表和元素的展示投影，不作为未编辑字段输出。
 * - `capacity`：单候选输入容量。
 * - `submit`：通过统一摘要与授权门生成候选的回调。
 * - `changed`：撤销编辑状态变化前的在途结果。
 * 返回：列表编辑面板；每次只提交一个明确动作，不保存或发布活动配置。
 */
export function sequenceEditor(object, values, capacity, submit, changed) {
  const node = element("details", "", "draft-sequence");
  node.append(element("summary", "逐项编辑有序列表"));
  node.append(
    element(
      "p",
      "列表操作单独生成候选；普通字段控件中尚未生成的修改不会随本次提交。位置从 0 开始，移动目标表示最终位置。",
      "subtle",
    ),
  );
  const choices = lists(object.kind, values);
  const list = element("select");
  list.setAttribute("aria-label", "列表字段");
  choices.forEach((item, index) => {
    const option = element(
      "option",
      item.title + " · " + item.path.join(" → "),
    );
    option.value = String(index);
    list.append(option);
  });
  const item = element("select");
  item.setAttribute("aria-label", "列表元素位置");
  const operation = element("select");
  operation.setAttribute("aria-label", "列表操作");
  for (const [value, title] of [
    ["keep", "选择列表操作"],
    ["patch", "编辑对象元素字段"],
    ["insert", "插入新元素"],
    ["set", "替换整个元素"],
    ["remove", "删除元素"],
    ["move", "移动元素"],
  ]) {
    const option = element("option", title);
    option.value = value;
    operation.append(option);
  }
  const position = element("input");
  position.type = "number";
  position.min = "0";
  position.step = "1";
  position.setAttribute("aria-label", "插入或移动目标位置");
  const body = element("div");
  const confirm = element("input");
  confirm.type = "checkbox";
  confirm.setAttribute("aria-label", "确认删除列表元素");
  const confirmation = element("label", "确认删除当前候选中的这个元素");
  confirmation.append(confirm);
  const button = element("button", "生成列表编辑后的候选");
  button.type = "button";
  const note = element("p", "", "subtle");
  note.setAttribute("role", "status");
  for (const [title, input] of [
    ["列表字段", list],
    ["现有元素位置", item],
    ["列表操作", operation],
    ["插入或移动后的目标位置", position],
  ]) {
    const label = element("label", title);
    label.append(input);
    node.append(label);
  }
  node.append(body, confirmation, button, note);
  let fields = null;
  let value = null;

  /**
   * 业务作用：切换操作或元素后重新建立显式输入，不能沿用另一元素的待写字段。
   * 参数说明: 无。
   * 返回：更新控件及删除确认；非列表或超限目标不开放动作。
   */
  function show() {
    changed();
    fields = value = null;
    body.replaceChildren();
    confirm.checked = false;
    confirmation.hidden = operation.value !== "remove";
    position.disabled = !["insert", "move"].includes(operation.value);
    const selected = choices[Number(list.value)];
    const entries = selected?.values ?? [];
    button.disabled =
      !selected?.valid || entries.length > 4096 || operation.value === "keep";
    note.textContent = !selected?.valid
      ? "当前位置不是列表或父字段类型不符，不能隐式覆盖。"
      : entries.length > 4096
        ? "列表超过逐项编辑容量，请使用原始 YAML。"
        : "仅明确输入的新值会写入候选，未编辑元素保持原声明。";
    if (button.disabled) {
      return;
    }
    const current = entries[Number(item.value)];
    if (operation.value === "patch") {
      if (!current || Array.isArray(current) || typeof current !== "object") {
        button.disabled = true;
        note.textContent = "当前元素不是对象，不能编辑子字段。";
        return;
      }
      fields = draftFieldPanel(selected.type, current, capacity);
      body.append(fields.node);
    } else if (["insert", "set"].includes(operation.value)) {
      if (
        [
          "instance",
          "tls_identity",
          "stream_route",
          "kafka_broker",
          "locality_target",
          "waf_exclusion",
          "bot_trusted",
          "dlp_exclusion",
          "schema_registry_document",
          "body_transform_operation",
          "body_transform_extract",
          "body_transform_emit",
          "external_plugin",
          "wasm_plugin",
          "script_plugin",
          "bff_target",
          "llm_model",
          "llm_guardrail",
          "rag_source",
          "mcp_tool",
          "mcp_server",
          "mcp_openapi_catalog",
          "mcp_openapi_operation",
          "traffic_quota_window",
          "layer_match",
          "ws_message_plugin",
        ].includes(selected.type)
      ) {
        // 稳定身份绑定路由、插件、聚合目标、模型、内容规则、检索来源和工具，只在新增或整值替换时开放声明。
        const type =
          selected.type === "stream_route"
            ? "stream_route_new"
            : selected.type === "external_plugin"
              ? "external_plugin_new"
              : selected.type === "wasm_plugin"
                ? "wasm_plugin_new"
                : selected.type === "script_plugin"
                  ? "script_plugin_new"
                  : selected.type === "bff_target"
                    ? "bff_target_new"
                    : selected.type === "llm_model"
                      ? "llm_model_new"
                      : selected.type === "llm_guardrail"
                        ? "llm_guardrail_new"
                        : selected.type === "rag_source"
                          ? "rag_source_new"
                          : selected.type === "mcp_tool"
                            ? "mcp_tool_new"
                            : selected.type === "mcp_server"
                              ? "mcp_server_new"
                              : selected.type === "mcp_openapi_operation"
                                ? "mcp_openapi_operation_new"
                                : selected.type;
        fields = draftFieldPanel(type, {}, capacity);
        body.append(
          element(
            "p",
            "新对象仅包含本次明确设置的字段；替换会移除旧元素的其它字段。",
            "subtle",
          ),
          fields.node,
        );
      } else {
        value = fieldRow(
          "列表元素",
          "明确的新元素值",
          selected.type,
          operation.value === "set" ? current : undefined,
          capacity,
        );
        body.append(value.node);
      }
    }
  }

  /**
   * 业务作用：按选中列表的原始顺序建立下标目录，不复制或提交其完整元素。
   * 参数说明: 无。
   * 返回：有界元素选择器与未选择动作，缺失列表只允许后续首次插入。
   */
  function selectList() {
    item.replaceChildren();
    const selected = choices[Number(list.value)];
    const entries = selected?.valid ? (selected.values ?? []) : [];
    entries.slice(0, 4096).forEach((entry, index) => {
      const label =
        typeof entry === "string"
          ? entry
          : selected?.type?.startsWith("body_transform_")
            ? bodyTransformEntryLabel(entry)
            : selected?.type === "mcp_openapi_catalog" &&
                typeof entry?.file === "string"
              ? entry.file
              : ["bot_trusted", "mcp_tool", "mcp_openapi_operation"].includes(
                    selected?.type,
                  ) && typeof entry?.name === "string"
                ? entry.name
                : selected?.type === "schema_registry_document" &&
                    typeof entry?.url === "string"
                  ? entry.url
                  : typeof entry?.id === "string"
                    ? entry.id
                    : typeof entry?.uri === "string"
                      ? entry.uri
                      : Array.isArray(entry?.server_names) &&
                          entry.server_names.every(
                            (name) => typeof name === "string",
                          )
                        ? entry.server_names.join(", ")
                        : "元素";
      const option = element("option", index + " · " + label.slice(0, 160));
      option.value = String(index);
      item.append(option);
    });
    operation.value = "keep";
    position.value = String(entries.length);
    show();
  }

  /**
   * 业务作用：解析用户明确填写的有限列表位置，空串不能被当成零下标。
   * 参数说明：
   * - `text`：下标控件原始字符串。
   * 返回：0至4096的整数；其它输入拒绝生成动作。
   */
  function index(text) {
    if (!/^(0|[1-9][0-9]*)$/.test(text) || Number(text) > 4096) {
      throw new Error("请填写有效的列表位置。");
    }
    return Number(text);
  }

  button.addEventListener("click", () => {
    try {
      if (button.disabled) {
        return;
      }
      const selected = choices[index(list.value)];
      const op = operation.value;
      let edit;
      if (op === "move") {
        edit = {
          op,
          from: index(item.value),
          to: index(position.value),
        };
      } else if (op === "remove") {
        if (!confirm.checked) {
          throw new Error("请先确认删除当前元素。");
        }
        edit = {
          op,
          index: index(item.value),
        };
      } else if (op === "patch") {
        const action = fieldAction(object, fields.read(), false);
        const edits =
          action.type === "patch_nested"
            ? action.edits
            : [
                ...Object.entries(action.fields).map(([key, value]) => ({
                  op: "set",
                  path: [key],
                  value,
                })),
                ...action.remove.map((key) => ({
                  op: "remove",
                  path: [key],
                })),
              ];
        edit = {
          op,
          index: index(item.value),
          edits,
        };
      } else if (op === "insert" || op === "set") {
        const action = fields
          ? fieldAction(object, fields.read(), true)
          : value.read();
        if (!action || action.remove) {
          throw new Error("请明确设置新元素值。");
        }
        // 新条件不能继承相邻项的匹配权，完整变体声明通过后才交给原目标复验可信事实和可达性。
        if (selected.type === "layer_match") {
          validateLayerMatchDeclaration(action.fields);
        }
        // 新窗口必须由操作者明确额度与长度，不能把相邻窗口的容量当作默认授权。
        if (
          selected.type === "traffic_quota_window" &&
          ["limit", "window_ms"].some(
            (key) => typeof action.fields?.[key] !== "number",
          )
        ) {
          throw new Error(
            "新增或替换额度窗口必须明确填写 limit 与 window_ms。",
          );
        }
        // 转换目录与操作都没有可继承的授权，必须显式提供完整原生声明后再进入目标预检。
        if (selected.type === "mcp_openapi_catalog") {
          if (
            typeof action.fields?.file !== "string" ||
            !action.fields.file.length ||
            !Object.hasOwn(action.fields, "target") ||
            !Object.hasOwn(action.fields, "operations")
          ) {
            throw new Error(
              "新增或替换 OpenAPI 目录必须明确填写非空 file、完整 target 和 operations。",
            );
          }
        }
        if (selected.type === "mcp_openapi_operation") {
          if (
            typeof action.fields?.operation_id !== "string" ||
            typeof action.fields?.name !== "string" ||
            !/^[A-Za-z0-9_.-]{1,64}$/.test(action.fields.name)
          ) {
            throw new Error(
              "新增或替换操作必须明确填写 operation_id 与1–64字节工具名称。",
            );
          }
          for (const key of [
            "discovery",
            "invocation",
            "side_effect",
            "deadline_ms",
            "max_calls_per_session",
            "max_request_bytes",
            "max_response_bytes",
          ]) {
            if (!Object.hasOwn(action.fields, key)) {
              throw new Error(`新增或替换操作必须明确填写 ${key}。`);
            }
          }
        }
        // 新服务器必须显式指定身份和完整目标，不能把其它服务器的地址或凭据当作默认声明。
        if (selected.type === "mcp_server") {
          if (
            typeof action.fields?.id !== "string" ||
            !/^[A-Za-z0-9_.-]{1,64}$/.test(action.fields.id) ||
            !Object.hasOwn(action.fields, "target")
          ) {
            throw new Error(
              "新增或替换 MCP 服务器必须明确填写1–64字节的稳定 id 和完整 target。",
            );
          }
        }
        // 新工具必须由操作者完整声明授权和后端，不能从相邻工具继承权限、schema 或凭据。
        if (selected.type === "mcp_tool") {
          if (
            typeof action.fields?.name !== "string" ||
            !/^[A-Za-z0-9_.-]{1,64}$/.test(action.fields.name)
          ) {
            throw new Error("新增或替换工具必须明确填写1–64字节的稳定名称。");
          }
          for (const key of [
            "description",
            "input_schema",
            "discovery",
            "invocation",
            "side_effect",
            "deadline_ms",
            "max_calls_per_session",
            "max_request_bytes",
            "max_response_bytes",
            "backend",
          ]) {
            if (!Object.hasOwn(action.fields, key)) {
              throw new Error(`新增或替换工具必须明确填写 ${key}。`);
            }
          }
        }
        // 新消息插件没有可继承的类型，必须明确选择受支持的执行语义，不能靠其它字段猜测权限。
        if (
          selected.type === "ws_message_plugin" &&
          !["acl", "json_schema", "redact", "rate_limit", "external"].includes(
            action.fields?.type,
          )
        ) {
          throw new Error(
            "新增或替换 WebSocket 消息插件必须明确选择有效的 type。",
          );
        }
        if (
          selected.type === "stream_route" &&
          (typeof action.fields?.id !== "string" || !action.fields.id.trim())
        ) {
          throw new Error("新流路由必须明确填写非空的稳定身份 id。");
        }
        if (
          selected.type === "external_plugin" &&
          (typeof action.fields?.id !== "string" || !action.fields.id.trim())
        ) {
          throw new Error("新增或替换外部插件必须明确填写非空的稳定身份 id。");
        }
        if (
          selected.type === "wasm_plugin" &&
          (typeof action.fields?.id !== "string" ||
            action.fields.id.length === 0)
        ) {
          throw new Error(
            "新增或替换 Proxy-Wasm 插件必须明确填写非空的稳定身份 id。",
          );
        }
        if (
          selected.type === "script_plugin" &&
          (typeof action.fields?.id !== "string" ||
            !/^[A-Za-z0-9_.-]{1,128}$/.test(action.fields.id))
        ) {
          throw new Error(
            "新增或替换 Lua 脚本必须明确填写1–128字节的稳定 id，仅允许字母、数字、-、_、.。",
          );
        }
        if (
          selected.type === "bff_target" &&
          (typeof action.fields?.id !== "string" ||
            !/^[A-Za-z0-9_.-]{1,64}$/.test(action.fields.id) ||
            action.fields.id === "_errors")
        ) {
          throw new Error(
            "新增或替换 BFF 目标必须明确填写1–64字节的稳定 id，仅允许字母、数字、-、_、.，不得为 _errors。",
          );
        }
        // 新模型必须由操作者明确声明身份和真实后端，不能从其它模型或客户端请求猜测授权目标。
        if (selected.type === "llm_model") {
          if (
            typeof action.fields?.id !== "string" ||
            !/^[A-Za-z0-9_.-]{1,64}$/.test(action.fields.id)
          ) {
            throw new Error(
              "新增或替换模型必须明确填写1–64字节的稳定 id，仅允许字母、数字、.、_、-。",
            );
          }
          for (const key of ["provider", "uri", "model"]) {
            if (
              typeof action.fields[key] !== "string" ||
              !action.fields[key].trim()
            ) {
              throw new Error(`新增或替换模型必须明确填写非空的 ${key}。`);
            }
          }
        }
        // 分类、方向与唯一匹配来源必须由操作者明确选择，不能从旧规则猜测新增的阻断范围。
        if (selected.type === "llm_guardrail") {
          if (
            typeof action.fields?.id !== "string" ||
            !/^[A-Za-z0-9_.-]{1,64}$/.test(action.fields.id)
          ) {
            throw new Error(
              "新增或替换内容规则必须明确填写1–64字节的稳定 id，仅允许字母、数字、.、_、-。",
            );
          }
          if (
            typeof action.fields.category !== "string" ||
            !action.fields.category.trim() ||
            !Array.isArray(action.fields.directions) ||
            !action.fields.directions.length
          ) {
            throw new Error(
              "新增或替换内容规则必须明确填写分类与非空方向名单。",
            );
          }
          if (
            ["contains", "regex", "detector"].filter((key) =>
              Object.hasOwn(action.fields, key),
            ).length !== 1
          ) {
            throw new Error("新增或替换内容规则必须明确选择恰好一种匹配来源。");
          }
        }
        // 新来源没有可继承的调用权或凭据，必须明确提供完整原生声明后交给原目标预检。
        if (selected.type === "rag_source") {
          if (
            typeof action.fields?.id !== "string" ||
            !/^[A-Za-z0-9_.-]{1,64}$/.test(action.fields.id)
          ) {
            throw new Error(
              "新增或替换检索来源须明确填写1–64字节的稳定安全 ASCII id。",
            );
          }
          for (const key of [
            "target",
            "invocation",
            "timeout_ms",
            "max_documents",
            "max_response_bytes",
            "allowed_sources",
            "allowed_citation_origins",
            "fail_mode",
          ]) {
            if (!Object.hasOwn(action.fields, key)) {
              throw new Error(`新增或替换检索来源必须明确填写 ${key}。`);
            }
          }
        }
        edit = {
          op,
          index: index(op === "insert" ? position.value : item.value),
          value: fields ? action.fields : action.value,
        };
      } else {
        throw new Error("请先选择列表操作。");
      }
      // 内层动作携带父目录的原始下标，未选择的目录和操作不从浏览器投影重新序列化。
      for (const parent of [...(selected.parents ?? [])].reverse()) {
        edit = { op: "sequence", index: parent.index, path: parent.path, edit };
      }
      submit({
        type: "patch_sequence",
        object,
        path: selected.path,
        edit,
      });
    } catch (error) {
      note.textContent = error.message;
    }
  });
  list.addEventListener("change", selectList);
  item.addEventListener("change", show);
  operation.addEventListener("change", show);
  node.addEventListener("input", changed);
  node.addEventListener("change", changed);
  selectList();
  return node;
}
