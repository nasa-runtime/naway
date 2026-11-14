import {
  identitySecurityFields,
  identityConsumerGroupEditor,
} from "./identity_security.js";

/**
 * 业务作用：独立编辑治理身份与保留声明，不从客户端头或展示值生成授权。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供原生六项身份字段和显式保留策略，必需值由原目标预检复验。
 */
export function routeAiSecurityFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["llm"],
      "AI 治理完整声明（需 ai-governance）",
      [
        [
          "governance",
          "完整治理（移除同时关闭固定模板、RAG 与输出裁决，保留模型及路由认证）",
          "json",
        ],
      ],
    ],
    [
      ["llm", "governance"],
      "AI 治理身份与保留",
      [
        [
          "security",
          "完整安全身份（替换整个身份声明；治理存在时不可缺失）",
          "json",
        ],
        [
          "retention",
          "显式保留策略（仅 request_only；不持久化本次治理正文）",
          "string",
        ],
      ],
    ],
    [
      ["llm", "governance", "security"],
      "AI 可信租户与身份来源",
      identitySecurityFields,
    ],
  ];
}

/**
 * 业务作用：让允许来源按原候选位置修改，不把名单显示顺序当作额外授权。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供 Origin 字符串列表，不生成任何默认来源。
 */
export function routeAiSecurityDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["llm", "governance", "security", "allowed_origins"],
      title: "AI 治理允许 Origin",
      type: "string",
    },
  ];
}

/**
 * 业务作用：为单个已认证 consumer 编辑固定组名单，保留其它 consumer 和治理原声明。
 * 参数说明：
 * - `object`：当前已读取的完整路由身份。
 * - `values`：只用于展示和选择的原始路由投影。
 * - `capacity`：单候选输入字节容量。
 * - `submit`：沿原选择代、摘要与权限门提交草稿动作的回调。
 * - `changed`：输入变化时撤销旧在途结果的回调。
 * 返回：有界逐键编辑面板；新增不继承组，删除须确认，不创建或认证 consumer。
 */
export function aiConsumerGroupEditor(
  object,
  values,
  capacity,
  submit,
  changed,
) {
  return identityConsumerGroupEditor(
    "ai",
    object,
    values,
    capacity,
    submit,
    changed,
  );
}
