/**
 * 业务作用：显式编辑内嵌授权模型、参数来源和故障边界，不把客户端属性当成已认证主体。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供七项原生字段；未编辑的身份要求、参数和故障策略保持原声明。
 */
export function routeCasbinFieldGroups(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    [
      ["casbin_authorization"],
      "内嵌 Casbin 授权",
      [
        ["model_file", "受信本地 PERM model 文件", "string"],
        ["policy_file", "受信本地 CSV policy 文件", "string"],
        ["arguments", "与 model r 顺序一致的参数（每行一项，1–16项）", "lines"],
        ["require_identity", "要求已通过认证链的 consumer", "boolean"],
        ["max_argument_bytes", "单参数上限（1–65536 UTF-8字节）", "number"],
        [
          "max_input_bytes",
          "参数总上限（不低于单参数上限，最多262144字节）",
          "number",
        ],
        ["fail_open", "仅内部求值异常时放行", "boolean"],
      ],
    ],
  ];
}

/**
 * 业务作用：按原始次序逐项编辑授权参数，防止展示时重建其它策略或改变参数位置。
 * 参数说明：
 * - `kind`：当前草稿对象类别。
 * 返回：仅路由提供参数字符串列表；移动位置表示最终 model 输入位置。
 */
export function routeCasbinDraftLists(kind) {
  if (kind !== "route") {
    return [];
  }
  return [
    {
      path: ["casbin_authorization", "arguments"],
      title: "Casbin 有序授权参数",
      type: "string",
    },
  ];
}
