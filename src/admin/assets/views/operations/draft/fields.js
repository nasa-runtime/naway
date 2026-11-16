import { element } from "../../../core/dom.js";
import { draftFields } from "./schema.js";
import { fieldRow } from "./controls.js";
import { nestedFields } from "./nested.js";

/**
 * 业务作用：保护字段编辑中的目录身份与独立管理容器，避免绕过对象边界改变授权。
 * 参数说明：
 * - `kind`：当前元素的草稿类别。
 * - `name`：原始字段名。
 * 返回：身份或单例子容器受保护时为 true；其它字段继续由其独立定义开放。
 */
export function identityField(kind, name) {
  return (
    name === "id" ||
    (kind === "ip_policy" &&
      !["schema_version", "acl", "client_ip_policy"].includes(name)) ||
    (kind === "portal_settings" &&
      ["catalogs", "products", "management", "key_applications"].includes(
        name,
      )) ||
    (kind === "portal_management" &&
      ["teams", "applications", "bindings"].includes(name)) ||
    (kind === "portal_binding" && ["proxy", "route"].includes(name)) ||
    (name === "name" &&
      [
        "credential",
        "secret_provider",
        "mcp_tool",
        "mcp_openapi_operation",
      ].includes(kind)) ||
    (name === "operation_id" && kind === "mcp_openapi_operation")
  );
}

/**
 * 业务作用：按对象类别生成常用字段及完整扩展字段编辑，修改仅指向用户选择的原始声明。
 * 参数说明：
 * - `kind`：对象类别。
 * - `values`：服务端无求值读取的原始对象。
 * - `capacity`：单候选字节上限。
 * 返回：只读出显式字段 patch 的控件组，不发送网络请求或保存草稿。
 */
export function draftFieldPanel(kind, values, capacity) {
  const node = element("div", "", "draft-fields");
  const rows = new Map();
  const known = draftFields(kind);
  if (kind === "ip_policy") {
    node.append(
      element(
        "p",
        "全局 ACL 同时约束 HTTP、TCP 和 UDP；空 whitelist 拒绝全部业务来源，Admin 使用独立权限。显式 ACL 或客户端来源声明要求 schema_version 为 2，旧制品会拒绝该候选，须核对全部原目标。forwarded 模式只读取选定的一个头，并要求直连前置在对应入口的 trusted_proxies 中；可信链缺失、格式不合法或超限时拒绝请求。移除 client_ip_policy 会恢复既有 XFF 兼容行为；关闭来源头解析请显式选择 socket_addr。这里只生成声明，不授予前置信任或发布配置，全部修改仍须原目标完整预检。",
        "subtle",
      ),
    );
  }
  if (kind === "portal_key_applications") {
    node.append(
      element(
        "p",
        "此策略只控制 pending 申请，成功受理不会签发 key 或赋予业务权限。申请使用独立 Bearer，管理员 Token 与 SSO 角色不能替代；这里只编辑 SecretSource 原文，不读取材料。关闭时须明确移除或清空凭据声明。集合换名不会删除旧申请，满额仍允许同一目录与申请人标识的幂等覆盖；预算和引用须完整预检。此入口只编辑既有配置，不能新建或删除整个申请策略，也不直接编辑待审批记录。",
        "subtle",
      ),
    );
  }
  if (kind === "portal_catalog") {
    node.append(
      element(
        "p",
        "此目录将 OpenAPI operation 物化为真实路由；改变文件、入口、上游或 filters 会改变实际部署与访问策略。文件与上游须明确声明，已有目录身份受保护。filters 保留完整原生 DSL；usage_plan 可完整 JSON 替换，也可独立编辑默认套餐与可信身份要求，不从其它目录继承认证或套餐。这里只生成声明，不读取文件或秘密、不启用门户；文件字节、合同、入口、重复路由及操作数量仍须原目标完整预检与审批执行。",
        "subtle",
      ),
    );
  }
  if (kind === "portal_settings") {
    node.append(
      element(
        "p",
        "这里只编辑既有门户的总开关、公开读面和文档上限。关闭门户要求目录与产品为空、无管理声明、申请入口关闭且不公开目录；这些关系仍须完整预检。目录、产品、身份管理和申请配置各自独立维护，此入口不能新建或移除整个门户。公开目录不授予团队角色、应用订阅或产品业务权限。文档上限按原始文件实际字节校验。",
        "subtle",
      ),
    );
  }
  if (kind === "portal_management") {
    node.append(
      element(
        "p",
        "这里只编辑既有管理声明的身份、SSO、origin 与会话设置。SSO 可整值替换或原位编辑；OIDC 与 SAML 分组只调整明确参数，不读取秘密或授予默认角色。身份域变更会改变主体归属。会话预算与登录策略及 token 剩余有效期共同收紧，不能提高更小的上限。团队、应用和绑定须分别维护；此入口不能新建、删除管理声明或开启门户。",
        "subtle",
      ),
    );
  }
  if (kind === "product") {
    node.append(
      element(
        "p",
        "产品身份独立于路由。版本清单为完整替换，可能改变公开可见性、订阅和文档；本编辑不会启用门户，所有引用和合同仍须原目标完整预检。",
        "subtle",
      ),
    );
  }
  if (kind === "portal_team") {
    node.append(
      element(
        "p",
        "团队身份独立于产品与路由。下方 JSON 角色映射为完整替换，也可用逐项界面维护单个成员，可能授予或撤销团队权限；这里只编辑声明，不建立 SSO、不开启门户，也不迁移应用。角色声明仍须原目标完整预检，访问时只信任已验证的 SSO 身份。",
        "subtle",
      ),
    );
  }
  if (kind === "portal_application") {
    node.append(
      element(
        "p",
        "应用身份独立于团队与路由。更换团队、消费者、套餐或状态会改变授权归属；回调、订阅与凭据清单为完整 JSON 替换，遗漏的旧项将被移除。这里只编辑声明，不建立 SSO、不生成明文凭据，也不自动订阅产品；全部引用、权限、配额与摘要仍须原目标完整预检。",
        "subtle",
      ),
    );
  }
  if (kind === "portal_binding") {
    node.append(
      element(
        "p",
        "绑定身份由所属入口与路由共同确定，合同必须明确产品、版本和操作。绑定按活动订阅凭据生成应用鉴权、套餐和计量归属；解除后路由采用自身声明的认证，请同时明确路由访问策略。这里只编辑声明，不建立路由、应用或订阅，全部引用与权限仍须原目标完整预检。",
        "subtle",
      ),
    );
  }
  const remaining = Object.keys(values).filter(
    (key) => !identityField(kind, key) && !known.some(([name]) => name === key),
  );
  if (known.length + remaining.length > 128) {
    throw new Error("此对象字段过多，请在原始 YAML 中编辑。");
  }
  for (const [name, title, type] of known) {
    const row = fieldRow(
      name,
      title,
      type,
      Object.hasOwn(values, name) ? values[name] : undefined,
      capacity,
      kind !== "consumer_binding",
    );
    rows.set(name, row);
    node.append(row.node);
  }
  const nested = nestedFields(kind, values, capacity);
  node.append(nested.node);
  const complex = element("details");
  complex.append(element("summary", "其它声明与复杂策略"));
  for (const name of remaining) {
    const value = values[name];
    const type = ["string", "boolean", "number"].includes(typeof value)
      ? typeof value
      : "json";
    const row = fieldRow(name, name, type, value, capacity);
    rows.set(name, row);
    complex.append(row.node);
  }
  const addName = element("input");
  addName.maxLength = 128;
  addName.autocomplete = "off";
  addName.setAttribute("aria-label", "新增字段名");
  const add = element("button", "添加字段控件");
  add.type = "button";
  const note = element(
    "p",
    "新增字段使用 JSON 值；现有未知字段会保持原声明。",
    "subtle",
  );
  add.addEventListener("click", () => {
    const name = addName.value;
    if (
      !name ||
      identityField(kind, name) ||
      rows.has(name) ||
      /[\x00-\x1f\x7f]/.test(name) ||
      new TextEncoder().encode(name).length > 128 ||
      rows.size >= 128
    ) {
      note.textContent = "字段名为空、重复、受保护或超过容量。";
      return;
    }
    const row = fieldRow(name, name, "json", undefined, capacity);
    rows.set(name, row);
    complex.append(row.node);
    complex.open = true;
    addName.value = "";
    note.textContent = "已添加控件；选择设置值后才会修改候选。";
  });
  const addLabel = element("label", "新增字段名");
  addLabel.append(addName);
  complex.append(addLabel, add, note);
  if (kind === "consumer_binding") {
    node.append(
      element(
        "p",
        "解除显式套餐绑定请删除此对象；组成员及身份凭据不受影响。",
        "subtle",
      ),
    );
  } else {
    node.append(complex);
  }

  /**
   * 业务作用：收集明确编辑的键，不从展示值重建整个对象。
   * 参数说明: 无。
   * 返回：独立设置和移除列表，至少一项显式动作才允许生成候选。
   */
  function read() {
    const fields = Object.create(null);
    const remove = [];
    for (const row of rows.values()) {
      const action = row.read();
      if (action?.remove) {
        remove.push(action.name);
      } else if (action) {
        fields[action.name] = action.value;
      }
    }
    const edits = nested.read();
    for (const edit of edits) {
      if (
        Object.hasOwn(fields, edit.path[0]) ||
        remove.includes(edit.path[0])
      ) {
        throw new Error(
          "同一字段不能同时整值修改和编辑子项，请只选择一种方式。",
        );
      }
    }
    if (!remove.length && !Object.keys(fields).length && !edits.length) {
      throw new Error("请先为需要修改的字段选择设置值或移除声明。");
    }
    if (edits.length) {
      return {
        fields,

        remove,

        edits,
      };
    }
    return {
      fields,

      remove,
    };
  }
  return {
    node,

    read,
  };
}
