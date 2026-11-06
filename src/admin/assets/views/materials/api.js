import { checkedRecord, hex } from "./common.js";
import { checkedImpact } from "./impact.js";
import { checkedExecution } from "./execution.js";

/**
 * 业务作用：把一次页面请求链固定到唯一集群与范围，接口之间不能混用响应作用域或执行权限。
 * 参数说明：
 * - `send`：已经绑定当前页面代与取消信号的同源请求函数。
 * - `cluster`：当前共享材料集群。
 * - `workspace`：本次冻结工作区，空文本代表平台。
 * 返回：只使用固定材料接口的客户端，不接受任意地址、文件路径或替代主体。
 */
export function materialApi(send, cluster, workspace) {
  const scope = workspace ? `workspace.${workspace}` : "platform";

  /**
   * 业务作用：从固定材料资源和唯一范围构造同源路径，幂等键只放请求头。
   * 参数说明：
   * - `suffix`：代码确定的入口后缀或已经验证的原提案身份。
   * - `query`：有限列表的游标参数。
   * 返回：唯一材料路径；平台不附加空workspace参数。
   */
  function path(suffix = "", query = {}) {
    const params = new URLSearchParams(query);
    if (workspace) {
      params.set("workspace", workspace);
    }
    const tail = params.toString();
    return `/api/certificate-proposals${suffix}${tail ? `?${tail}` : ""}`;
  }

  /**
   * 业务作用：拒绝把另一集群或范围的上下文用于当前表单授权。
   * 参数说明：
   * - `value`：含显式集群和范围字段的响应。
   * 返回：当前同域对象，字段不一致时整份拒绝。
   */
  function scoped(value) {
    if (value?.cluster_id !== cluster || value.scope !== scope) {
      throw new Error("响应所属集群或范围已变化，请重新核对入口。");
    }
    return value;
  }

  /**
   * 业务作用：分别读取材料、完整影响和执行能力，功能缺席不会借用配置提案权限。
   * 参数说明: 无。
   * 返回：材料真实权限及可选独立能力；材料读权失败终止整个读取。
   */
  async function capabilities() {
    const material = scoped((await send(path("/context"))).data);
    if (
      ["read", "write", "review"].some(
        (name) => typeof material.access?.[name] !== "boolean",
      ) ||
      typeof material.accept_proposals !== "boolean" ||
      material.access.read !== true
    ) {
      throw new Error("材料上下文没有返回完整的当前权限。");
    }
    /**
     * 业务作用：独立功能缺席或不可用时关闭对应动作，材料普通读取保持原权限边界。
     * 参数说明：
     * - `suffix`：代码指定的影响或执行上下文入口。
     * 返回：同范围能力，或明确不可用；越权和响应范围错误继续上抛。
     */
    const optional = async (suffix) => {
      try {
        return scoped((await send(path(suffix))).data);
      } catch (error) {
        if ([404, 503].includes(error.status)) {
          return null;
        }
        throw error;
      }
    };
    const impact = await optional("/impact-context");
    const execution = await optional("/execution-context");
    if (
      (impact &&
        (typeof impact.accept_proposals !== "boolean" ||
          ["read", "write", "review"].some(
            (name) => typeof impact.access?.[name] !== "boolean",
          ))) ||
      (execution &&
        [
          "execution_supported",
          "execution_enabled",
          "execution_ready",
          "can_request_execution",
        ].some((name) => typeof execution[name] !== "boolean"))
    ) {
      throw new Error("独立影响或执行上下文没有返回明确的能力状态。");
    }
    return {
      material,
      impact,
      execution,
    };
  }

  /**
   * 业务作用：以小页读取材料目录，并逐记录验证全部原目标的集群与范围。
   * 参数说明：
   * - `after`：上次服务端返回的规范游标。
   * 返回：完整分页与下一游标；异常记录或重复身份使整页失效。
   */
  async function list(after = "") {
    const query = { limit: "16" };
    if (after) {
      if (!hex(after, 32)) {
        throw new Error("材料分页游标不合法。");
      }
      query.after = after;
    }
    const data = (await send(path("", query))).data;
    if (
      !Array.isArray(data?.proposals) ||
      data.proposals.length > 16 ||
      (data.next_after !== null && !hex(data.next_after, 32))
    ) {
      throw new Error("材料目录响应不符合分页约定。");
    }
    const seen = new Set();
    for (const value of data.proposals) {
      checkedRecord(value, cluster, scope);
      if (seen.has(value.id)) {
        throw new Error("材料目录出现重复原身份。");
      }
      seen.add(value.id);
    }
    if (
      data.next_after !== null &&
      data.proposals.at(-1)?.id !== data.next_after
    ) {
      throw new Error("材料分页游标与完整页末记录不一致。");
    }
    return data;
  }

  /**
   * 业务作用：按唯一原材料身份读取完整记录，不把列表元数据当作最新审阅事实。
   * 参数说明：
   * - `id`：规范原提案身份。
   * 返回：同一原记录；身份或范围不符拒绝。
   */
  async function record(id) {
    if (!hex(id, 32)) {
      throw new Error("原材料提案身份不合法。");
    }
    const value = checkedRecord(
      (await send(path(`/${id}`))).data.proposal,
      cluster,
      scope,
    );
    if (value.id !== id) {
      throw new Error("响应替换了原材料提案身份。");
    }
    return value;
  }

  /**
   * 业务作用：读取或按原请求恢复唯一完整影响，未找到仍保留登记结果未知的可能。
   * 参数说明：
   * - `proposal`：当前完整原材料记录。
   * - `entry`：可选原登记键、代际与主体；缺席时按父材料查询。
   * 返回：完整影响或本次未找到，不自动发起新登记。
   */
  async function impact(proposal, entry = null) {
    try {
      const options = entry
        ? {
            headers: {
              "Idempotency-Key": entry.key,

              "Naway-Admission-Epoch": entry.epoch,
            },
          }
        : {};
      const data = (
        await send(
          path(`/${proposal.id}/impact${entry ? "/resolve" : ""}`),
          options,
        )
      ).data;
      const value = checkedImpact(data.impact, proposal, cluster, scope);
      if (
        entry &&
        (value.admission_epoch !== entry.epoch ||
          value.creator !== entry.principal)
      ) {
        throw new Error("完整影响恢复返回了另一原请求身份。");
      }
      return value;
    } catch (error) {
      if (error.status === 404) {
        return null;
      }
      throw error;
    }
  }

  /**
   * 业务作用：只读原材料唯一任务并复验完整节点、效果与协议证据，关闭新执行不妨碍历史读取。
   * 参数说明：
   * - `proposal`：当前完整原材料记录。
   * 返回：完整任务或当前未找到；不改变任何执行状态。
   */
  async function execution(proposal) {
    return checkedExecution(
      (await send(path(`/${proposal.id}/execution`))).data,
      proposal,
      cluster,
      scope,
    );
  }

  /**
   * 业务作用：用当前主体的原键与代际恢复保存结果，不读取或重新上传PEM。
   * 参数说明：
   * - `entry`：发送前固定的原低敏请求身份。
   * 返回：唯一原材料记录；未找到交由页面保持未知，不生成新键。
   */
  async function resolveMaterial(entry) {
    const value = checkedRecord(
      (
        await send(path("/resolve"), {
          headers: {
            "Idempotency-Key": entry.key,

            "Naway-Admission-Epoch": entry.epoch,
          },
        })
      ).data.proposal,
      cluster,
      scope,
    );
    if (
      value.creator !== entry.principal ||
      String(value.admission_epoch) !== entry.epoch
    ) {
      throw new Error("材料恢复响应不属于原主体和原受理代。");
    }
    return value;
  }

  /**
   * 业务作用：只发送调用方已冻结并登记身份的明确JSON动作，响应按原材料领域验证。
   * 参数说明：
   * - `suffix`：固定的原资源动作后缀。
   * - `value`：首次明确动作正文。
   * - `headers`：原幂等键或受理代；不能包含替代主体。
   * 返回：原响应正文，后续调用方必须核对具体领域身份。
   */
  async function post(suffix, value, headers = {}) {
    return (
      await send(path(suffix), {
        method: "POST",

        headers: {
          "Content-Type": "application/json",
          ...headers,
        },

        body: JSON.stringify(value),
      })
    ).data;
  }

  return {
    path,

    scoped,

    capabilities,

    list,

    record,

    impact,

    execution,

    resolveMaterial,

    post,
  };
}
