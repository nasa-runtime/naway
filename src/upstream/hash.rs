//! 一致性哈希选择表(ring-hash / Maglev)与会话保持的哈希底座。
//!
//! 本模块只回答「给定一个哈希键,按稳定顺序给出候选实例的探测次序」,不认识健康、
//! locality、backup 分层与排除列表——那些仍由 `upstream::select_instance_from_slice`
//! 的候选谓词裁决。这样一致性哈希不会成为健康检查旁路:表里命中的实例若已不可选,
//! 调用方继续沿表向后探测,健康实例存在时绝不会粘在失效实例上。

use std::cmp::Ordering as CmpOrdering;
use std::collections::BinaryHeap;
use std::sync::Arc;

use super::UpstreamInstance;

/// ring-hash 每单位权重生成的虚拟节点数上限,防止超大权重把环撑爆。
pub const MAX_REPLICAS_PER_UNIT_WEIGHT: u32 = 1_000;
/// 环上虚拟节点总数硬上限。超过即在构建期拒绝候选配置。
pub const MAX_RING_ENTRIES: usize = 1 << 20;
/// Maglev 查找表尺寸硬上限(必须是质数,见 `MAGLEV_PRIMES`)。
pub const MAX_MAGLEV_TABLE: usize = 655_373;
/// 单次查找允许向后探测的最大不同实例数,避免大规模不可用时退化成全表扫描。
const MAX_PROBES: usize = 64;

/// 可选质数表:Maglev 要求表长为质数才能保证 permutation 覆盖全表。
const MAGLEV_PRIMES: &[usize] = &[
    251, 509, 1_021, 2_053, 4_099, 8_209, 16_411, 32_771, 65_537, 131_071, 262_147, 655_373,
];

/// 加权槽位调度游标。
///
/// 比较键使用下一个槽位的归一化位置 `(2 * picks + 1) / weight`。二叉堆每次取位置
/// 最靠前的成员，因此任意前缀都接近声明权重，而不是只在表头体现一次权重后退化为等权。
#[derive(Clone, Copy, PartialEq, Eq)]
struct WeightedTurn {
    /// 已分配槽位数。
    picks: u64,
    /// 成员权重。
    weight: u64,
    /// 成员在构建数组中的稳定下标。
    member: usize,
}

impl Ord for WeightedTurn {
    /// 业务作用：按下一个归一化槽位位置排序加权成员，供 `BinaryHeap` 确定性取最小位置。
    ///
    /// 参数说明：
    /// - `other`：是另一个调度游标。
    ///
    /// 返回：位置更小者排序更大；位置相同时稳定下标更小者优先。
    fn cmp(&self, other: &Self) -> CmpOrdering {
        let self_numerator = u128::from(self.picks).saturating_mul(2).saturating_add(1);
        let other_numerator = u128::from(other.picks).saturating_mul(2).saturating_add(1);
        let left = self_numerator.saturating_mul(u128::from(other.weight));
        let right = other_numerator.saturating_mul(u128::from(self.weight));
        right
            .cmp(&left)
            .then_with(|| other.member.cmp(&self.member))
    }
}

impl PartialOrd for WeightedTurn {
    /// 业务作用：复用总序为加权调度游标提供堆排序关系。
    ///
    /// 参数说明：
    /// - `other`：是另一个调度游标。
    ///
    /// 返回：始终返回可比较的顺序。
    fn partial_cmp(&self, other: &Self) -> Option<CmpOrdering> {
        Some(self.cmp(other))
    }
}

/// 业务作用：按声明权重生成指定长度的确定性成员次序。
///
/// 参数说明：
/// - `weights`：是稳定成员顺序及其正权重
/// - `slots`：是需要分配的槽位数。
///
/// 返回：成员下标序列；空成员或零槽位返回空序列。
fn weighted_member_order(weights: &[u64], slots: usize) -> Vec<usize> {
    let mut heap = BinaryHeap::with_capacity(weights.len());
    for (member, weight) in weights.iter().copied().enumerate() {
        if weight > 0 {
            heap.push(WeightedTurn {
                picks: 0,
                weight,
                member,
            });
        }
    }
    let mut order = Vec::with_capacity(slots);
    while order.len() < slots {
        let Some(mut turn) = heap.pop() else {
            break;
        };
        order.push(turn.member);
        turn.picks = turn.picks.saturating_add(1);
        heap.push(turn);
    }
    order
}

/// 业务作用：把任意配置值收敛到不大于上限的合法 Maglev 表长,保证 permutation 能覆盖全表。
///
/// 参数说明：
/// - `requested`：是配置声明的期望表长。
///
/// 返回：不小于 `requested` 的最小质数；超过硬上限时返回上限质数。
pub fn maglev_table_size(requested: usize) -> usize {
    for prime in MAGLEV_PRIMES {
        if *prime >= requested {
            return *prime;
        }
    }
    MAX_MAGLEV_TABLE
}

/// 业务作用：对任意字节串给出稳定且高位充分扩散的 64 位哈希,作为环位置、
/// Maglev permutation 与会话亲和令牌的共同基础。
///
/// 选用 FNV-1a + 雪崩终混:FNV-1a 保证实现固定、跨进程与跨版本稳定,不依赖随机 seed
/// (**绝不能换成 `DefaultHasher`**——它带进程级随机种子,同一 key 在不同节点会落到
/// 不同实例,直接破坏跨节点一致性)。
///
/// **终混不可省略**:裸 FNV-1a 对长度相同、仅个别字节不同的输入,高位几乎不变
/// (例如三个只差端口末位的 URI,前 20 bit 完全相同)。环位置按整个 u64 排序并二分,
/// 高位不扩散会让所有键落进环上同一段窄区间,只有少数实例能被选中——份额严重倾斜。
/// 这里补一次 fmix64 终混,使高低位都充分扩散。
///
/// 参数说明：
/// - `bytes`：是已经过 allowlist 与长度裁剪的哈希键原文。
///
/// 返回：稳定 64 位哈希值。
pub fn stable_hash(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xff51_afd7_ed55_8ccd);
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    hash ^ (hash >> 33)
}

/// 业务作用：把 64 位种子与一个序号混合,派生虚拟节点位置与 Maglev 的 offset/skip。
///
/// 参数说明：
/// - `seed`：是实例身份哈希
/// - `index`：是副本序号。
///
/// 返回：派生哈希；同一 `(seed, index)` 在任何节点上恒等。
fn derive(seed: u64, index: u64) -> u64 {
    let mut hash = seed ^ index.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xff51_afd7_ed55_8ccd);
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    hash ^= hash >> 33;
    hash
}

/// 一致性哈希表的具体形态。
enum HashTableKind {
    /// 有序虚拟节点环:`(位置, 实例下标)`,按位置升序,二分定位后向后环绕探测。
    Ring(Box<[(u64, u32)]>),
    /// Maglev 查找表:定长数组,每格存实例下标,O(1) 定位后按表顺序向后探测。
    Maglev(Box<[u32]>),
}

/// 一份与具体实例切片绑定的一致性哈希表。
///
/// **生命周期不变式**:结构体持有构建时那份 `Arc<[Arc<UpstreamInstance>]>` 的强引用。
/// 这既保证 `Arc::ptr_eq` 的指针比较不会因为地址复用产生 ABA 误判,也保证表内下标
/// 始终能安全索引回同一份切片。
pub struct ConsistentHashTable {
    instances: Arc<[Arc<UpstreamInstance>]>,
    kind: HashTableKind,
}

impl ConsistentHashTable {
    /// 业务作用：判断缓存表是否仍然对应当前实例切片,避免实例目录换代后继续用旧表选路。
    ///
    /// 参数说明：
    /// - `instances`：是本次请求读到的实例切片。
    ///
    /// 返回：指向同一份切片时返回 `true`。
    pub fn matches(&self, instances: &Arc<[Arc<UpstreamInstance>]>) -> bool {
        Arc::ptr_eq(&self.instances, instances)
    }

    /// 业务作用：按 ketama 风格构建加权虚拟节点环,使扩缩容只迁移该实例自身承担的 key。
    ///
    /// 权重直接决定虚拟节点数,因此加权与一致性在同一结构里表达;权重为 0 或被强制下线
    /// 的实例不进环——它们本就不该承接任何 key,放进环只会制造必然失败的探测。
    ///
    /// 参数说明：
    /// - `instances`：是服务当前实例切片
    /// - `replicas_per_weight`：是每单位权重的虚拟节点数。
    ///
    /// 返回：构建好的环；无任何可入环实例时返回 `None`。
    pub fn build_ring(
        instances: &Arc<[Arc<UpstreamInstance>]>,
        replicas_per_weight: u32,
    ) -> Option<Self> {
        Self::build_ring_weighted(instances, replicas_per_weight, |instance| {
            u64::from(instance.weight)
        })
    }

    /// 业务作用：将服务已编译的拓扑份额纳入一致性哈希，不复制或改写共享实例。
    ///
    /// 参数说明：
    /// - `instances`：服务当前的不可变实例切片。
    /// - `replicas_per_weight`：每单位有效权重的虚拟节点数。
    /// - `weight`：已归一化的实例与拓扑组合权重读取器。
    ///
    /// 返回：受固定环容量约束的共享目录索引；无有效权重时返回 None。
    pub(super) fn build_ring_weighted(
        instances: &Arc<[Arc<UpstreamInstance>]>,
        replicas_per_weight: u32,
        weight: impl Fn(&UpstreamInstance) -> u64,
    ) -> Option<Self> {
        let replicas = replicas_per_weight.clamp(1, MAX_REPLICAS_PER_UNIT_WEIGHT);
        let mut members = Vec::new();
        for (index, inst) in instances.iter().enumerate() {
            let Some(count) = ring_replicas(inst, replicas, weight(inst)) else {
                continue;
            };
            members.push((index as u32, count, stable_hash(inst.health_key.as_bytes())));
        }
        if members.is_empty() {
            return None;
        }
        let desired = members.iter().fold(0_u128, |total, (_, count, _)| {
            total.saturating_add(*count as u128)
        });
        let entry_count = desired.min(MAX_RING_ENTRIES as u128) as usize;
        let weights = members
            .iter()
            .map(|(_, count, _)| *count)
            .collect::<Vec<_>>();
        let order = weighted_member_order(&weights, entry_count);
        let mut assigned = vec![0_u64; members.len()];
        let mut entries: Vec<(u64, u32)> = Vec::with_capacity(entry_count);
        for member in order {
            let (index, _, seed) = members[member];
            let replica = assigned[member];
            assigned[member] = replica.saturating_add(1);
            entries.push((derive(seed, replica), index));
        }
        // 位置升序是二分查找的前提;位置相同时按实例下标定序,保证任何节点构建出的环完全一致。
        entries.sort_unstable_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
        entries.dedup_by(|left, right| left.0 == right.0 && left.1 == right.1);
        Some(Self {
            instances: instances.clone(),
            kind: HashTableKind::Ring(entries.into_boxed_slice()),
        })
    }

    /// 业务作用：构建 Maglev 查找表,在保持一致性的同时得到比环更均匀的份额分布。
    ///
    /// 按标准 Maglev:每个实例用 `(offset, skip)` 生成一条覆盖全表的 permutation,
    /// 轮流认领尚未被占用的槽位。权重通过「认领轮数」体现,使加权与均匀性共存。
    ///
    /// 参数说明：
    /// - `instances`：是服务当前实例切片
    /// - `table_size`：是期望表长(会归一到质数)。
    ///
    /// 返回：构建好的查找表；无任何可入表实例时返回 `None`。
    pub fn build_maglev(
        instances: &Arc<[Arc<UpstreamInstance>]>,
        table_size: usize,
    ) -> Option<Self> {
        Self::build_maglev_weighted(instances, table_size, |instance| u64::from(instance.weight))
    }

    /// 业务作用：用同一拓扑份额构建 Maglev 分配表，使加权选择与候选分层保持一致。
    ///
    /// 参数说明：
    /// - `instances`：服务当前的不可变实例切片。
    /// - `table_size`：期望槽位数，会收敛到有界质数。
    /// - `weight`：实例与拓扑权重的归一化读取器，不创建临时实例对象。
    ///
    /// 返回：固定容量的索引表；没有可分配权重时返回 None。
    pub(super) fn build_maglev_weighted(
        instances: &Arc<[Arc<UpstreamInstance>]>,
        table_size: usize,
        weight: impl Fn(&UpstreamInstance) -> u64,
    ) -> Option<Self> {
        let size = maglev_table_size(table_size);
        // 只有真正可承接 key 的实例参与 permutation;权重为 0 / down 的实例不占槽位。
        let members: Vec<(u32, u64)> = instances
            .iter()
            .enumerate()
            .filter_map(|(index, inst)| {
                ring_replicas(inst, 1, weight(inst)).map(|weight| (index as u32, weight))
            })
            .collect();
        if members.is_empty() {
            return None;
        }
        let mut permutation: Vec<(usize, usize)> = Vec::with_capacity(members.len());
        for (index, _) in &members {
            let inst = &instances[*index as usize];
            let seed = stable_hash(inst.health_key.as_bytes());
            let offset = (derive(seed, 1) % size as u64) as usize;
            // skip 必须与 size 互质;size 为质数时取 [1, size-1] 即可保证覆盖全表。
            let skip = (derive(seed, 2) % (size as u64 - 1)) as usize + 1;
            permutation.push((offset, skip));
        }
        let mut table = vec![u32::MAX; size];
        let mut next: Vec<usize> = vec![0; members.len()];
        let weights = members
            .iter()
            .map(|(_, weight)| *weight)
            .collect::<Vec<_>>();
        // 权重调度必须覆盖整张表。只让每个成员按权重认领一小段、随后等权补满，
        // 会让大表几乎完全退化成 1:1，配置权重在真实流量上失效。
        for slot in weighted_member_order(&weights, size) {
            let (index, _) = members[slot];
            let (offset, skip) = permutation[slot];
            // 沿本实例的 permutation 前进，直到找到空槽；质数表长保证一定能找到。
            loop {
                let candidate = (offset + next[slot] * skip) % size;
                next[slot] += 1;
                if table[candidate] == u32::MAX {
                    table[candidate] = index;
                    break;
                }
            }
        }
        Some(Self {
            instances: instances.clone(),
            kind: HashTableKind::Maglev(table.into_boxed_slice()),
        })
    }

    /// 业务作用：按哈希键定位起点,并沿稳定顺序返回第一个通过候选谓词的实例。
    ///
    /// **可用性优先于亲和性**:表内命中的实例若不健康、被摘除或不在允许 locality,
    /// 继续向后探测而不是返回失败——这正是「健康实例存在时不得粘到已失效实例」的落点。
    /// 探测次数有硬上限,大规模不可用时交回调用方走常规 LB,不做全表扫描。
    ///
    /// 参数说明：
    /// - `hash`: 已由调用方按配置来源算好的稳定哈希键。
    /// - `accept`: 候选谓词,复用既有健康/排除/backup/locality 分层判定。
    ///
    /// 返回：命中的共享实例;探测预算内无可用候选时返回 `None`。
    pub fn select<F>(&self, hash: u64, mut accept: F) -> Option<Arc<UpstreamInstance>>
    where
        F: FnMut(&UpstreamInstance) -> bool,
    {
        match &self.kind {
            HashTableKind::Ring(entries) => {
                if entries.is_empty() {
                    return None;
                }
                // 环绕语义:找不到 >= hash 的位置时回到环首,而不是判定失败。
                let start = entries
                    .binary_search_by(|probe| probe.0.cmp(&hash))
                    .unwrap_or_else(|insert| insert)
                    % entries.len();
                let mut visited = [u32::MAX; MAX_PROBES];
                let mut probed = 0usize;
                for step in 0..entries.len() {
                    let (_, index) = entries[(start + step) % entries.len()];
                    // 虚拟节点不一定相邻；预算必须按不同实例计算，不能让同一高权重实例
                    // 在环上反复出现就耗尽全部探测机会。
                    if visited[..probed].contains(&index) {
                        continue;
                    }
                    if probed == MAX_PROBES {
                        return None;
                    }
                    visited[probed] = index;
                    probed += 1;
                    let inst = &self.instances[index as usize];
                    if accept(inst.as_ref()) {
                        return Some(inst.clone());
                    }
                }
                None
            }
            HashTableKind::Maglev(table) => {
                if table.is_empty() {
                    return None;
                }
                let start = (hash % table.len() as u64) as usize;
                let mut visited = [u32::MAX; MAX_PROBES];
                let mut probed = 0usize;
                for step in 0..table.len() {
                    let index = table[(start + step) % table.len()];
                    if index == u32::MAX || visited[..probed].contains(&index) {
                        continue;
                    }
                    if probed == MAX_PROBES {
                        return None;
                    }
                    visited[probed] = index;
                    probed += 1;
                    let inst = &self.instances[index as usize];
                    if accept(inst.as_ref()) {
                        return Some(inst.clone());
                    }
                }
                None
            }
        }
    }
}

/// 业务作用：计算一个实例应占的虚拟节点数,并把不该承接 key 的实例排除在表外。
///
/// 参数说明：
/// - `inst`：是候选实例
/// - `replicas_per_weight`：是每单位权重的虚拟节点数。
/// - `weight`：实例自身权重与可选拓扑份额组合后的归一化值。
///
/// 返回：应生成的虚拟节点数；实例被强制下线或权重为 0 时返回 `None`。
fn ring_replicas(
    inst: &Arc<UpstreamInstance>,
    replicas_per_weight: u32,
    weight: u64,
) -> Option<u64> {
    if inst.down || inst.weight == 0 || weight == 0 {
        return None;
    }
    Some(weight.saturating_mul(u64::from(replicas_per_weight)).max(1))
}
