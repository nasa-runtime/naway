export const upstreamCatalogFields = [
  ["registry_service_import", "Kubernetes MCS ServiceImport 端点", "boolean"],
  ["registry_port_name", "Kubernetes 端口名称（与数字端口互斥）", "string"],
  ["scheme", "发现实例的 URI scheme：http / https", "string"],
  ["clusters", "Nacos cluster 过滤（每行一项，空列表允许全部）", "lines"],
  ["hash_ring_replicas", "哈希环每单位权重的虚拟节点数（1–1000）", "number"],
  ["hash_table_size", "Maglev 期望槽位数（1–655373，选预设质数）", "number"],
];
