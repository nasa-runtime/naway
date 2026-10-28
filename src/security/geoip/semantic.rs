//! MMDB 比较保留冻结材料身份，不复制数据库或在比较期间查询地址。

use super::DatabaseSnapshot;

impl PartialEq for DatabaseSnapshot {
    /// 业务作用：识别同路径数据库轮换，确保比较依据与实际查询 reader 来自同一次读取。
    ///
    /// 参数说明：
    /// - `other`：候选构建内共享的已解析数据库。
    ///
    /// 返回：材料、数据库类型和构建时间一致时为真，不重新打开文件或读取当前时钟。
    fn eq(&self, other: &Self) -> bool {
        let Self {
            material_identity,
            database_type,
            build_time,
            reader: _,
        } = self;
        material_identity == &other.material_identity
            && database_type == &other.database_type
            && build_time == &other.build_time
    }
}

impl Eq for DatabaseSnapshot {}
