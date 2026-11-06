//! 集群材料动作的本机准备和文件执行，共用既有材料锁与底层文件事务。

pub(crate) mod apply;
pub(crate) mod prepare;
pub(crate) mod source;
