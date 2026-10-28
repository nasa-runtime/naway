-- 新增键与容量判断必须原子执行；已有键更新不重复占用目录名额。
local exists = redis.call('HEXISTS', KEYS[1], ARGV[1])
if exists == 0 and redis.call('HLEN', KEYS[1]) >= tonumber(ARGV[3]) then
    return 0
end
-- 业务作用：将字符串传输中的十六进制编码还原为原始字节，保持二进制存储合同。
-- 参数说明：
-- - pair：一个原始字节对应的两位十六进制字符。
-- 返回：对应单字节；编码由调用方生成，不接受外部未验证输入。
local value = string.gsub(ARGV[2], '..', function(pair)
    return string.char(tonumber(pair, 16))
end)
redis.call('HSET', KEYS[1], ARGV[1], value)
return 1
