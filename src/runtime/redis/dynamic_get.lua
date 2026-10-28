-- 先在 Redis 内限制实体长度，超大共享值不得跨网络进入网关内存。
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 0 then
    return false
end
if redis.call('HSTRLEN', KEYS[1], ARGV[1]) > tonumber(ARGV[2]) then
    redis.call('HDEL', KEYS[1], ARGV[1])
    return false
end
return redis.call('HGET', KEYS[1], ARGV[1])
