-- 并发名额使用有期限的共享计数；客户端失联不会留下永久占用。
local limit = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
if limit == nil or limit <= 0 then
    return {
        1,
        0
    }
end
if ttl == nil or ttl <= 0 then
    ttl = 60000
end
local current = redis.call('INCR', KEYS[1])
redis.call('PEXPIRE', KEYS[1], ttl)
-- 未获准的申请必须原子撤销自己的增量，不能消耗其它连接的余额。
if current > limit then
    current = redis.call('DECR', KEYS[1])
    if current <= 0 then
        redis.call('DEL', KEYS[1])
    end
    return {
        0,
        current
    }
end
return {
    1,
    current
}
