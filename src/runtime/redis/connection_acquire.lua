-- 一个共享键记录各持有者的独立期限；拒绝及其它持有者的续期都不能延长泄漏名额。
local limit = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])
local lease = ARGV[3]
if limit == nil or limit <= 0 or ttl == nil or ttl <= 0 or not lease or lease == '' then
    return redis.error_reply('invalid connection lease parameters')
end
local kind = redis.call('TYPE', KEYS[1]).ok
if kind == 'string' then
    -- 旧制品的计数没有持有者证据；等待原权威排空或过期，不篡改它的名额。
    return {0, tonumber(redis.call('GET', KEYS[1])) or 0}
end
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
local current = redis.call('ZCARD', KEYS[1])
if redis.call('ZSCORE', KEYS[1], lease) then
    -- 同一申请收到重试时继续使用原租约，不重复计数或延长原期限。
    return {1, current}
end
if current >= limit then
    return {0, current}
end
redis.call('ZADD', KEYS[1], now + ttl, lease)
local latest = redis.call('ZREVRANGE', KEYS[1], 0, 0, 'WITHSCORES')
redis.call('PEXPIREAT', KEYS[1], latest[2])
return {1, current + 1}
