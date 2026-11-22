-- Redis 时间给出活跃租约的期限，只有仍持有名额的同一执行者可以续期。
if redis.call('TYPE', KEYS[1]).ok ~= 'zset' then
    return 0
end
local ttl = tonumber(ARGV[1])
local lease = ARGV[2]
local time = redis.call('TIME')
local now = tonumber(time[1]) * 1000 + math.floor(tonumber(time[2]) / 1000)
local score = tonumber(redis.call('ZSCORE', KEYS[1], lease))
if not score or score <= now or not ttl or ttl <= 0 then
    return 0
end
-- 旧续期延迟抵达时不能缩短已经提交的更晚期限。
if now + ttl > score then
    redis.call('ZADD', KEYS[1], 'XX', now + ttl, lease)
    local latest = redis.call('ZREVRANGE', KEYS[1], 0, 0, 'WITHSCORES')
    redis.call('PEXPIREAT', KEYS[1], latest[2])
end
return 1
