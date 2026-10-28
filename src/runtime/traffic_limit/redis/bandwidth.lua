-- 同一方向的所有节点共享理论发送时刻；先检查完整成本和写权限，再发布调度债务。
if not redis.acl_check_cmd then
    return redis.error_reply('traffic ledger requires Redis ACL preflight capability')
end
local state_type = redis.call('TYPE', KEYS[1]).ok
local index_type = redis.call('TYPE', KEYS[2]).ok
if (state_type ~= 'none' and state_type ~= 'hash') or (index_type ~= 'none' and index_type ~= 'zset') then
    return redis.error_reply('invalid bandwidth state type')
end
local capacity, bytes, rate, burst, max_wait = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3]), tonumber(ARGV[4]), tonumber(ARGV[5])
if not capacity or capacity < 1 or capacity > 1000000 or not bytes or bytes < 0 or bytes > 4294967296
    or not rate or rate < 1 or rate > 4294967296 or not burst or burst < 0 or burst > 4294967296
    or burst > rate * 60 or not max_wait or max_wait < 1 or max_wait > 60000000 then
    return redis.error_reply('invalid bandwidth arguments')
end
local clock = redis.call('TIME')
local physical_now = tonumber(clock[1]) * 1000000 + tonumber(clock[2])
if physical_now < 0 or physical_now > 4500000000000000 then
    return redis.error_reply('bandwidth clock exceeds exact range')
end
local now, tat = physical_now, physical_now
if state_type ~= 'none' then
    local state = redis.call('HMGET', KEYS[1], 'clock', 'tat')
    local previous = tonumber(state[1])
    tat = tonumber(state[2])
    if not previous or previous < 0 or previous % 1 ~= 0 or previous - now > 60000000
        or not tat or tat < previous or tat % 1 ~= 0 or tat > 4503599627370496 then
        return redis.error_reply('invalid bandwidth state')
    end
    now = math.max(now, previous)
end
local next_tat = math.max(now, tat) + math.ceil(bytes * 1000000 / rate)
local tolerance = math.ceil(burst * 1000000 / rate)
local delay = math.max(0, next_tat - tolerance - physical_now)
if delay > max_wait or next_tat > 4503599627370496 then
    return {-2}
end
local now_ms = math.floor(physical_now / 1000)
local existing = redis.call('ZSCORE', KEYS[2], KEYS[1])
local expired = redis.call('ZCOUNT', KEYS[2], '-inf', now_ms)
if (not existing or tonumber(existing) <= now_ms) and redis.call('ZCARD', KEYS[2]) - expired >= capacity then
    return {-1}
end
-- 状态必须活到全部债务过期；取消一条流也不能把其它并发流的发送时刻提前。
local ttl = math.max(1, math.ceil((next_tat - physical_now) / 1000) + 1)
local next_text, now_text = string.format('%.0f', next_tat), string.format('%.0f', now)
if not redis.acl_check_cmd('HSET', KEYS[1], 'clock', now_text, 'tat', next_text)
    or not redis.acl_check_cmd('PEXPIRE', KEYS[1], ttl)
    or not redis.acl_check_cmd('ZREMRANGEBYSCORE', KEYS[2], '-inf', now_ms)
    or not redis.acl_check_cmd('ZADD', KEYS[2], now_ms + ttl, KEYS[1])
    or not redis.acl_check_cmd('PEXPIRE', KEYS[2], ttl + 1000) then
    return redis.error_reply('bandwidth write authority unavailable')
end
local index_ttl = redis.call('PTTL', KEYS[2])
redis.call('HSET', KEYS[1], 'clock', now_text, 'tat', next_text)
redis.call('PEXPIRE', KEYS[1], ttl)
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now_ms)
redis.call('ZADD', KEYS[2], now_ms + ttl, KEYS[1])
if index_ttl < ttl + 1000 then
    redis.call('PEXPIRE', KEYS[2], ttl + 1000)
end
return {delay}
