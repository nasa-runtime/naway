-- 队列只存动作令牌与到期时间，不持有请求正文；名额不可被其它请求代为释放。
if not redis.acl_check_cmd then
    return redis.error_reply('traffic queue requires Redis ACL preflight capability')
end
local state_type, index_type = redis.call('TYPE', KEYS[1]).ok, redis.call('TYPE', KEYS[2]).ok
if (state_type ~= 'none' and state_type ~= 'zset') or (index_type ~= 'none' and index_type ~= 'zset') then
    return redis.error_reply('invalid traffic queue state type')
end
local capacity, operation, token, maximum, lifetime = tonumber(ARGV[1]), ARGV[2], ARGV[3], tonumber(ARGV[4]), tonumber(ARGV[5])
if not capacity or capacity < 1 or capacity > 1000000 or not token or #token ~= 32
    or not maximum or maximum < 1 or maximum > 4096 or not lifetime or lifetime < 1 or lifetime > 61000
    or (operation ~= '0' and operation ~= '1') then
    return redis.error_reply('invalid traffic queue arguments')
end
if operation == '0' then
    -- 删除仅匹配不可猜测的本请求令牌；到期索引保守保留，避免误撤其它等待者的容量。
    if not redis.acl_check_cmd('ZREM', KEYS[1], token) then
        return redis.error_reply('traffic queue release authority unavailable')
    end
    redis.call('ZREM', KEYS[1], token)
    return {1}
end
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local expired = redis.call('ZCOUNT', KEYS[1], '-inf', now)
if redis.call('ZCARD', KEYS[1]) - expired >= maximum then
    return {0}
end
local existing = redis.call('ZSCORE', KEYS[2], KEYS[1])
local expired_states = redis.call('ZCOUNT', KEYS[2], '-inf', now)
if (not existing or tonumber(existing) <= now) and redis.call('ZCARD', KEYS[2]) - expired_states >= capacity then
    return {-1}
end
local state_ttl, index_ttl = redis.call('PTTL', KEYS[1]), redis.call('PTTL', KEYS[2])
local ttl = math.max(lifetime + 1, state_ttl)
if not redis.acl_check_cmd('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
    or not redis.acl_check_cmd('ZADD', KEYS[1], now + lifetime, token)
    or not redis.acl_check_cmd('PEXPIRE', KEYS[1], ttl)
    or not redis.acl_check_cmd('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
    or not redis.acl_check_cmd('ZADD', KEYS[2], now + ttl, KEYS[1])
    or not redis.acl_check_cmd('PEXPIRE', KEYS[2], ttl + 1000) then
    return redis.error_reply('traffic queue write authority unavailable')
end
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now)
redis.call('ZADD', KEYS[1], now + lifetime, token)
redis.call('PEXPIRE', KEYS[1], ttl)
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now)
redis.call('ZADD', KEYS[2], now + ttl, KEYS[1])
if index_ttl < ttl + 1000 then
    redis.call('PEXPIRE', KEYS[2], ttl + 1000)
end
return {1}
