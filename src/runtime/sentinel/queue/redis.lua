-- 调度时间只取 Redis TIME；请求令牌不携带正文或原始维度。
if not redis.acl_check_cmd then
    return redis.error_reply('sentinel queue requires ACL preflight')
end
local operation, token = ARGV[1], ARGV[2]
local interval, maximum, wait, remaining = tonumber(ARGV[3]), tonumber(ARGV[4]), tonumber(ARGV[5]), tonumber(ARGV[6])
local active_limit, soft_open, owner_limit = tonumber(ARGV[7]), ARGV[8], tonumber(ARGV[9])
-- 业务作用：限制调度字段为精确整数，防止浮点或无界参数改变共享时间权威。
-- 参数说明：
-- - value：待验证的整数。
-- - minimum：允许的下界。
-- - maximum_value：允许的上界。
-- 返回：仅范围内精确整数通过。
local function integer(value, minimum, maximum_value)
    return value and value == math.floor(value) and value >= minimum and value <= maximum_value
end
if #KEYS ~= 5 or #ARGV ~= 9 or not token or #token ~= 32 or not string.match(token, '^[0-9a-f]+$')
    or (operation ~= 'probe' and operation ~= 'reserve' and operation ~= 'claim' and operation ~= 'release')
    or not integer(interval, 1, 3600000000) or not integer(maximum, 1, 4096)
    or not integer(wait, 1000, 60000000) or not integer(remaining, 1, 60000000)
    or not integer(active_limit, 1, 1000000) or not integer(owner_limit, 0, 1000000)
    or (soft_open ~= '0' and soft_open ~= '1') then
    return redis.error_reply('invalid sentinel queue arguments')
end
for i = 1, 5 do
    local kind = redis.call('TYPE', KEYS[i]).ok
    local expected = i == 1 and 'hash' or 'zset'
    if kind ~= 'none' and kind ~= expected then
        return redis.error_reply('invalid sentinel queue state type')
    end
end
if operation == 'release' then
    -- 取消只能撤销本请求的随机令牌，不回退其它等待者已经引用的调度尾部。
    if not redis.acl_check_cmd('ZREM', KEYS[2], token) or not redis.acl_check_cmd('ZREM', KEYS[3], token) then
        return redis.error_reply('sentinel queue release authority unavailable')
    end
    redis.call('ZREM', KEYS[2], token)
    redis.call('ZREM', KEYS[3], token)
    return {1}
end
local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000000 + tonumber(clock[2])
local now_ms = math.floor(now / 1000)
local state = redis.call('HMGET', KEYS[1], 'tail', 'grant', 'clock', 'interval', 'capacity', 'wait')
local tail, grant, previous = tonumber(state[1]), tonumber(state[2]), tonumber(state[3])
if state[1] and (not integer(tail, 0, 4503599627370496) or not integer(grant, 0, 4503599627370496)
    or not integer(previous, 0, 4503599627370496) or tonumber(state[4]) ~= interval
    or tonumber(state[5]) ~= maximum or tonumber(state[6]) ~= wait) then
    return redis.error_reply('invalid sentinel queue schedule')
end
if previous and now < previous then
    return {-5}
end
if now + interval + wait >= 4503599627370496 then
    return {-5}
end
local count = redis.call('ZCARD', KEYS[2])
if count > 4096 or redis.call('ZCARD', KEYS[3]) ~= count or (count > 0 and not state[1]) then
    return redis.error_reply('invalid sentinel queue cardinality')
end
local expired = redis.call('ZRANGEBYSCORE', KEYS[3], '-inf', now)
local due = math.max(tail or now, now)
local deadline = now + math.min(wait, remaining)
local result = 1
if operation == 'claim' then
    local reserved = redis.call('ZSCORE', KEYS[2], token)
    local expires = redis.call('ZSCORE', KEYS[3], token)
    if not reserved or not expires or tonumber(expires) <= now then
        return {-2}
    end
    deadline = tonumber(expires)
    due = math.max(tonumber(reserved), (grant or 0) + interval)
    if due >= deadline then
        return {-2}
    end
    local first = redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', '+inf', 'LIMIT', 0, #expired + 1)
    local leader = false
    for _, candidate in ipairs(first) do
        local expiry = redis.call('ZSCORE', KEYS[3], candidate)
        if not expiry then
            return redis.error_reply('sentinel queue ticket has no deadline')
        end
        if tonumber(expiry) > now then
            leader = candidate
            break
        end
    end
    if leader ~= token then
        return {2, 50000}
    end
    if due > now then
        return {2, due - now}
    end
elseif count - #expired > 0 or due > now then
    if operation == 'probe' then
        return {-3}
    end
    if count - #expired >= maximum then
        return {-1}
    end
    if due >= deadline then
        return {-2}
    end
    if redis.call('ZSCORE', KEYS[2], token) then
        return redis.error_reply('sentinel queue token already reserved')
    end
    result = 2
end
local active_count = redis.call('ZCARD', KEYS[4]) - redis.call('ZCOUNT', KEYS[4], '-inf', now_ms)
local existing = redis.call('ZSCORE', KEYS[4], KEYS[1])
local new_state = not existing or tonumber(existing) <= now_ms
if new_state then
    -- 物理容量和归属容量优先于显式软门，不能用放行策略创建无界共享状态。
    if active_count >= 65536 then
        return {-4}
    end
    if owner_limit > 0 then
        local owned = redis.call('ZSCORE', KEYS[5], KEYS[1])
        if (not owned or tonumber(owned) <= now_ms)
            and redis.call('ZCARD', KEYS[5]) - redis.call('ZCOUNT', KEYS[5], '-inf', now_ms) >= owner_limit then
            return {-4}
        end
    end
    if active_count >= active_limit then
        if soft_open == '1' and operation ~= 'claim' then
            return {3}
        end
        return {-4}
    end
end
local next_tail = math.max(tail or now, due + interval)
local next_grant = grant or 0
if result == 1 then
    next_grant = now
    next_tail = math.max(next_tail, now + interval)
end
local ttl = math.ceil((math.max(next_tail, deadline, now + wait) - now) / 1000) + 1000
-- 全部写权限在首个副作用之前验证，避免脚本部分执行后失去一致的队列权威。
if not redis.acl_check_cmd('HSET', KEYS[1], 'tail', next_tail, 'grant', next_grant, 'clock', now, 'interval', interval, 'capacity', maximum, 'wait', wait) then
    return redis.error_reply('sentinel queue schedule authority unavailable')
end
for i = 1, 5 do
    if not redis.acl_check_cmd('PEXPIRE', KEYS[i], ttl + 1000) then
        return redis.error_reply('sentinel queue expiry authority unavailable')
    end
    if i > 1 and (not redis.acl_check_cmd('ZREM', KEYS[i], token)
        or not redis.acl_check_cmd('ZADD', KEYS[i], now, token)) then
        return redis.error_reply('sentinel queue index authority unavailable')
    end
    if i >= 4 and not redis.acl_check_cmd('ZREMRANGEBYSCORE', KEYS[i], '-inf', now_ms) then
        return redis.error_reply('sentinel queue capacity authority unavailable')
    end
    -- 读权限也在写入前经过真实命令验证，不能把后续 TTL 读取失败留在提交之后。
    redis.call('PTTL', KEYS[i])
end
for _, expired_token in ipairs(expired) do
    redis.call('ZREM', KEYS[2], expired_token)
    redis.call('ZREM', KEYS[3], expired_token)
end
if result == 2 then
    redis.call('ZADD', KEYS[2], due, token)
    redis.call('ZADD', KEYS[3], deadline, token)
elseif operation == 'claim' then
    redis.call('ZREM', KEYS[2], token)
    redis.call('ZREM', KEYS[3], token)
end
-- 先提交实际授权时刻和未来债务，再返回准入；取消不能撤回已授予的间隔。
redis.call('HSET', KEYS[1], 'tail', next_tail, 'grant', next_grant, 'clock', now, 'interval', interval, 'capacity', maximum, 'wait', wait)
for i = 1, 3 do
    redis.call('PEXPIRE', KEYS[i], ttl)
end
for i = 4, 5 do
    if i == 4 or owner_limit > 0 then
        redis.call('ZREMRANGEBYSCORE', KEYS[i], '-inf', now_ms)
        redis.call('ZADD', KEYS[i], now_ms + ttl, KEYS[1])
        if redis.call('PTTL', KEYS[i]) < ttl + 1000 then
            redis.call('PEXPIRE', KEYS[i], ttl + 1000)
        end
    end
end
if result == 2 then
    return {2, due - now}
end
return {1}
