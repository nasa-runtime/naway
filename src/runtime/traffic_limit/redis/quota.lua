-- 所有窗口先完整预检，再在同一 slot 发布；脚本错误没有自动回滚，任何类型错误必须先于写入。
if not redis.acl_check_cmd then
    return redis.error_reply('traffic ledger requires Redis ACL preflight capability')
end
local state_type = redis.call('TYPE', KEYS[1]).ok
local index_type = redis.call('TYPE', KEYS[2]).ok
if (state_type ~= 'none' and state_type ~= 'hash') or (index_type ~= 'none' and index_type ~= 'zset') then
    return redis.error_reply('invalid traffic state type')
end
local capacity = tonumber(ARGV[1])
local cost = tonumber(ARGV[2])
local count = tonumber(ARGV[3])
local algorithm = tonumber(ARGV[4])
if not capacity or capacity < 1 or capacity > 1000000 or not cost or cost < 0 or cost > 4294967296
    or not count or count < 1 or count > 16 or not algorithm or algorithm < 1 or algorithm > 3 then
    return redis.error_reply('invalid traffic arguments')
end
local clock = redis.call('TIME')
local physical_now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
local previous_clock = redis.call('HGET', KEYS[1], 'clock')
if state_type == 'hash' and not previous_clock then
    return redis.error_reply('traffic state clock is missing')
end
local now = physical_now
local token = ARGV[5 + count * 3]
if token then
    local queue_type = redis.call('TYPE', KEYS[3]).ok
    if queue_type ~= 'none' and queue_type ~= 'zset' then
        return redis.error_reply('invalid traffic queue authority')
    end
    local expires = redis.call('ZSCORE', KEYS[3], token)
    -- 排队权威必须在本次提交内复验；过期、撤销或其它请求的令牌都不能取得额度。
    if not expires or tonumber(expires) <= physical_now then
        return {-3}
    end
    if not redis.acl_check_cmd('ZREM', KEYS[3], token) then
        return redis.error_reply('traffic queue release authority unavailable')
    end
end
if physical_now < 0 or physical_now > 4500000000000 then
    return redis.error_reply('traffic clock exceeds exact range')
end
if previous_clock then
    local timestamp = tonumber(previous_clock)
    if not timestamp or timestamp % 1 ~= 0 or timestamp < 0 or timestamp > 4503599627370496 or timestamp - now > 60000 then
        return redis.error_reply('invalid traffic clock')
    end
    now = math.max(now, timestamp)
end
local windows = {}
local remaining = 4503599627370496
local tight_limit = 0
local tight_reset = 0
local retry = 0
local allowed = true
local retention = 1
for i = 1, count do
    local offset = 5 + (i - 1) * 3
    local limit = tonumber(ARGV[offset])
    local duration = tonumber(ARGV[offset + 1])
    local burst = tonumber(ARGV[offset + 2])
    if not limit or limit < 1 or not duration or duration < 1 or duration > 2678400000 or not burst or burst < 0
        or limit + burst > 4294967296 or (limit + burst) * duration > 4503599627370496 then
        return redis.error_reply('invalid traffic window')
    end
    local state = redis.call('HMGET', KEYS[1], i .. ':current', i .. ':previous', i .. ':start', i .. ':debt')
    local current, previous, started, debt = 0, 0, now, 0
    if state_type ~= 'none' then
        current, previous, started, debt = tonumber(state[1]), tonumber(state[2]), tonumber(state[3]), tonumber(state[4])
        if not current or not previous or not started or not debt or current < 0 or previous < 0 or started < 0 or debt < 0
            or current % 1 ~= 0 or previous % 1 ~= 0 or started % 1 ~= 0 or debt % 1 ~= 0
            or current > 4294967296 or previous > 4294967296 or started > now or debt > 4503599627370496 then
            return redis.error_reply('invalid traffic window state')
        end
    end
    local elapsed = now - started
    if elapsed >= duration then
        if elapsed >= 2 * duration then
            previous = 0
        else
            previous = current
        end
        -- 窗口沿原始边界推进，拒绝请求不写账本也不能反复重置滑动残值的衰减起点。
        started = started + math.floor(elapsed / duration) * duration
        current, elapsed = 0, now - started
    end
    local reset = duration - elapsed
    local used = current
    local bound = limit + burst
    local wait = reset
    local next_debt = debt
    if algorithm == 2 then
        used = current + math.floor(previous * reset / duration)
        if previous > 0 then
            local excess = math.max(0, used + cost - bound)
            if excess >= previous then
                wait = duration
            else
                wait = math.ceil(excess * duration / previous)
            end
        end
    elseif algorithm == 3 then
        -- 微秒时钟与债务始终处于精确整数范围；无法装入一窗的成本不生成债务。
        local now_us = now * 1000 + tonumber(clock[2]) % 1000
        local outstanding = math.max(0, debt - now_us)
        local per_unit = math.max(1, math.ceil(duration * 1000 / limit))
        next_debt = now_us + outstanding + per_unit * math.min(cost, limit)
        bound = limit
        used = math.max(0, limit - math.floor(math.max(0, duration * 1000 - outstanding) / per_unit))
        wait = math.max(1, math.ceil((next_debt - now_us - duration * 1000) / 1000))
    end
    local accepts = used + cost <= bound
    if algorithm == 3 then
        accepts = cost <= limit and next_debt <= now * 1000 + tonumber(clock[2]) % 1000 + duration * 1000
    end
    if not accepts then
        allowed = false
        retry = math.max(retry, wait)
    end
    local left = math.max(0, bound - used)
    if left < remaining then
        remaining, tight_limit, tight_reset = left, limit, reset
    end
    windows[i] = {current, previous, started, next_debt}
    retention = math.max(retention, 2 * duration)
end
if not allowed then
    return {0, remaining, tight_limit, tight_reset, retry}
end
-- 只回收自然过期的索引成员；不能驱逐有效额度为新维度腾出名额。
local existing = redis.call('ZSCORE', KEYS[2], KEYS[1])
local expired = redis.call('ZCOUNT', KEYS[2], '-inf', physical_now)
if (not existing or tonumber(existing) <= physical_now) and redis.call('ZCARD', KEYS[2]) - expired >= capacity then
    return {-1}
end
local ttl = retention + now - physical_now + 1
local values = {'clock', string.format('%.0f', now)}
for i = 1, count do
    local state = windows[i]
    local current = state[1]
    if algorithm ~= 3 then
        current = current + cost
    end
    values[#values + 1], values[#values + 2] = i .. ':current', string.format('%.0f', current)
    values[#values + 1], values[#values + 2] = i .. ':previous', string.format('%.0f', state[2])
    values[#values + 1], values[#values + 2] = i .. ':start', string.format('%.0f', state[3])
    values[#values + 1], values[#values + 2] = i .. ':debt', string.format('%.0f', state[4])
end
-- 扣账与容量记录同一原子发布；所有写命令的键类型和数值范围均已通过预检。
-- ACL 对不同命令可授予不同权限；逐项先复验，避免扣账成功后到期或索引写入才遭拒绝。
if not redis.acl_check_cmd('HSET', KEYS[1], unpack(values))
    or not redis.acl_check_cmd('PEXPIRE', KEYS[1], ttl)
    or not redis.acl_check_cmd('ZREMRANGEBYSCORE', KEYS[2], '-inf', physical_now)
    or not redis.acl_check_cmd('ZADD', KEYS[2], physical_now + ttl, KEYS[1])
    or not redis.acl_check_cmd('PEXPIRE', KEYS[2], ttl + 1000) then
    return redis.error_reply('traffic ledger write authority unavailable')
end
local index_ttl = redis.call('PTTL', KEYS[2])
redis.call('HSET', KEYS[1], unpack(values))
redis.call('PEXPIRE', KEYS[1], ttl)
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', physical_now)
redis.call('ZADD', KEYS[2], physical_now + ttl, KEYS[1])
if index_ttl < ttl + 1000 then
    redis.call('PEXPIRE', KEYS[2], ttl + 1000)
end
if token then
    redis.call('ZREM', KEYS[3], token)
end
return {1, math.max(0, remaining - cost), tight_limit, tight_reset, 0}
