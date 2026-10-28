-- 回执与全部窗口同 slot 提交；终态封住迟到增量，任何预检失败都不能留下部分扣账。
if not redis.acl_check_cmd then
    return redis.error_reply('traffic settlement requires Redis ACL preflight capability')
end
-- 业务作用：拒绝坏账本中的负数、小数与超界数字，避免它们获得额度或退款权威。
-- 参数说明：
-- - value：配置参数或账本中待验证的数字。
-- - maximum：该字段允许的最大精确整数。
-- 返回：合法整数；非法字段返回 nil，调用方必须在写入前拒绝。
local function integer(value, maximum)
    local number = tonumber(value)
    if not number or number < 0 or number > maximum or number % 1 ~= 0 then
        return nil
    end
    return number
end
-- 业务作用：以十进制整数保存微秒时刻，避免科学计数法损失账本精度。
-- 参数说明：
-- - number：已经通过精确范围校验的整数。
-- 返回：可无损回读的十进制文本。
local function encoded(number)
    return string.format('%.0f', number)
end
local safe = 4503599627370496
local capacity = integer(ARGV[1], 1000000)
local mode = integer(ARGV[2], 2)
local cost = integer(ARGV[3], 4294967296)
local idle = integer(ARGV[4], 600000)
local maximum = integer(ARGV[5], 4294967296)
local count = integer(ARGV[6], 16)
local algorithm = integer(ARGV[7], 3)
if not capacity or capacity < 1 or not mode or not cost or not idle or idle < 1000
    or not maximum or maximum < 1 or cost > maximum or not count or count < 1
    or not algorithm or algorithm < 1 then
    return redis.error_reply('invalid traffic settlement arguments')
end
local state_type = redis.call('TYPE', KEYS[1]).ok
local index_type = redis.call('TYPE', KEYS[2]).ok
local receipt_type = redis.call('TYPE', KEYS[3]).ok
if (state_type ~= 'none' and state_type ~= 'hash') or (index_type ~= 'none' and index_type ~= 'zset')
    or (receipt_type ~= 'none' and receipt_type ~= 'hash') then
    return redis.error_reply('invalid traffic settlement state type')
end
local charged = 0
local reserved, last_base = cost, cost
if mode == 0 then
    if receipt_type ~= 'none' then
        return redis.error_reply('traffic settlement admission already exists')
    end
else
    -- 失去或过期的回执不能由响应帧重新创建；旧请求也不能借新账本取得退款权威。
    if receipt_type == 'none' or state_type == 'none' then
        return {-3}
    end
    local receipt = redis.call('HMGET', KEYS[3], 'charged', 'closed', 'reserved', 'last_base')
    charged = integer(receipt[1], maximum)
    local closed = integer(receipt[2], 1)
    reserved, last_base = integer(receipt[3], maximum), integer(receipt[4], maximum)
    if not charged or not closed or not reserved or not last_base or reserved > charged or last_base > charged then
        return redis.error_reply('invalid traffic settlement receipt')
    end
    if closed == 1 then
        if mode == 2 then
            return {1, 0, 0, 0, 0}
        end
        return {-3}
    end
    if last_base > reserved and cost < last_base then
        return redis.error_reply('traffic settlement observation regressed')
    end
end
local clock = redis.call('TIME')
local physical = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)
if physical < 0 or physical > 4500000000000 then
    return redis.error_reply('traffic settlement clock exceeds exact range')
end
local now = physical
if state_type == 'hash' then
    local previous = integer(redis.call('HGET', KEYS[1], 'clock'), safe)
    if not previous or previous - now > 60000 then
        return redis.error_reply('invalid traffic settlement clock')
    end
    now = math.max(now, previous)
end
local now_us = now * 1000 + tonumber(clock[2]) % 1000
local token = ARGV[8 + count * 3]
if token then
    if mode ~= 0 then
        return redis.error_reply('traffic settlement queue only admits new receipts')
    end
    local queue_type = redis.call('TYPE', KEYS[4]).ok
    if queue_type ~= 'none' and queue_type ~= 'zset' then
        return redis.error_reply('invalid traffic settlement queue')
    end
    local expires = redis.call('ZSCORE', KEYS[4], token)
    if not expires or tonumber(expires) <= physical then
        return {-3}
    end
    if not redis.acl_check_cmd('ZREM', KEYS[4], token) then
        return redis.error_reply('traffic settlement queue authority unavailable')
    end
end
local extra = math.max(0, cost - charged)
local refund = 0
if mode == 2 then
    refund = math.max(0, charged - cost)
end
local remaining, tight_limit, tight_reset, retry = safe, 0, 0, 0
local allowed = true
local retention = idle
local values = {'clock', encoded(now)}
local receipt_values = {'charged', encoded(math.max(charged, cost)), 'closed', mode == 2 and '1' or '0',
    'reserved', encoded(reserved), 'last_base', encoded(mode ~= 0 and extra > 0 and charged or last_base)}
for i = 1, count do
    local offset = 8 + (i - 1) * 3
    local limit = integer(ARGV[offset], 4294967296)
    local duration = integer(ARGV[offset + 1], 2678400000)
    local burst = integer(ARGV[offset + 2], 4294967296)
    if not limit or limit < 1 or not duration or duration < 1 or not burst
        or limit + burst > 4294967296 or (limit + burst) * duration > safe then
        return redis.error_reply('invalid traffic settlement window')
    end
    local prefix = i .. ':'
    local bound = math.floor(safe / duration)
    local current, previous, started, debt, shifted, epoch = 0, 0, now, 0, 0, 0
    if state_type == 'hash' then
        local state = redis.call('HMGET', KEYS[1], prefix .. 'current', prefix .. 'previous', prefix .. 'start',
            prefix .. 'debt', prefix .. 'shifted', prefix .. 'epoch')
        current, previous, started = integer(state[1], bound), integer(state[2], bound), integer(state[3], now)
        debt, shifted, epoch = integer(state[4], safe), integer(state[5], safe), integer(state[6], safe)
        if not current or not previous or not started or not debt or not shifted or not epoch then
            return redis.error_reply('invalid traffic settlement window state')
        end
    end
    local own_current, own_previous, own_start, own_end, own_shifted, own_epoch = 0, 0, started, 0, shifted, epoch
    local initial_end, initial_shifted, initial_epoch = 0, shifted, epoch
    if mode ~= 0 then
        local own = redis.call('HMGET', KEYS[3], prefix .. 'current', prefix .. 'previous', prefix .. 'start',
            prefix .. 'end', prefix .. 'shifted', prefix .. 'epoch', prefix .. 'initial_end',
            prefix .. 'initial_shifted', prefix .. 'initial_epoch')
        own_current, own_previous, own_start = integer(own[1], maximum), integer(own[2], maximum), integer(own[3], now)
        own_end, own_shifted, own_epoch = integer(own[4], safe), integer(own[5], safe), integer(own[6], safe)
        initial_end, initial_shifted, initial_epoch = integer(own[7], safe), integer(own[8], safe), integer(own[9], safe)
        if not own_current or not own_previous or not own_start or not own_end or not own_shifted or not own_epoch
            or not initial_end or not initial_shifted or not initial_epoch
            or own_current + own_previous > charged then
            return redis.error_reply('invalid traffic settlement window receipt')
        end
    end
    if now - started >= duration then
        previous = now - started >= 2 * duration and 0 or current
        current = 0
        started = started + math.floor((now - started) / duration) * duration
    end
    if now - own_start >= duration then
        own_previous = now - own_start >= 2 * duration and 0 or own_current
        own_current = 0
        own_start = own_start + math.floor((now - own_start) / duration) * duration
    end
    if own_start ~= started or own_current > current or own_previous > previous then
        return redis.error_reply('traffic settlement receipt does not match window')
    end
    local reset = duration - (now - started)
    local used, window_limit, wait = current, limit + burst, reset
    if algorithm == 2 then
        used = current + math.floor(previous * reset / duration)
        if previous > 0 then
            local excess = math.max(0, used + cost - window_limit)
            wait = excess >= previous and duration or math.ceil(excess * duration / previous)
        end
    elseif algorithm == 3 then
        if limit > duration * 1000 then
            return redis.error_reply('traffic settlement leaky interval is not representable')
        end
        local per_unit = math.ceil(duration * 1000 / limit)
        local outstanding = math.max(0, debt - now_us)
        window_limit = limit
        used = math.max(0, limit - math.floor(math.max(0, duration * 1000 - outstanding) / per_unit))
        wait = math.max(1, math.ceil((outstanding + per_unit * math.min(cost, limit) - duration * 1000) / 1000))
        if mode == 0 and (cost > limit or outstanding + per_unit * cost > duration * 1000) then
            allowed = false
            retry = math.max(retry, wait)
        end
        if extra > 0 then
            local increment = per_unit * extra
            -- 事实补扣可以超过准入额度，但最长未来债务仍有界，超界帧不能交付。
            if increment > 2678400000000 or outstanding + increment > 2678400000000 then
                return redis.error_reply('traffic settlement debt exceeds retention bound')
            end
            debt = math.max(debt, now_us) + increment
            own_end, own_shifted, own_epoch = debt, shifted, epoch
            if mode == 0 then
                initial_end, initial_shifted, initial_epoch = debt, shifted, epoch
            end
        elseif refund > 0 then
            -- 初始预留与最后一次未确认补扣可能被其它请求隔开，分别限定退款区间，不能跨越中间债务。
            local segments = {
                {initial_end, initial_shifted, initial_epoch, math.max(0, reserved - cost)},
                {own_end, own_shifted, own_epoch, math.max(0, charged - math.max(reserved, cost))}
            }
            for _, segment in ipairs(segments) do
                if segment[3] == epoch and segment[2] <= shifted then
                    local eligible = math.max(0, segment[1] - (shifted - segment[2]) - now_us)
                    local returned = math.min(segment[4] * per_unit, eligible, math.max(0, debt - now_us))
                    debt = debt - returned
                    -- 极长期累积位移达到整数边界时换代；旧代退款保守失效，绝不抵消新债务。
                    if shifted + returned > safe then
                        if epoch >= safe then
                            return redis.error_reply('traffic settlement refund epoch exhausted')
                        end
                        epoch, shifted = epoch + 1, 0
                    else
                        shifted = shifted + returned
                    end
                end
            end
        end
        retention = math.max(retention, math.ceil(math.max(0, debt - now_us) / 1000))
    end
    if algorithm ~= 3 then
        if mode == 0 and used + cost > window_limit then
            allowed = false
            retry = math.max(retry, wait)
        end
        if current + previous + extra > bound then
            return redis.error_reply('traffic settlement counter exceeds exact range')
        end
        current, own_current = current + extra, own_current + extra
        -- 先消费已经过期的退款份额，只能从本回执仍在当前或上一窗口的余额返还。
        local eligible = math.max(0, refund - (charged - own_current + extra - own_previous))
        local from_previous = math.min(eligible, own_previous)
        local from_current = math.min(eligible - from_previous, own_current)
        previous, own_previous = previous - from_previous, own_previous - from_previous
        current, own_current = current - from_current, own_current - from_current
    end
    local left = math.max(0, window_limit - used)
    if left < remaining then
        remaining, tight_limit, tight_reset = left, limit, reset
    end
    retention = math.max(retention, 2 * duration)
    local state_fields = {'current', 'previous', 'start', 'debt', 'shifted', 'epoch'}
    local state_values = {current, previous, started, debt, shifted, epoch}
    local own_fields = {'current', 'previous', 'start', 'end', 'shifted', 'epoch', 'initial_end', 'initial_shifted', 'initial_epoch'}
    local own_values = {own_current, own_previous, own_start, own_end, own_shifted, own_epoch, initial_end, initial_shifted, initial_epoch}
    for field = 1, 6 do
        values[#values + 1], values[#values + 2] = prefix .. state_fields[field], encoded(state_values[field])
    end
    for field = 1, 9 do
        receipt_values[#receipt_values + 1], receipt_values[#receipt_values + 2] = prefix .. own_fields[field], encoded(own_values[field])
    end
end
if not allowed then
    return {0, remaining, tight_limit, tight_reset, retry}
end
local expired = redis.call('ZCOUNT', KEYS[2], '-inf', physical)
local added = 0
for _, key in ipairs({KEYS[1], KEYS[3]}) do
    local indexed = redis.call('ZSCORE', KEYS[2], key)
    if not indexed or tonumber(indexed) <= physical then
        added = added + 1
    end
end
if redis.call('ZCARD', KEYS[2]) - expired + added > capacity then
    return {-1}
end
local ttl = retention + now - physical + 1
local receipt_ttl = mode == 2 and 1000 or idle
local index_ttl = redis.call('PTTL', KEYS[2])
-- Redis 脚本没有回滚；数据、回执、TTL、容量与队列写权限全部通过后才执行第一条写命令。
if not redis.acl_check_cmd('HSET', KEYS[1], unpack(values))
    or not redis.acl_check_cmd('HSET', KEYS[3], unpack(receipt_values))
    or not redis.acl_check_cmd('PEXPIRE', KEYS[1], ttl)
    or not redis.acl_check_cmd('PEXPIRE', KEYS[3], receipt_ttl)
    or not redis.acl_check_cmd('ZREMRANGEBYSCORE', KEYS[2], '-inf', physical)
    or not redis.acl_check_cmd('ZADD', KEYS[2], physical + ttl, KEYS[1], physical + receipt_ttl, KEYS[3])
    or not redis.acl_check_cmd('PEXPIRE', KEYS[2], ttl + 1000) then
    return redis.error_reply('traffic settlement write authority unavailable')
end
redis.call('HSET', KEYS[1], unpack(values))
redis.call('HSET', KEYS[3], unpack(receipt_values))
redis.call('PEXPIRE', KEYS[1], ttl)
redis.call('PEXPIRE', KEYS[3], receipt_ttl)
redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', physical)
redis.call('ZADD', KEYS[2], physical + ttl, KEYS[1], physical + receipt_ttl, KEYS[3])
if index_ttl < ttl + 1000 then
    redis.call('PEXPIRE', KEYS[2], ttl + 1000)
end
if token then
    redis.call('ZREM', KEYS[4], token)
end
return {1, math.max(0, remaining - (mode == 0 and cost or 0)), tight_limit, tight_reset, 0}
