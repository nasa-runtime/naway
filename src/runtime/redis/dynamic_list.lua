-- 集合目录必须有界；超过调用方容量时整次枚举失败，不返回不完整事实集。
local cursor = '0'
local out = { }
local max = tonumber(ARGV[1])
repeat
    local page = redis.call('HSCAN', KEYS[1], cursor, 'COUNT', 1000)
    cursor = page[1]
    local entries = page[2]
    for i = 1, #entries, 2 do
        if #out >= max then
            return redis.error_reply('dynamic store collection key limit exceeded')
        end
        out[#out + 1] = entries[i]
    end
until cursor == '0'
return out
