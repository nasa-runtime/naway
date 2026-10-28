-- 每个候选和整个响应都有字节上限，超大成员跳过而不放大网关分配。
local out = {};
local total = 0;
local count = tonumber(ARGV[1]);
local each = tonumber(ARGV[2]);
local budget = tonumber(ARGV[3]);
for i = 0, count - 1 do
    local v = redis.call('LINDEX', KEYS[1], i);
    if not v then
        break
    end;
    local n = string.len(v);
    if n <= each and total + n <= budget then
        table.insert(out, v);
        total = total + n
    end
end;
return out
