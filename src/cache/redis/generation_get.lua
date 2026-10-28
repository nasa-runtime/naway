-- 缺失的失效代号按初始代处理，实体自身的保留期仍由缓存合同约束。
local v = redis.call('GET', KEYS[1]);
if not v then
    return 0
else
    return tonumber(v)
end
