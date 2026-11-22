-- 只移除自己持有的租约；丢失后重建的共享键也不能被旧释放清空。
if redis.call('TYPE', KEYS[1]).ok ~= 'zset' then
    return 0
end
return redis.call('ZREM', KEYS[1], ARGV[1])
