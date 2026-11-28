-- 返回原始十进制文本，避免 Lua 浮点数舍入高位代次并让旧实体再次命中。
return redis.call('GET', KEYS[1]) or '0'
