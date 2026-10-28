-- 精确响应已先写入；这里只推进有界候选目录并续期，不把目录变成正文事实源。
redis.call('LPUSH', KEYS[1], ARGV[1]);
redis.call('LTRIM', KEYS[1], 0, tonumber(ARGV[2]) - 1);
redis.call('PEXPIRE', KEYS[1], ARGV[3]);
return 1
