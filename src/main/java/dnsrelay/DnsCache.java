package dnsrelay;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.Closeable;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * 轻量级可持久化 DNS 缓存
 * <p>
 * 功能：
 * 在内存中维护域名到 IP 地址列表的映射（支持 A/AAAA 多条记录）
 * 定期清理过期条目并写入磁盘
 * 启动时加载上次缓存，关闭时保存当前缓存
 * <p>
 * cache.txt：<domain> <ip> <expireEpochMs>
 */
public class DnsCache implements Closeable {

    /**
     * 默认 TTL（秒），当上游未提供 TTL 时使用
     */
    private static final int DEFAULT_TTL = 300;

    /**
     * 缓存文件路径
     */
    private final Path filePath;

    /**
     * 内存缓存：域名（小写）→ CacheEntry（IP 列表 + 过期时间）
     */
    private final Map<String, CacheEntry> table = new ConcurrentHashMap<>();

    /**
     * 后台清理&刷盘任务，每分钟执行一次
     */
    private final ScheduledExecutorService sweeper =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "DnsCache-Sweeper");
                t.setDaemon(true);
                return t;
            });

    /**
     * 构造函数：指定持久化文件名，加载历史缓存，启动定时任务
     *
     * @param fileName 缓存文件路径
     */
    public DnsCache(String fileName) {
        this.filePath = Paths.get(fileName);
        loadFromDisk();                       // 加载旧缓存
        // 每60秒清理过期、写回磁盘
        sweeper.scheduleAtFixedRate(
                this::flushExpired, 60, 60, TimeUnit.SECONDS);
    }

    /**
     * 查询缓存，返回第一个 IP（兼容旧接口）
     *
     * @param domain 域名（大小写不敏感）
     * @return 第一条 IP；缓存失效或不存在则返回 null
     */
    public String lookup(String domain) {
        CacheEntry e = table.get(domain.toLowerCase());
        if (e == null || e.expireMs < System.currentTimeMillis()) {
            table.remove(domain.toLowerCase());
            return null;
        }
        return e.firstIp();
    }

    /**
     * 查询缓存，返回所有存活 IP
     *
     * @param domain 域名（大小写不敏感）
     * @return IP 列表；无记录或全部过期则返回空列表
     */
    public List<String> lookupAll(String domain) {
        CacheEntry e = table.get(domain.toLowerCase());
        if (e == null || e.expireMs < System.currentTimeMillis()) {
            table.remove(domain.toLowerCase());
            return List.of();
        }
        return e.ips;
    }

    /**
     * 将一条记录写入缓存（追加去重），并设置过期时间
     *
     * @param domain 域名（不含末尾“.”，大小写不敏感）
     * @param ip     IPv4或 IPv6字符串
     * @param ttl    TTL秒数；<=0 时使用 DEFAULT_TTL
     */
    public void put(String domain, String ip, int ttl) {
        long expire = System.currentTimeMillis()
                + 1000L * (ttl > 0 ? ttl : DEFAULT_TTL);

        table.compute(domain.toLowerCase(), (k, old) -> {
            List<String> list = (old != null && old.expireMs >= System.currentTimeMillis())
                    ? new ArrayList<>(old.ips)
                    : new ArrayList<>();
            if (!list.contains(ip)) {
                list.add(ip);
            }
            return new CacheEntry(list, expire);
        });
    }

    /**
     * 清理过期条目并持久化到磁盘
     */
    private synchronized void flushExpired() {
        long now = System.currentTimeMillis();
        table.entrySet().removeIf(e -> e.getValue().expireMs < now);
        persistToDisk();
    }

    /**
     * 覆盖写入整个 table到文件
     */
    private void persistToDisk() {
        try (BufferedWriter bw = Files.newBufferedWriter(
                filePath,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING)) {
            for (var e : table.entrySet()) {
                String domain = e.getKey();
                long exp = e.getValue().expireMs;
                for (String ip : e.getValue().ips) {
                    bw.write(domain);
                    bw.write(' ');
                    bw.write(ip);
                    bw.write(' ');
                    bw.write(Long.toString(exp));
                    bw.newLine();
                }
            }
        } catch (IOException ioe) {
            System.err.println("[DnsCache] 写入缓存文件失败: " + ioe);
        }
    }

    /**
     * 启动时加载磁盘缓存到内存，忽略已过期或格式错误行
     */
    private void loadFromDisk() {
        if (!Files.exists(filePath)) {
            return;
        }
        try (BufferedReader br = Files.newBufferedReader(filePath)) {
            String line;
            long now = System.currentTimeMillis();
            while ((line = br.readLine()) != null) {
                String[] p = line.strip().split("\\s+");
                if (p.length != 3) continue;
                long exp = Long.parseLong(p[2]);
                if (exp > now) {
                    // 单行只包含一个 IP，后续 put()会追加更多
                    table.put(p[0].toLowerCase(),
                            new CacheEntry(List.of(p[1]), exp));
                }
            }
            System.out.printf("[DnsCache] 已加载 %d 条历史缓存%n", table.size());
        } catch (Exception e) {
            System.err.println("[DnsCache] 读取缓存文件出错: " + e);
        }
    }

    /**
     * 关闭缓存：停止后台线程并立即写盘
     */
    @Override
    public void close() {
        sweeper.shutdownNow();
        flushExpired();
    }

    /**
     * 单个域名对应的多条 IP及全局过期时间
     */
    private record CacheEntry(List<String> ips, long expireMs) {
        /**
         * 返回列表的第一条 IP，兼容旧接口
         */
        String firstIp() {
            return ips.get(0);
        }
    }
}
