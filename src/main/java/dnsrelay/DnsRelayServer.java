package dnsrelay;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * DnsRelayServer：一个简单的 DNS 中继服务器，
 * 实现本地缓存、静态映射表拦截/重定向，以及上游转发功能。
 */
public class DnsRelayServer {
    /**
     * 本地监听的 DNS端口（53）
     */
    private static final int DNS_PORT = 53;
    /**
     * UDP报文缓冲区最大长度（符合 RFC规范的 512字节）
     */
    private static final int BUF_SIZE = 512;

    /**
     * 本地静态映射表：域名（全小写） -> IP地址 或 特殊值“0.0.0.0”
     */
    private final Map<String, String> localTable = new HashMap<>();
    /**
     * 上游 DNS服务器的地址（IP + 端口）
     */
    private final InetSocketAddress upstream;
    /**
     * 用于接收客户端请求和发送响应的 UDP Socket，绑定本地 53 端口
     */
    private final DatagramSocket socket;
    /**
     * 日志打印级别（NONE, NORMAL, DEBUG）
     */
    private final LogLevel logLevel;
    /**
     * 用于向上游 DNS转发请求的随机端口 UDP Socket
     */
    private final DatagramSocket upstreamSocket;
    /**
     * 本地缓存：将 A/AAAA记录缓存到文件，支持查询和过期管理
     */
    private final DnsCache cache = new DnsCache("cache.txt");
    /**
     * 异步线程池，用于并发处理客户端的查询请求
     */
    private ExecutorService executor = Executors.newCachedThreadPool();

    /**
     * 构造函数：
     * 1. 设置上游服务器地址 & 日志级别
     * 2. 绑定本地 53端口
     * 3. 加载静态映射表（resource或文件）
     * 4. 注册 JVM退出钩子，关闭缓存文件
     */
    public DnsRelayServer(String upstreamIp, String tableFile, LogLevel level) throws IOException {
        this.upstream = new InetSocketAddress(upstreamIp, DNS_PORT);
        this.logLevel = level;

        // 打印启动横幅
        System.out.printf("Name server %s:%d.%n", upstreamIp, DNS_PORT);
        System.out.printf("Debug level %d.%n", level.ordinal());

        // 尝试绑定本地UDP_53端口
        DatagramSocket tmp;
        try {
            tmp = new DatagramSocket(DNS_PORT);
            System.out.println("Bind UDP port 53 ...OK!");
        } catch (BindException be) {
            System.out.println("Bind UDP port 53 ...**** Fail to bind UDP port, Error " + be.getMessage());
            throw be;
        }
        this.socket = tmp;

        // 初始化用于上游转发的随机端口Socket
        this.upstreamSocket = new DatagramSocket();

        // 加载本地映射表，打印加载结果
        int entryCnt = loadLocalTable(tableFile);
        if (entryCnt == -1) {
            System.out.printf("Try to load table \"%s\" ... Ignored!%n", tableFile);
        } else {
            int mem = localTable.entrySet().stream()
                    .mapToInt(e -> e.getKey().length() + e.getValue().length() + 1)
                    .sum();
            System.out.printf("Try to load table \"%s\" ... OK%n", tableFile);
            System.out.printf("%d names, occupy %d bytes memory%n%n", entryCnt, mem);
        }

        // 注册退出钩子，确保缓存文件正确关闭
        Runtime.getRuntime().addShutdownHook(new Thread(cache::close));
    }

    /**
     * dumpHex：调试用，十六进制转储输出
     *
     * @param tag 标记输出前缀
     * @param buf 数据缓冲区
     * @param len 有效字节数
     */
    private static void dumpHex(String tag, byte[] buf, int len) {
        System.out.println(tag + ": ");
        for (int i = 0; i < len; i++) {
            if (i % 16 == 0 && i != 0) System.out.println();
            System.out.printf("%02X ", buf[i]);
        }
        System.out.println();
    }

    /**
     * 启动服务器主循环：
     * 不断接收 UDP报文，并提交给线程池异步处理
     */
    public void start() throws IOException {
        byte[] buf = new byte[BUF_SIZE];
        while (true) {
            DatagramPacket packet = new DatagramPacket(buf, buf.length);
            socket.receive(packet);  // 阻塞等待客户端查询
            executor.submit(() -> {
                try {
                    handleQuery(packet);
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        }
    }

    /**
     * 处理单个 DNS 查询：
     * 1. 解析请求头 + 问题区
     * 2. 本地静态表直答 / 拦截
     * 3. 缓存命中则回答缓存
     * 4. 否则转发到上游，修正事务 ID，缓存回答
     * 5. 根据日志级别选择性打印详细信息
     */
    private void handleQuery(DatagramPacket pkt) throws IOException {
        // 解析请求头和问题部分
        ByteBuffer in = ByteBuffer.wrap(pkt.getData(), 0, pkt.getLength())
                .order(ByteOrder.BIG_ENDIAN);
        DnsHeader reqHeader = DnsHeader.parse(in);
        DnsQuestion question = DnsQuestion.parse(in);
        String clientIp = pkt.getAddress().getHostAddress();

        if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal()) {
            System.out.printf("← %-15s : %-30s (ID 0x%04X)%n",
                    clientIp, question.qName(), reqHeader.id());
        }

        int qType = question.qType();           // 1=A, 28=AAAA
        boolean wantV6 = (qType == DnsRecord.TYPE_AAAA);
        String ip = localTable.get(question.qName().toLowerCase());
        byte[] resp = null;

        // 静态映射表处理
        if (ip != null) {
            if ("0.0.0.0".equals(ip)) {
                // 拦截规则，返回 Name Error
                resp = ResponseBuilder.buildNameError(reqHeader, question);
                if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal())
                    System.out.printf("→ %-15s : BLOCK  (NameError)%n", clientIp);
            } else {
                boolean isV6 = ip.contains(":");
                // 类型匹配才直接回答
                if (isV6 == wantV6) {
                    resp = ResponseBuilder.buildLocalAnswer(reqHeader, question, ip);
                    if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal())
                        System.out.printf("→ %-15s : local  %s%n", clientIp, ip);
                }
            }
        }

        // 缓存处理
        if (resp == null) {
            List<String> ips = new ArrayList<>(cache.lookupAll(question.qName()));
            ips.removeIf(addr -> addr.contains(":") != wantV6);
            if (!ips.isEmpty()) {
                resp = ResponseBuilder.buildLocalAnswer(reqHeader, question, ips);
                if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal())
                    System.out.printf("→ %-15s : cache   %s (%d RRs)%n",
                            clientIp, ips.get(0), ips.size());
            }
        }

        // 上游转发
        if (resp == null) {
            resp = forwardToUpstream(pkt.getData(), pkt.getLength(),
                    reqHeader.id(), question);
            if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal())
                System.out.printf("→ %-15s : upstream%n", clientIp);
        }

        // 发送响应
        socket.send(new DatagramPacket(resp, resp.length, pkt.getSocketAddress()));

        // DEBUG 级别下打印完整报文
        if (logLevel == LogLevel.DEBUG) {
            dumpHex("REQ ", pkt.getData(), pkt.getLength());
            dumpHex("RESP", resp, resp.length);
        }
    }

    /**
     * 同步转发到上游 DNS：
     * 发送请求
     * 接收响应（2s 超时）
     * 修正事务 ID
     * 缓存 A/AAAA 记录
     * 如果超时或错误，返回 SERVFAIL 报文
     */
    private byte[] forwardToUpstream(byte[] query, int len,
                                     int id, DnsQuestion q) {
        try {
            DatagramPacket upReq = new DatagramPacket(query, len, upstream);
            upstreamSocket.send(upReq);

            upstreamSocket.setSoTimeout(2000);
            byte[] buf = new byte[4096];
            DatagramPacket upResp = new DatagramPacket(buf, buf.length);
            upstreamSocket.receive(upResp);

            // 修正 ID 并截取有效长度
            ByteBuffer.wrap(buf, 0, 2).putShort((short) id);
            byte[] resp = Arrays.copyOf(buf, upResp.getLength());

            // 缓存回答中的 A/AAAA 记录
            cacheByAnswer(resp, q.qName());
            return resp;

        } catch (SocketTimeoutException e) {
            if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal())
                System.out.println("Upstream timeout, return SERVFAIL");
            return ResponseBuilder.buildServFail(id, query, len);

        } catch (IOException ioe) {
            if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal())
                System.out.println("Upstream IO error: " + ioe);
            return ResponseBuilder.buildServFail(id, query, len);
        }
    }

    /**
     * 从上游响应报文中提取 A/AAAA 记录，写入本地缓存
     */
    private void cacheByAnswer(byte[] resp, String domain) {
        try {
            ByteBuffer buf = ByteBuffer.wrap(resp).order(ByteOrder.BIG_ENDIAN);
            DnsHeader h = DnsHeader.parse(buf);
            if (h.anCount() == 0) return;

            // 跳过 Question 区
            DnsQuestion.parse(buf);

            for (int i = 0; i < h.anCount(); i++) {
                // 跳过 NAME（标签或指针）
                int len;
                while (((len = buf.get() & 0xFF) != 0)) {
                    if ((len & 0xC0) == 0xC0) {
                        buf.get(); // 压缩指针：再跳过一个字节
                        break;
                    } else {
                        buf.position(buf.position() + len);
                    }
                }

                int type = buf.getShort() & 0xFFFF;
                int clazz = buf.getShort() & 0xFFFF;
                int ttl = buf.getInt();
                int rdLen = buf.getShort() & 0xFFFF;

                // 只缓存 IN 类别下的 A/AAAA
                if (clazz == DnsRecord.CLASS_IN &&
                        (type == DnsRecord.TYPE_A || type == DnsRecord.TYPE_AAAA)) {

                    byte[] rdata = new byte[rdLen];
                    buf.get(rdata);
                    String ip = InetAddress.getByAddress(rdata).getHostAddress();
                    cache.put(domain, ip, ttl); // 多次插入内部去重

                    if (logLevel == LogLevel.DEBUG)
                        System.out.printf("[CACHE ADD] %s -> %s (ttl %d)%n", domain, ip, ttl);
                    continue;
                } else {
                    // 跳过其他类型的 RDATA
                    buf.position(buf.position() + rdLen);
                }
            }
        } catch (Exception ignore) {
            // 忽略解析错误，防止缓存过程影响主流程
        }
    }

    /**
     * 加载本地静态映射表：
     * 文件或 classpath 资源，每行：<域名> <IP>
     * 支持注释（# 开头）和空行
     */
    private int loadLocalTable(String file) {
        InputStream in = getClass().getClassLoader().getResourceAsStream(file);
        if (in == null && !Files.exists(Path.of(file))) return -1;

        try (BufferedReader br = new BufferedReader(
                in != null
                        ? new InputStreamReader(in)
                        : Files.newBufferedReader(Path.of(file))
        )) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.strip();
                if (line.isEmpty() || line.startsWith("#")) continue;
                String[] parts = line.split("\\s+");
                if (parts.length == 2) {
                    localTable.put(parts[0].toLowerCase(), parts[1]);
                }
            }
            return localTable.size();
        } catch (IOException e) {
            System.out.println("**** Error reading db-file: " + e);
            return -1;
        }
    }
}
