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
 * DnsRelayServer：一个简单的 DNS 中继服务器，实现本地缓存与上游转发功能。
 */
public class DnsRelayServer {
    /**
     * 本地监听的 DNS 端口
     */
    private static final int DNS_PORT = 53;
    /**
     * UDP 报文缓冲区最大长度（符合 RFC 标准）
     */
    private static final int BUF_SIZE = 512;

    /**
     * 本地 DNS 映射表：域名（小写）-> IP / 特殊值
     */
    private final Map<String, String> localTable = new HashMap<>();
    /**
     * 上游 DNS 服务器地址
     */
    private final InetSocketAddress upstream;
    /**
     * 用于接收客户端请求和发送响应的 Socket
     */
    private final DatagramSocket socket;
    /**
     * 日志打印级别
     */
    private final LogLevel logLevel;
    /**
     * 用于向上游DNS转发请求的随机端口Socket
     */
    private final DatagramSocket upstreamSocket;
    private final DnsCache cache = new DnsCache("cache.txt");
    /**
     * 异步线程池，用于并发处理客户端查询
     */
    private ExecutorService executor = Executors.newCachedThreadPool();


    /**
     * 构造函数：初始化上游服务器、日志级别、绑定本地53端口、加载本地映射表
     *
     * @param upstreamIp 上游DNS服务器IP地址
     * @param tableFile  本地映射表文件名
     * @param level      日志级别
     * @throws IOException 如果端口绑定或文件读取失败
     */
    public DnsRelayServer(String upstreamIp, String tableFile, LogLevel level) throws IOException {

        // 设置上游服务器地址
        this.upstream = new InetSocketAddress(upstreamIp, DNS_PORT);
        this.logLevel = level;

        // 打印横幅：显示上游服务器地址和日志级别
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

        // 加载本地DNS映射表，返回条目数
        int entryCnt = loadLocalTable(tableFile);
        if (entryCnt == -1) {
            // 文件不存在或读取失败，忽略本地表
            System.out.printf("Try to load table \"%s\" ... Ignored!%n", tableFile);
        } else {
            // 计算大致内存占用并打印加载结果
            int mem = localTable.entrySet().stream()
                    .mapToInt(e -> e.getKey().length() + e.getValue().length() + 1)
                    .sum();
            System.out.printf("Try to load table \"%s\" ... OK%n", tableFile);
            System.out.printf("%d names, occupy %d bytes memory%n%n", entryCnt, mem);
        }
        Runtime.getRuntime().addShutdownHook(new Thread(cache::close));

    }

    /**
     * 十六进制转储，用于调试
     *
     * @param tag 日志前缀
     * @param buf 字节数组
     * @param len 有效长度
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
     * 启动服务器：循环接收客户端 UDP报文并提交给线程池处理
     *
     * @throws IOException 如果接收报文失败
     */
    public void start() throws IOException {
        byte[] buf = new byte[BUF_SIZE];
        while (true) {
            // 接收客户端查询
            DatagramPacket packet = new DatagramPacket(buf, buf.length);
            socket.receive(packet);
            // 提交异步任务处理查询，避免阻塞主循环
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
     * 处理单个 DNS查询：
     * 1. 解析请求头和问题部分
     * 2. 检查本地映射表，直答 / 拦截 / 转发
     * 3. 根据日志级别打印日志
     * 4. 发送响应给客户端
     *
     * @param pkt 客户端发送的 DatagramPacket
     * @throws IOException 如果发送/接收失败
     */
    private void handleQuery(DatagramPacket pkt) throws IOException {
        // ---------- 解析请求 ----------
        ByteBuffer in = ByteBuffer.wrap(pkt.getData(), 0, pkt.getLength())
                .order(ByteOrder.BIG_ENDIAN);
        DnsHeader reqHeader = DnsHeader.parse(in);
        DnsQuestion question = DnsQuestion.parse(in);
        String clientIp = pkt.getAddress().getHostAddress();

        if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal()) {
            System.out.printf("← %-15s : %-30s (ID 0x%04X)%n",
                    clientIp, question.qName(), reqHeader.id());
        }

        int qType = question.qType();           // 1 = A, 28 = AAAA
        boolean wantV6 = (qType == DnsRecord.TYPE_AAAA);
        String ip = localTable.get(question.qName().toLowerCase());
        byte[] resp = null;                       // ← 先置空，防遗漏

        if (ip != null) {
            if ("0.0.0.0".equals(ip)) {              // 拦截条目
                resp = ResponseBuilder.buildNameError(reqHeader, question);
                if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal())
                    System.out.printf("→ %-15s : BLOCK  (NameError)%n", clientIp);
            } else {
                boolean isV6 = ip.indexOf(':') >= 0;
                if (isV6 == wantV6) {                // 类型匹配才直接回答
                    resp = ResponseBuilder.buildLocalAnswer(reqHeader, question, ip);
                    if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal())
                        System.out.printf("→ %-15s : local  %s%n", clientIp, ip);
                }
                // 类型不匹配就留给后面缓存/上游处理
            }
        }

        if (resp == null) {
            // 先拿出缓存里的所有条目（拷贝成可变列表）
            List<String> ips = new ArrayList<>(cache.lookupAll(question.qName()));

            // 只保留当前请求类型（A / AAAA）
            ips.removeIf(addr -> (addr.indexOf(':') >= 0) != wantV6);

            if (!ips.isEmpty()) {
                // 多条一起打包回 Answer
                resp = ResponseBuilder.buildLocalAnswer(reqHeader, question, ips);

                if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal())
                    System.out.printf("→ %-15s : cache   %s (%d RRs)%n",
                            clientIp, ips.get(0), ips.size());
            }
        }
        if (resp == null) {
            resp = forwardToUpstream(pkt.getData(), pkt.getLength(),
                    reqHeader.id(), question);
            if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal())
                System.out.printf("→ %-15s : upstream%n", clientIp);
        }
        socket.send(new DatagramPacket(resp, resp.length, pkt.getSocketAddress()));

        if (logLevel == LogLevel.DEBUG) {
            dumpHex("REQ ", pkt.getData(), pkt.getLength());
            dumpHex("RESP", resp, resp.length);
        }
    }


    /**
     * 将查询报文同步转发到上游 DNS，等待响应并修正事务 ID
     *
     * @param query 原始查询报文字节数组
     * @param len   有效长度
     * @param id    原始事务 ID
     * @return 上游响应报文（若超时或出错，则返回 ServFail 报文）
     */
    private byte[] forwardToUpstream(byte[] query, int len,
                                     int id, DnsQuestion q) {

        try {
            /* ① 发送到上游 */
            DatagramPacket upReq = new DatagramPacket(query, len, upstream);
            upstreamSocket.send(upReq);

            /* ② 接收上游响应（2 s 超时） */
            upstreamSocket.setSoTimeout(2000);
            byte[] buf = new byte[4096];
            DatagramPacket upResp = new DatagramPacket(buf, buf.length);
            upstreamSocket.receive(upResp);

            /* ③ 把事务 ID 改回客户端原值 */
            ByteBuffer.wrap(buf, 0, 2).putShort((short) id);
            byte[] resp = Arrays.copyOf(buf, upResp.getLength());

            /* ④ 把好用的记录写进缓存 */
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

    private void cacheByAnswer(byte[] resp, String domain) {
        try {
            ByteBuffer buf = ByteBuffer.wrap(resp).order(ByteOrder.BIG_ENDIAN);
            DnsHeader h = DnsHeader.parse(buf);
            if (h.anCount() == 0) return;

            /* 跳过 Question 区 */
            DnsQuestion.parse(buf);

            // ===== 这段 for 循环内部改成下面这样 =====
            for (int i = 0; i < h.anCount(); i++) {
                /* 读取 NAME（指针或标签序列） */
                int len;
                while (((len = buf.get() & 0xFF) != 0)) {
                    if ((len & 0xC0) == 0xC0) {   // 压缩指针
                        buf.get();                // 再吃一个字节
                        break;
                    } else {
                        buf.position(buf.position() + len);
                    }
                }

                int type = buf.getShort() & 0xFFFF;
                int clazz = buf.getShort() & 0xFFFF;
                int ttl = buf.getInt();
                int rdLen = buf.getShort() & 0xFFFF;

                if (clazz == DnsRecord.CLASS_IN &&
                        (type == DnsRecord.TYPE_A || type == DnsRecord.TYPE_AAAA)) {

                    byte[] rdata = new byte[rdLen];
                    buf.get(rdata);
                    String ip = InetAddress.getByAddress(rdata).getHostAddress();
                    cache.put(domain, ip, ttl);            // ← 多次插入，内部去重

                    if (logLevel == LogLevel.DEBUG)
                        System.out.printf("[CACHE ADD] %s -> %s (ttl %d)%n", domain, ip, ttl);
                    continue;                              // 继续扫下一条 Answer
                } else {
                    buf.position(buf.position() + rdLen);   // 跳过非 A/AAAA
                }
            }
        } catch (Exception ignore) {
        }
    }

    /**
     * 加载本地 DNS 映射表文件，每行格式：<域名> <IP>
     *
     * @param file 文件名或资源路径
     * @return 成功加载的条目数，-1 表示忽略或错误
     */
    private int loadLocalTable(String file) {
        // 尝试从 classpath 资源加载
        InputStream in = getClass().getClassLoader().getResourceAsStream(file);
        // 如果既不是资源也不存在文件，则忽略
        if (in == null && !Files.exists(Path.of(file))) return -1;

        try (BufferedReader br = new BufferedReader(new InputStreamReader(in))) {

            String line;
            while ((line = br.readLine()) != null) {
                line = line.strip();
                // 跳过空行与注释
                if (line.isEmpty() || line.startsWith("#")) continue;
                String[] parts = line.split("\\s+");
                // 格式正确时加入映射表
                if (parts.length == 2)
                    localTable.put(parts[0].toLowerCase(), parts[1]);
            }
            return localTable.size();
        } catch (IOException e) {
            System.out.println("**** Error reading db-file: " + e);
            return -1;
        }
    }
}
