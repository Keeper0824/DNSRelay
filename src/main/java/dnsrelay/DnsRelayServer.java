package dnsrelay;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * DnsRelayServer：一个简单的 DNS 中继服务器，实现本地缓存与上游转发功能。
 */
public class DnsRelayServer {
    /** 本地监听的 DNS 端口 */
    private static final int DNS_PORT = 53;
    /** UDP 报文缓冲区最大长度（符合 RFC 标准） */
    private static final int BUF_SIZE = 512;

    /** 本地 DNS 映射表：域名（小写）-> IP / 特殊值 */
    private final Map<String, String> localTable = new HashMap<>();
    /** 上游 DNS 服务器地址 */
    private final InetSocketAddress upstream;
    /** 用于接收客户端请求和发送响应的 Socket */
    private final DatagramSocket socket;
    /** 日志打印级别 */
    private final LogLevel logLevel;
    /** 用于向上游 DNS 转发请求的随机端口 Socket */
    private final DatagramSocket upstreamSocket;
    /** 异步线程池，用于并发处理客户端查询 */
    private ExecutorService executor = Executors.newCachedThreadPool();

    /**
     * 构造函数：初始化上游服务器、日志级别、绑定本地 53 端口、加载本地映射表
     *
     * @param upstreamIp 上游 DNS 服务器 IP 地址
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

        // 尝试绑定本地 UDP 53 端口
        DatagramSocket tmp;
        try {
            tmp = new DatagramSocket(DNS_PORT);
            System.out.println("Bind UDP port 53 ...OK!");
        } catch (BindException be) {
            System.out.println("Bind UDP port 53 ...**** Fail to bind UDP port, Error " + be.getMessage());
            throw be;
        }
        this.socket = tmp;

        // 初始化用于上游转发的随机端口 Socket
        this.upstreamSocket = new DatagramSocket();

        // 加载本地 DNS 映射表，返回条目数
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
    }

    /**
     * 启动服务器：循环接收客户端 UDP 报文并提交给线程池处理
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
     * 处理单个 DNS 查询：
     * 1. 解析请求头和问题部分
     * 2. 检查本地映射表，直答 / 拦截 / 转发
     * 3. 根据日志级别打印日志
     * 4. 发送响应给客户端
     *
     * @param pkt 客户端发送的 DatagramPacket
     * @throws IOException 如果发送/接收失败
     */
    private void handleQuery(DatagramPacket pkt) throws IOException {
        // 解析 DNS 报文
        ByteBuffer in = ByteBuffer.wrap(pkt.getData(), 0, pkt.getLength()).order(ByteOrder.BIG_ENDIAN);
        DnsHeader reqHeader = DnsHeader.parse(in);
        DnsQuestion question = DnsQuestion.parse(in);

        String clientIp = pkt.getAddress().getHostAddress();

        // 普通日志：打印收到的查询信息
        if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal()) {
            System.out.printf("← %-15s : %-30s (ID 0x%04X)%n",
                    clientIp, question.qName(), reqHeader.id());
        }

        // 查询本地映射表
        String ip = localTable.get(question.qName().toLowerCase());
        byte[] resp;

        if (ip != null && !"0.0.0.0".equals(ip)) {
            // 本地有记录且不是 0.0.0.0：直接返回 A 记录
            resp = ResponseBuilder.buildLocalAnswer(reqHeader, question, ip);
            if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal()) {
                System.out.printf("→ %-15s : local  %s%n", clientIp, ip);
            }
        } else if (ip != null) {
            // 本地记录为 0.0.0.0：返回 Name Error 拦截
            resp = ResponseBuilder.buildNameError(reqHeader, question);
            if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal()) {
                System.out.printf("→ %-15s : BLOCK  (NameError)%n", clientIp);
            }
        } else {
            // 本地无记录：转发给上游 DNS
            resp = forwardToUpstream(pkt.getData(), pkt.getLength(), reqHeader.id());
            if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal()) {
                System.out.printf("→ %-15s : upstream%n", clientIp);
            }
        }

        // 调试日志：打印十六进制数据包
        if (logLevel == LogLevel.DEBUG) {
            dumpHex("REQ ", pkt.getData(), pkt.getLength());
            dumpHex("RESP", resp, resp.length);
        }

        // 将响应发回客户端
        socket.send(new DatagramPacket(resp, resp.length, pkt.getSocketAddress()));
    }

    /**
     * 将查询报文同步转发到上游 DNS，等待响应并修正事务 ID
     *
     * @param query 原始查询报文字节数组
     * @param len   有效长度
     * @param id    原始事务 ID
     * @return 上游响应报文（若超时或出错，则返回 ServFail 报文）
     */
    private byte[] forwardToUpstream(byte[] query, int len, int id) {
        try {
            // ① 发送到上游
            DatagramPacket upReq = new DatagramPacket(query, len, upstream);
            upstreamSocket.send(upReq);

            // ② 等待上游响应，设置超时 2 秒
            upstreamSocket.setSoTimeout(2000);
            byte[] buf = new byte[4096];
            DatagramPacket upResp = new DatagramPacket(buf, buf.length);
            upstreamSocket.receive(upResp);

            // ③ 恢复原始事务 ID
            ByteBuffer.wrap(buf, 0, 2).putShort((short) id);
            return Arrays.copyOf(buf, upResp.getLength());

        } catch (SocketTimeoutException e) {
            // 超时返回 SERVFAIL
            if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal()) {
                System.out.println("Upstream timeout, return SERVFAIL");
            }
            return ResponseBuilder.buildServFail(id, query, len);

        } catch (IOException ioe) {
            // 其他 IO 错误也返回 SERVFAIL
            if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal()) {
                System.out.println("Upstream IO error: " + ioe);
            }
            return ResponseBuilder.buildServFail(id, query, len);
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

        try (BufferedReader br = new BufferedReader(new InputStreamReader(
                in != null ? in : Files.newInputStream(Path.of(file)),
                StandardCharsets.UTF_8))) {

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

    /**
     * 十六进制转储，用于调试
     *
     * @param tag 日志前缀
     * @param buf 字节数组
     * @param len 有效长度
     */
    private static void dumpHex(String tag, byte[] buf, int len) {
        System.out.print(tag + " ");
        for (int i = 0; i < len; i++) {
            if (i % 16 == 0 && i != 0) System.out.println();
            System.out.printf("%02X ", buf[i]);
        }
        System.out.println();
    }
}
