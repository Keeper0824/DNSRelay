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

public class DnsRelayServer {
    private static final int DNS_PORT = 53;
    private static final int BUF_SIZE = 512;          // RFC 标准 UDP 长度
    private final Map<String, String> localTable = new HashMap<>();
    private final InetSocketAddress   upstream;
    private final DatagramSocket      socket;
    private final LogLevel logLevel;   // 新字段
    // DnsRelayServer.java  —— 其他字段旁边
    private final DatagramSocket upstreamSocket;  // 用随机端口做转发
    private ExecutorService executor = Executors.newCachedThreadPool();

    public DnsRelayServer(String upstreamIp, String tableFile,
                          LogLevel level) throws IOException {

        this.upstream = new InetSocketAddress(upstreamIp, DNS_PORT);
        this.logLevel = level;

        /* ---------- 横幅 1：上游 + Debug 级别 ---------- */
        System.out.printf("Name server %s:%d.%n", upstreamIp, DNS_PORT);
        System.out.printf("Debug level %d.%n", level.ordinal());

        /* ---------- 尝试绑定本地 53 ---------- */
        DatagramSocket tmp;
        try {
            tmp = new DatagramSocket(DNS_PORT);
            System.out.println("Bind UDP port 53 ...OK!");
        } catch (BindException be) {
            System.out.println("Bind UDP port 53 ...**** Fail to bind UDP port, Error " + be.getMessage());
            throw be;                           // 或者 System.exit(1);
        }
        this.socket = tmp;

        /* ---------- 上游 Socket 随机端口 ---------- */
        this.upstreamSocket = new DatagramSocket();

        /* ---------- 读取本地映射表 ---------- */
        int entryCnt = loadLocalTable(tableFile);     // 返回条目数
        if (entryCnt == -1) {
            System.out.printf("Try to load table \"%s\" ... Ignored!%n", tableFile);
        } else {
            int mem = localTable.entrySet().stream()  // 粗略估内存
                    .mapToInt(e -> e.getKey().length() + e.getValue().length() + 1)
                    .sum();
            System.out.printf("Try to load table \"%s\" ... OK%n", tableFile);
            System.out.printf("%d names, occupy %d bytes memory%n%n", entryCnt, mem);
        }

        /* 关机钩子省略 … */
    }



    public void start() throws IOException {
        byte[] buf = new byte[BUF_SIZE];
        while (true) {
            DatagramPacket packet = new DatagramPacket(buf, buf.length);
            socket.receive(packet);
            executor.submit(() -> {
                try {
                    handleQuery(packet); // 你自己的处理方法
                } catch (Exception e) {
                    // 打印异常到控制台或日志，防止线程崩溃
                    e.printStackTrace();
                    // 或者用日志框架 logger.error("DNS query error", e);
                }
            });

        }
    }

    private void handleQuery(DatagramPacket pkt) throws IOException {
        /* --- 解析请求 --- */
        ByteBuffer in = ByteBuffer.wrap(pkt.getData(), 0, pkt.getLength())
                .order(ByteOrder.BIG_ENDIAN);
        DnsHeader   reqHeader = DnsHeader.parse(in);
        DnsQuestion question  = DnsQuestion.parse(in);

        String clientIp = pkt.getAddress().getHostAddress();

        if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal()) {
            System.out.printf("← %-15s : %-30s (ID 0x%04X)%n",
                    clientIp, question.qName(), reqHeader.id());
        }

        /* --- 判断本地表 --- */
        String ip   = localTable.get(question.qName().toLowerCase());
        byte[] resp;
        if (ip != null && !"0.0.0.0".equals(ip)) {          // ★ 非 0.0.0.0 → 直答
            resp = ResponseBuilder.buildLocalAnswer(reqHeader, question, ip);

            if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal()) {
                System.out.printf("→ %-15s : local  %s%n", clientIp, ip);
            }

        } else if (ip != null) {                            // ★ 0.0.0.0 → 拦截
            resp = ResponseBuilder.buildNameError(reqHeader, question);

            if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal()) {
                System.out.printf("→ %-15s : BLOCK  (NameError)%n", clientIp);
            }

        } else {                                            // ★ 本地无记录 → 上游
            resp = forwardToUpstream(pkt.getData(), pkt.getLength(), reqHeader.id());

            if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal()) {
                System.out.printf("→ %-15s : upstream%n", clientIp);
            }
        }

        /* --- DEBUG 档十六进制 dump（如有需要） --- */
        if (logLevel == LogLevel.DEBUG) {
            dumpHex("REQ ", pkt.getData(), pkt.getLength());
            dumpHex("RESP", resp,            resp.length);
        }

        /* --- 把应答发回客户端 --- */
        socket.send(new DatagramPacket(resp, resp.length, pkt.getSocketAddress()));
    }


    /* ---------------- 上游转发，最简同步实现 ---------------- */
    private byte[] forwardToUpstream(byte[] query, int len, int id) {
        try {
            // ① 发送
            DatagramPacket upReq = new DatagramPacket(query, len, upstream);
            upstreamSocket.send(upReq);

            // ② 接收（2 s 超时）
            upstreamSocket.setSoTimeout(2000);
            byte[] buf = new byte[4096];
            DatagramPacket upResp = new DatagramPacket(buf, buf.length);
            upstreamSocket.receive(upResp);
            // ③ 把 ID 改回原始（保险）
            ByteBuffer.wrap(buf, 0, 2).putShort((short) id);
            return Arrays.copyOf(buf, upResp.getLength());

        } catch (SocketTimeoutException e) {        // ⭐ 捕获超时
            if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal()) {
                System.out.println("Upstream timeout, return SERVFAIL");
            }
            // 返回一个 SERVFAIL （RCODE=2）报文
            return ResponseBuilder.buildServFail(id, query, len);
        } catch (IOException ioe) {                 // 其他 IO 问题
            if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal()) {
                System.out.println("Upstream IO error: " + ioe);
            }
            return ResponseBuilder.buildServFail(id, query, len);
        }
    }

    private int loadLocalTable(String file) {
        InputStream in = getClass().getClassLoader().getResourceAsStream(file);
        if (in == null && !Files.exists(Path.of(file))) return -1;   // Ignored

        try (BufferedReader br = new BufferedReader(new InputStreamReader(
                in != null ? in : Files.newInputStream(Path.of(file)),
                StandardCharsets.UTF_8))) {

            String line;
            while ((line = br.readLine()) != null) {
                line = line.strip();
                if (line.isEmpty() || line.startsWith("#")) continue;
                String[] parts = line.split("\\s+");
                if (parts.length == 2)
                    localTable.put(parts[0].toLowerCase(), parts[1]);
            }
            return localTable.size();
        } catch (IOException e) {
            System.out.println("**** Error reading db-file: " + e);
            return -1;
        }
    }

    private static void dumpHex(String tag, byte[] buf, int len) {
        System.out.print(tag + " ");
        for (int i = 0; i < len; i++) {
            if (i % 16 == 0 && i != 0) System.out.println();
            System.out.printf("%02X ", buf[i]);
        }
        System.out.println();
    }
}


