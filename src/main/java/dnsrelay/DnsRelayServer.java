package dnsrelay;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class DnsRelayServer {
    private static final int DNS_PORT = 53;
    private static final int BUF_SIZE = 512;          // RFC 标准 UDP 长度
    private final Map<String, String> localTable = new HashMap<>();
    private final InetSocketAddress   upstream;
    private final DatagramSocket      socket;
    private final LogLevel logLevel;   // 新字段
    // DnsRelayServer.java  —— 其他字段旁边
    private final DatagramSocket upstreamSocket;  // 用随机端口做转发


    public DnsRelayServer(String upstreamIp, String tableFile,
                          LogLevel level) throws IOException {

        this.upstream = new InetSocketAddress(upstreamIp, DNS_PORT);

        /* 监听客户端查询的 Socket —— 无权限可把 DNS_PORT 改 1053 */
        this.socket = new DatagramSocket(DNS_PORT);

        /* 发往上游 DNS 的临时 Socket —— 用随机端口即可 */
        this.upstreamSocket = new DatagramSocket();

        this.logLevel = level;

        /* 读取本地映射表 */
        loadLocalTable(tableFile);

        if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal()) {
            System.out.println("Local table loaded, size=" + localTable.size());
        }

        /* 可选：关机时自动关闭两个 Socket */
    }


    public void start() throws IOException {
        byte[] buf = new byte[BUF_SIZE];
        while (true) {
            DatagramPacket pkt = new DatagramPacket(buf, buf.length);
            socket.receive(pkt);
            handleQuery(pkt);
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
                System.out.println("⚠ Upstream timeout, return SERVFAIL");
            }
            // 返回一个 SERVFAIL （RCODE=2）报文
            return ResponseBuilder.buildServFail(id, query, len);
        } catch (IOException ioe) {                 // 其他 IO 问题
            if (logLevel.ordinal() >= LogLevel.NORMAL.ordinal()) {
                System.out.println("⚠ Upstream IO error: " + ioe);
            }
            return ResponseBuilder.buildServFail(id, query, len);
        }
    }




    private void loadLocalTable(String file) throws IOException {
        try (BufferedReader br = new BufferedReader(new InputStreamReader(
                Objects.requireNonNull(getClass().getClassLoader().getResourceAsStream(file)),
                StandardCharsets.UTF_8))) {

            String line;
            while ((line = br.readLine()) != null) {
                line = line.strip();
                if (line.isEmpty() || line.startsWith("#")) continue;
                String[] parts = line.split("\\s+");
                if (parts.length == 2) localTable.put(parts[0].toLowerCase(), parts[1]);
            }
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


