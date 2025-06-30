package dnsrelay;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * 单条资源记录（RR）
 */
public record DnsRecord(String name, int type, int clazz,
                        int ttl, byte[] rData) {

    /* ========== 新增常量 ========== */
    public static final int TYPE_A    = 1;   // IPv4
    public static final int TYPE_AAAA = 28;  // IPv6
    public static final int CLASS_IN  = 1;   // Internet

    /* ---------- 工厂：A ---------- */
    public static DnsRecord ofA(String name, byte[] ipv4, int ttl) {
        return new DnsRecord(name, TYPE_A, CLASS_IN, ttl, ipv4);
    }

    /* ---------- 新增工厂：AAAA ---------- */
    public static DnsRecord ofAAAA(String name, byte[] ipv6, int ttl) {
        return new DnsRecord(name, TYPE_AAAA, CLASS_IN, ttl, ipv6);
    }

    /* ---------- 序列化写入 ---------- */
    public void write(ByteBuffer buf) {
        /* 1) NAME —— 标签序列 */
        for (String label : name.split("\\.")) {
            buf.put((byte) label.length());
            buf.put(label.getBytes(StandardCharsets.US_ASCII));
        }
        buf.put((byte) 0);  // 结束 0

        /* 2) TYPE, CLASS, TTL, RDLENGTH, RDATA */
        buf.putShort((short) type);   // TYPE：1=A，28=AAAA
        buf.putShort((short) clazz);  // CLASS：1=IN
        buf.putInt(ttl);              // TTL
        buf.putShort((short) rData.length);
        buf.put(rData);
    }
}
