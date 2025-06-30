package dnsrelay;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public record DnsRecord(String name, int type, int clazz,
                        int ttl, byte[] rData) {

    /* ------------------ 工厂：构造 A 记录 ------------------ */
    public static DnsRecord ofA(String name, byte[] ipv4, int ttl) {
        return new DnsRecord(name, /*type*/ 1, /*class*/ 1, ttl, ipv4);
    }

    /* ------------------ 序列化写入 ------------------ */
    public void write(ByteBuffer buf) {
        /* 1) NAME —— 用标签序列，不要写 QTYPE/QCLASS */
        for (String label : name.split("\\.")) {
            buf.put((byte) label.length());
            buf.put(label.getBytes(StandardCharsets.US_ASCII));
        }
        buf.put((byte) 0);               // 结束 0

        /* 2) TYPE, CLASS, TTL, RDLENGTH, RDATA */
        buf.putShort((short) type);      // TYPE  = 1 (A)
        buf.putShort((short) clazz);     // CLASS = 1 (IN)
        buf.putInt(ttl);                 // TTL
        buf.putShort((short) rData.length);
        buf.put(rData);
    }

}

