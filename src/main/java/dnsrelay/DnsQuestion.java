package dnsrelay;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public record DnsQuestion(String qName, int qType, int qClass) {

    /* 解析 */
    public static DnsQuestion parse(ByteBuffer buf) {
        StringBuilder sb = new StringBuilder();
        while (true) {
            int len = buf.get() & 0xFF;
            if (len == 0) break;
            byte[] label = new byte[len];
            buf.get(label);
            sb.append(new String(label, StandardCharsets.US_ASCII)).append('.');
        }
        if (sb.length() > 0) sb.setLength(sb.length() - 1);   // 去掉末尾点

        int type  = buf.getShort() & 0xFFFF;
        int clazz = buf.getShort() & 0xFFFF;
        return new DnsQuestion(sb.toString(), type, clazz);
    }

    /* 写入 */
    public void write(ByteBuffer buf) {
        for (String part : qName.split("\\.")) {
            buf.put((byte) part.length());
            buf.put(part.getBytes(StandardCharsets.US_ASCII));
        }
        buf.put((byte) 0);          // 结束
        buf.putShort((short) qType);
        buf.putShort((short) qClass);
    }
}

