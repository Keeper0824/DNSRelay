package dnsrelay;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class ResponseBuilder {
    /* ---------- 正常 A 记录答复 ---------- */
// 1️⃣ 方法签名尾部加 throws UnknownHostException
    public static byte[] buildLocalAnswer(DnsHeader reqHeader,
                                          DnsQuestion q,
                                          String ip) throws java.net.UnknownHostException {

        byte[] ipBytes = java.net.InetAddress.getByName(ip).getAddress();

        DnsRecord record;

        if (ipBytes.length == 4) {
            record = DnsRecord.ofA(q.qName(), ipBytes, 300);
            InetAddress ipv4 = InetAddress.getByAddress(record.rData());
            System.out.println(ipv4.getHostAddress());
        } else if (ipBytes.length == 16) {
            record = DnsRecord.ofAAAA(q.qName(), ipBytes, 300); // 👈用type=28
            InetAddress ipv6 = InetAddress.getByAddress(record.rData());
            System.out.println(ipv6.getHostAddress());
        } else {
            throw new IllegalArgumentException("非法IP地址长度: " + ipBytes.length);
        }


        DnsHeader header = reqHeader.copyWithCounts(1, 0, 0);

        ByteBuffer buf = ByteBuffer.allocate(512).order(ByteOrder.BIG_ENDIAN);
        header.write(buf);
        q.write(buf);
        record.write(buf);

        byte[] out = new byte[buf.position()];
        buf.flip();
        buf.get(out);
        return out;
    }


    /* ---------- Name Error (RCODE = 3) ---------- */
    public static byte[] buildNameError(DnsHeader reqHeader, DnsQuestion q) {
        DnsHeader header = new DnsHeader(reqHeader.id(), true, 0, false,
                false, reqHeader.rd(), true, 0, 3,   // RCODE=3
                1, 0, 0, 0);
        ByteBuffer buf = ByteBuffer.allocate(512).order(java.nio.ByteOrder.BIG_ENDIAN);
        header.write(buf);
        q.write(buf);
        byte[] out = new byte[buf.position()];
        buf.flip();
        buf.get(out);
        return out;
    }

    /* 构造 Server Failure (RCODE=2) 应答——保持 Question 区原样 */
    public static byte[] buildServFail(int id, byte[] origQuery, int len) {
        ByteBuffer in  = ByteBuffer.wrap(origQuery, 0, len).order(ByteOrder.BIG_ENDIAN);
        DnsHeader reqH = DnsHeader.parse(in);
        DnsQuestion q  = DnsQuestion.parse(in);

        DnsHeader respH = new DnsHeader(id, true, 0, false, false,
                reqH.rd(), true, 0, 2, // RCODE=2
                1, 0, 0, 0);

        ByteBuffer out = ByteBuffer.allocate(512).order(ByteOrder.BIG_ENDIAN);
        respH.write(out);
        q.write(out);
        byte[] arr = new byte[out.position()];
        out.flip(); out.get(arr);
        return arr;
    }

}

