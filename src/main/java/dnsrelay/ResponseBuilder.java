package dnsrelay;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

/**
 * ResponseBuilder：构造各种类型的 DNS 响应报文，包括本地应答、Name Error、Server Failure。
 */
public class ResponseBuilder {

    /**
     * 构造本地应答报文（A或 AAAA记录）。
     *
     * @param reqHeader 客户端请求中的 DNS 头部
     * @param q         客户端请求中的 Question 部分
     * @param ip        要返回的 IP 地址字符串（IPv4 或 IPv6）
     * @return 构造好的 DNS 响应报文字节数组
     * @throws java.net.UnknownHostException 如果给定 IP无法解析为 InetAddress
     */
    public static byte[] buildLocalAnswer(DnsHeader reqHeader, DnsQuestion q, String ip) throws java.net.UnknownHostException {
        // 将字符串IP转换为字节数组（4 字节或 16 字节）
        byte[] ipBytes = InetAddress.getByName(ip).getAddress();

        // 根据IP字节长度选择A或AAAA记录构造方法
        DnsRecord record;
        if (ipBytes.length == 4) {
            // IPv4：TTL固定300秒
            record = DnsRecord.ofA(q.qName(), ipBytes, 300);
            // 打印解析后的IPv4地址，便于调试
            InetAddress ipv4 = InetAddress.getByAddress(record.rData());
            System.out.println(ipv4.getHostAddress());
        } else if (ipBytes.length == 16) {
            // IPv6：TTL固定300秒
            record = DnsRecord.ofAAAA(q.qName(), ipBytes, 300);
            // 打印解析后的IPv6地址，便于调试
            InetAddress ipv6 = InetAddress.getByAddress(record.rData());
            System.out.println(ipv6.getHostAddress());
        } else {
            // 非法长度直接抛错
            throw new IllegalArgumentException("非法IP地址长度: " + ipBytes.length);
        }

        // 构造响应头，将QR=1（响应）、AnCount=1，其它 counts 保持默认
        DnsHeader header = reqHeader.copyWithCounts(1, 0, 0);

        // 分配缓冲区并按网络字节序写入
        ByteBuffer buf = ByteBuffer.allocate(512).order(ByteOrder.BIG_ENDIAN);
        header.write(buf);   // 写入头部
        q.write(buf);        // 写入Question
        record.write(buf);   // 写入资源记录RDATA

        // 将缓冲区中已写入的数据复制到返回数组
        byte[] out = new byte[buf.position()];
        buf.flip();
        buf.get(out);
        return out;
    }

    /**
     * 构造 Name Error (RCODE=3) 响应报文，用于拦截本地表中值为 0.0.0.0 的域名。
     *
     * @param reqHeader 客户端请求中的 DNS 头部
     * @param q         客户端请求中的 Question 部分
     * @return 带有 RCODE=3 且不包含 Answer 部分的 DNS 响应报文
     */
    public static byte[] buildNameError(DnsHeader reqHeader, DnsQuestion q) {
        // 直接构造一个新的响应头：QR=1, RCODE=3, QD=1，其它 counts=0
        DnsHeader header = new DnsHeader(
                reqHeader.id(),  // 保持相同事务 ID
                true,            // QR=1 表示响应
                0,               // OPCODE 保持 0
                false,           // AA=false
                false,           // TC=false
                reqHeader.rd(),  // RD 保留客户端期望
                true,            // RA=true
                0,               // Z 保留位
                3,               // RCODE=3 Name Error
                1, 0, 0, 0       // QD=1, AN=0, NS=0, AR=0
        );

        // 写入头部和 Question，Answer 部分为空
        ByteBuffer buf = ByteBuffer.allocate(512)
                .order(ByteOrder.BIG_ENDIAN);
        header.write(buf);
        q.write(buf);

        // 返回已写入的字节
        byte[] out = new byte[buf.position()];
        buf.flip();
        buf.get(out);
        return out;
    }

    /**
     * 构造 Server Failure (RCODE=2) 响应报文，保留客户端原始 Question 部分。
     *
     * @param id        事务 ID，应与请求对应
     * @param origQuery 原始请求报文字节数组
     * @param len       原始请求长度
     * @return 带有 RCODE=2 的 DNS 响应报文（Question 区保持原样）
     */
    public static byte[] buildServFail(int id, byte[] origQuery, int len) {
        // 重新解析请求的头部和 Question
        ByteBuffer in = ByteBuffer.wrap(origQuery, 0, len).order(ByteOrder.BIG_ENDIAN);
        DnsHeader reqH = DnsHeader.parse(in);
        DnsQuestion q = DnsQuestion.parse(in);

        // 构造失败响应头：RCODE=2, QD=1，其它 counts=0
        DnsHeader respH = new DnsHeader(
                id,            // 保持事务 ID
                true,          // QR=1 响应
                0,             // OPCODE=0
                false,         // AA=false
                false,         // TC=false
                reqH.rd(),     // RD 保留原请求设置
                true,          // RA=true
                0,             // Z=0
                2,             // RCODE=2 Server Failure
                1, 0, 0, 0     // QD=1, AN=0, NS=0, AR=0
        );

        // 写入头部和 Question
        ByteBuffer out = ByteBuffer.allocate(512).order(ByteOrder.BIG_ENDIAN);
        respH.write(out);
        q.write(out);

        // 输出已写入的字节
        byte[] arr = new byte[out.position()];
        out.flip();
        out.get(arr);
        return arr;
    }
}
