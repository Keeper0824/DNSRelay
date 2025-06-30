package dnsrelay;

import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.List;

/**
 * ResponseBuilder 用于构建本地 DNS响应报文
 * 支持多 IP返回、Name Error、Server Fail等场景
 */
public class ResponseBuilder {
    /**
     * 构建本地 DNS 应答报文，返回多个 A/AAAA记录
     *
     * @param reqHeader 原始请求头
     * @param q         原始请求的 Question
     * @param ips       本地 IP列表，可以包含 IPv4和 IPv6
     * @return 构建好的 DNS响应报文字节数组
     * @throws java.net.UnknownHostException IP 解析失败时抛出
     */
    public static byte[] buildLocalAnswer(DnsHeader reqHeader,
                                          DnsQuestion q,
                                          List<String> ips)
            throws java.net.UnknownHostException {

        // 校验ips列表不能为空
        if (ips == null || ips.isEmpty())
            throw new IllegalArgumentException("ips list is empty");

        // 根据返回IP数量构造新的 Header，ANCount = ips.size()
        DnsHeader header = reqHeader.copyWithCounts(ips.size(), 0, 0);

        // 准备512字节缓冲区，写入Header与Question
        ByteBuffer buf = ByteBuffer.allocate(512).order(ByteOrder.BIG_ENDIAN);
        header.write(buf);
        q.write(buf);

        // 遍历ips列表，写入每个IP对应的A或AAAA记录
        for (String ip : ips) {
            byte[] ipBytes = InetAddress.getByName(ip).getAddress();
            DnsRecord rr = (ipBytes.length == 4)
                    ? DnsRecord.ofA(q.qName(), ipBytes, 300)      // TTL = 300s
                    : DnsRecord.ofAAAA(q.qName(), ipBytes, 300);
            rr.write(buf);
        }

        // 将缓冲区中有效数据拷贝到数组并返回
        byte[] out = new byte[buf.position()];
        buf.flip();
        buf.get(out);
        return out;
    }

    /**
     * 构建单 IP 响应，内部调用多 IP 方法
     *
     * @param reqHeader 原始请求头
     * @param q         DNS 问题
     * @param ip        单个 IP
     */
    public static byte[] buildLocalAnswer(DnsHeader reqHeader,
                                          DnsQuestion q,
                                          String ip)
            throws java.net.UnknownHostException {
        // Java 9+ List.of 快速构造单元素列表
        return buildLocalAnswer(reqHeader, q, List.of(ip));
    }

    /**
     * 构建 Name Error 响应 (域名不存在)
     * RCODE = 3, ANCount = 1, 不返回具体数据，仅保留 Question
     *
     * @param reqHeader 原始请求头
     * @param q         DNS Question
     * @return Name Error 响应报文
     */
    public static byte[] buildNameError(DnsHeader reqHeader, DnsQuestion q) {
        // 强制设置 QR=1, AA=0, RD保持原值, RA=1, RCODE=3
        DnsHeader header = new DnsHeader(
                reqHeader.id(), true, 0,
                false, false, reqHeader.rd(),
                true, 0, 3,
                1, 0, 0, 0);

        // 写入Header与Question，不写Resource Record
        ByteBuffer buf = ByteBuffer.allocate(512).order(ByteOrder.BIG_ENDIAN);
        header.write(buf);
        q.write(buf);

        byte[] out = new byte[buf.position()];
        buf.flip();
        buf.get(out);
        return out;
    }

    /**
     * 构建 Server Fail 响应 (服务器故障)
     * 从原始请求报文中解析 Header 与 Question，并设置 RCODE=2
     *
     * @param id        返回给客户端的事务 ID
     * @param origQuery 原始查询报文字节
     * @param len       原始查询长度
     */
    public static byte[] buildServFail(int id, byte[] origQuery, int len) {
        // 从原始数据解析请求头和问询
        ByteBuffer in = ByteBuffer.wrap(origQuery, 0, len).order(ByteOrder.BIG_ENDIAN);
        DnsHeader reqH = DnsHeader.parse(in);
        DnsQuestion q = DnsQuestion.parse(in);

        // 构造响应 Header: QR=1, RD保持, RA=1, RCODE=2 (Server Fail)
        DnsHeader respH = new DnsHeader(
                id, true, 0,
                false, false, reqH.rd(),
                true, 0, 2,
                1, 0, 0, 0);

        // 写入响应Header与原Question
        ByteBuffer out = ByteBuffer.allocate(512).order(ByteOrder.BIG_ENDIAN);
        respH.write(out);
        q.write(out);

        // 返回有效字节
        byte[] arr = new byte[out.position()];
        out.flip();
        out.get(arr);
        return arr;
    }
}
