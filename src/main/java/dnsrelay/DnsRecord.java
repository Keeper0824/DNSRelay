package dnsrelay;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * DnsRecord：表示 DNS 报文中的单条资源记录（Resource Record, RR）。
 * <p>
 *
 * @param name  记录对应的域名（不带末尾点）
 * @param type  记录类型（例如 1 = A，28 = AAAA）
 * @param clazz 记录类（通常为 1，表示 IN Internet 类）
 * @param ttl   生存时间（Time to Live），单位秒
 * @param rData 记录数据部分的原始字节（例如 IPv4 或 IPv6 地址）
 */
public record DnsRecord(String name, int type, int clazz,
                        int ttl, byte[] rData) {

    /**
     * 记录类型：A（IPv4 地址记录）
     */
    public static final int TYPE_A = 1;
    /**
     * 记录类型：AAAA（IPv6 地址记录）
     */
    public static final int TYPE_AAAA = 28;
    /**
     * 记录类：IN（Internet）
     */
    public static final int CLASS_IN = 1;

    /**
     * 创建一个 A 记录的辅助方法。
     *
     * @param name 域名
     * @param ipv4 4 字节的 IPv4 地址
     * @param ttl  生存时间
     * @return 对应的 DnsRecord 实例
     */
    public static DnsRecord ofA(String name, byte[] ipv4, int ttl) {
        return new DnsRecord(name, TYPE_A, CLASS_IN, ttl, ipv4);
    }

    /**
     * 创建一个 AAAA 记录的辅助方法。
     *
     * @param name 域名
     * @param ipv6 16 字节的 IPv6 地址
     * @param ttl  生存时间
     * @return 对应的 DnsRecord 实例
     */
    public static DnsRecord ofAAAA(String name, byte[] ipv6, int ttl) {
        return new DnsRecord(name, TYPE_AAAA, CLASS_IN, ttl, ipv6);
    }

    /**
     * 将当前资源记录写入到 ByteBuffer，用于构造 DNS响应报文。
     * <p>
     * 写入流程：
     * 1. 将域名按标签拆分，每段前写入长度字节，最后写入0结束。
     * 2. 写入2字节的 type、2字节的class、4字节的 TTL。
     * 3. 写入2字节的 RDATA长度、及对应的 RDATA字节。
     *
     * @param buf 用于写入的 ByteBuffer，position 应指向写入起始位置
     */
    public void write(ByteBuffer buf) {
        // 写入域名标签
        for (String label : name.split("\\.")) {
            byte[] bytes = label.getBytes(StandardCharsets.US_ASCII);
            buf.put((byte) bytes.length);   // 标签长度
            buf.put(bytes);                 // 标签内容
        }
        buf.put((byte) 0);  // 域名结束标志

        // 写入类型和类
        buf.putShort((short) type);   // TYPE：1 = A, 28 = AAAA
        buf.putShort((short) clazz);  // CLASS：1 = IN

        // 写入生存时间
        buf.putInt(ttl);

        // 写入 RDATA 长度和数据
        buf.putShort((short) rData.length);
        buf.put(rData);
    }
}
