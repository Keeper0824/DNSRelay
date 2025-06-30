package dnsrelay;

import java.nio.ByteBuffer;

/**
 * DnsHeader：表示一个 DNS 报文的头部字段。
 *
 * 字段说明：
 * @param id       事务 ID，用于匹配请求与响应
 * @param qr       查询/响应标志，true 表示响应，false 表示查询
 * @param opcode   操作码，4 位，通常为 0（标准查询）
 * @param aa       权威应答标志，true 表示权威回答
 * @param tc       截断标志，true 表示消息超过 UDP 限制而被截断
 * @param rd       递归期望，true 表示客户端希望服务器递归查询
 * @param ra       递归可用，true 表示服务器支持递归
 * @param z        保留位，3 位，必须为 0
 * @param rcode    响应码，4 位，0 表示无错误
 * @param qdCount  问题记录数
 * @param anCount  回答记录数
 * @param nsCount  授权记录数
 * @param arCount  附加记录数
 */
public record DnsHeader(
        int id,
        boolean qr,
        int opcode,
        boolean aa,
        boolean tc,
        boolean rd,
        boolean ra,
        int z,
        int rcode,
        int qdCount,
        int anCount,
        int nsCount,
        int arCount
) {

    /**
     * 从 ByteBuffer 中解析出一个 DnsHeader 实例。
     * 读取顺序：ID（2 字节），Flags（2 字节），各计数字段（各 2 字节）。
     *
     * @param buf 包含 DNS 头部的 ByteBuffer，position 应指向头部开始
     * @return 解析得到的 DnsHeader 对象
     */
    public static DnsHeader parse(ByteBuffer buf) {
        // 事务 ID（无符号 16 位）
        int id     = buf.getShort() & 0xFFFF;
        // Flags 字段，共 16 位
        int flags  = buf.getShort() & 0xFFFF;

        // 依次解析 Flags 中各子字段
        boolean qr   = ((flags >> 15) & 1) == 1;      // 第 15 位：查询/响应
        int     op   = (flags >> 11) & 0xF;           // 第 11-14 位：操作码
        boolean aa   = ((flags >> 10) & 1) == 1;      // 第 10 位：权威应答
        boolean tc   = ((flags >>  9) & 1) == 1;      // 第 9 位：截断
        boolean rd   = ((flags >>  8) & 1) == 1;      // 第 8 位：递归期望
        boolean ra   = ((flags >>  7) & 1) == 1;      // 第 7 位：递归可用
        int     z    = (flags >> 4) & 0x7;            // 第 4-6 位：保留位
        int     rcode= flags & 0xF;                   // 第 0-3 位：响应码

        // 依次读取问题、回答、授权、附加记录数
        int qd = buf.getShort() & 0xFFFF;
        int an = buf.getShort() & 0xFFFF;
        int ns = buf.getShort() & 0xFFFF;
        int ar = buf.getShort() & 0xFFFF;

        return new DnsHeader(id, qr, op, aa, tc, rd, ra, z, rcode, qd, an, ns, ar);
    }

    /**
     * 将当前 DnsHeader 写入到 ByteBuffer，用于构造 DNS 报文。
     * 写入顺序：ID（2 字节），Flags（2 字节），各计数字段（各 2 字节）。
     *
     * @param buf 用于写入的 ByteBuffer，position 应指向写入起始位置
     */
    public void write(ByteBuffer buf) {
        // 写入事务 ID
        buf.putShort((short) id);

        // 重新组合 Flags 字段
        int flags = 0;
        flags |= (qr   ? 1 : 0) << 15;
        flags |= (opcode & 0xF) << 11;
        flags |= (aa   ? 1 : 0) << 10;
        flags |= (tc   ? 1 : 0) << 9;
        flags |= (rd   ? 1 : 0) << 8;
        flags |= (ra   ? 1 : 0) << 7;
        flags |= (z    & 0x7) << 4;
        flags |= (rcode & 0xF);
        buf.putShort((short) flags);

        // 写入各记录计数
        buf.putShort((short) qdCount);
        buf.putShort((short) anCount);
        buf.putShort((short) nsCount);
        buf.putShort((short) arCount);
    }

    /**
     * 创建一个新的 DnsHeader，修改回答/授权/附加记录数，并将其他字段
     * 设为响应类型，供构造应答报文使用。
     *
     * @param an 回答记录数
     * @param ns 授权记录数
     * @param ar 附加记录数
     * @return 适合用于响应的 DnsHeader 实例
     */
    public DnsHeader copyWithCounts(int an, int ns, int ar) {
        // qr=true（响应），aa=false（非权威），ra=true（可递归），rcode=0（无错误）
        return new DnsHeader(
                id,
                true,      // 响应
                opcode,    // 操作码保持一致
                false,     // 非权威
                false,     // 不截断
                rd,        // 保留原始递归期望
                true,      // 递归可用
                0,         // 保留位
                0,         // 响应码：无错误
                qdCount,   // 问题数保持一致
                an,
                ns,
                ar
        );
    }
}
