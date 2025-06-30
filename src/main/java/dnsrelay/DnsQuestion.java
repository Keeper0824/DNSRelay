package dnsrelay;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

/**
 * DnsQuestion：表示 DNS 报文中的 Question 部分。
 *
 * @param qName  查询的域名（不带末尾点）
 * @param qType  查询类型（例如 1=A，28=AAAA）
 * @param qClass 查询类（通常为 1，表示 IN 类）
 */
public record DnsQuestion(String qName, int qType, int qClass) {

    /**
     * 从 ByteBuffer 中解析出一个 DnsQuestion 实例。
     * <p>
     * 解析流程：
     * 1. 读取域名：以长度字节开头的标签序列，最后以 0 长度结束。
     * 2. 将标签用点号拼接成完整域名。
     * 3. 读取 2 字节查询类型和 2 字节查询类。
     *
     * @param buf 包含 Question 部分的 ByteBuffer，position 应指向域名起始处
     * @return 解析得到的 DnsQuestion 对象
     */
    public static DnsQuestion parse(ByteBuffer buf) {
        // 用于拼接域名各标签
        StringBuilder sb = new StringBuilder();
        while (true) {
            // 读取下一段标签长度（无符号）
            int len = buf.get() & 0xFF;
            // 长度为 0 表示域名末尾
            if (len == 0) break;
            // 读取标签内容
            byte[] label = new byte[len];
            buf.get(label);
            // 按 ASCII 编码将标签转换为字符串并追加点号
            sb.append(new String(label, StandardCharsets.US_ASCII)).append('.');
        }
        // 去除最后一个多余的点号
        if (sb.length() > 0) {
            sb.setLength(sb.length() - 1);
        }

        // 读取查询类型和查询类（各 2 字节无符号）
        int type  = buf.getShort() & 0xFFFF;
        int clazz = buf.getShort() & 0xFFFF;
        return new DnsQuestion(sb.toString(), type, clazz);
    }

    /**
     * 将当前 DnsQuestion 写入到 ByteBuffer，用于构造 DNS 查询报文。
     * <p>
     * 写入流程：
     * 1. 将域名按标签拆分，每段前写入长度字节，最后写入 0 表示结束。
     * 2. 写入 2 字节查询类型和 2 字节查询类。
     *
     * @param buf 用于写入的 ByteBuffer，position 应指向写入起始位置
     */
    public void write(ByteBuffer buf) {
        // 分割域名标签并写入
        for (String part : qName.split("\\.")) {
            byte[] bytes = part.getBytes(StandardCharsets.US_ASCII);
            // 写入标签长度
            buf.put((byte) bytes.length);
            // 写入标签内容
            buf.put(bytes);
        }
        // 写入结束标志
        buf.put((byte) 0);
        // 写入查询类型和查询类
        buf.putShort((short) qType);
        buf.putShort((short) qClass);
    }
}
