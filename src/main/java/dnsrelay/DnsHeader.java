package dnsrelay;

import java.nio.ByteBuffer;

public record DnsHeader(
        int id, boolean qr, int opcode, boolean aa, boolean tc, boolean rd,
        boolean ra, int z, int rcode,
        int qdCount, int anCount, int nsCount, int arCount) {

    /* ---------- 解析 ---------- */
    public static DnsHeader parse(ByteBuffer buf) {
        int id     = buf.getShort() & 0xFFFF;
        int flags  = buf.getShort() & 0xFFFF;

        boolean qr   = ((flags >> 15) & 1) == 1;
        int     op   = (flags >> 11) & 0xF;
        boolean aa   = ((flags >> 10) & 1) == 1;
        boolean tc   = ((flags >>  9) & 1) == 1;
        boolean rd   = ((flags >>  8) & 1) == 1;
        boolean ra   = ((flags >>  7) & 1) == 1;
        int     z    = (flags >> 4) & 0x7;
        int     rcode= flags & 0xF;

        int qd = buf.getShort() & 0xFFFF;
        int an = buf.getShort() & 0xFFFF;
        int ns = buf.getShort() & 0xFFFF;
        int ar = buf.getShort() & 0xFFFF;

        return new DnsHeader(id, qr, op, aa, tc, rd, ra, z, rcode, qd, an, ns, ar);
    }

    /* ---------- 组包 ---------- */
    public void write(ByteBuffer buf) {
        buf.putShort((short) id);

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

        buf.putShort((short) qdCount);
        buf.putShort((short) anCount);
        buf.putShort((short) nsCount);
        buf.putShort((short) arCount);
    }

    /* ---------- 工具 ---------- */
    public DnsHeader copyWithCounts(int an, int ns, int ar) {
        return new DnsHeader(id, true, opcode, false, false, rd,
                true, 0, 0, qdCount, an, ns, ar);
    }
}

