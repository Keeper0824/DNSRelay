package dnsrelay;

/**
 * DNSRelay 程序入口类
 */
public class Main {

    // 程序版本号
    private static final String VERSION = "1.00";
    // 构建时间
    private static final String BUILD = "Jun 30 2025 14:30:00";

    /**
     * 程序主方法
     * <p>
     * 支持以下命令行参数：
     * -d    开启普通日志级别
     * -dd   开启调试日志级别
     * <dns-server>   指定上游 DNS 服务器 IP 地址（默认为 114.114.114.114）
     * <db-file>      指定本地黑/白名单数据库文件（默认为 dnsrelay.txt）
     */
    public static void main(String[] args) throws Exception {
        // 默认上游 DNS 服务器
        String upstream = "114.114.114.114";
        // 默认本地解析表文件
        String table = "dnsrelay.txt";
        // 默认不打印日志
        LogLevel level = LogLevel.NONE;

        // 解析命令行参数
        for (String arg : args) {
            switch (arg) {
                // 开启普通日志
                case "-d" -> level = LogLevel.NORMAL;
                // 开启调试日志
                case "-dd" -> level = LogLevel.DEBUG;
                default -> {
                    // 如果参数是一个 IPv4 地址，则视作上游 DNS 服务器
                    if (arg.matches("\\d+\\.\\d+\\.\\d+\\.\\d+"))
                        upstream = arg;
                        // 否则视作本地数据库文件名
                    else
                        table = arg;
                }
            }
        }

        // 打印程序版本和用法
        System.out.printf("DNSRELAY, Version %s, Build: %s%n", VERSION, BUILD);
        System.out.println("Usage: dnsrelay [-d | -dd] [<dns-server>] [<db-file>]");

        // 启动 DNSRelayServer，传入上游服务器、数据库文件和日志级别
        new DnsRelayServer(upstream, table, level).start();
    }
}
