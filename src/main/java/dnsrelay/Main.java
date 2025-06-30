package dnsrelay;

public class Main {

    private static final String VERSION = "1.30";
    private static final String BUILD   = "Jun 28 2025 14:30:00";

    public static void main(String[] args) throws Exception {

        /* ------- 缺省值 ------- */
        String upstream = "114.114.114.114";   // 北互 DNS，和原 exe 一致
        String table    = "dnsrelay.txt";
        LogLevel level  = LogLevel.NONE;

        /* ------- 参数解析 ------- */
        for (String arg : args) {
            switch (arg) {
                case "-d"  -> level = LogLevel.NORMAL;
                case "-dd" -> level = LogLevel.DEBUG;
                default -> {
                    if (arg.matches("\\d+\\.\\d+\\.\\d+\\.\\d+"))
                        upstream = arg;
                    else
                        table = arg;
                }
            }
        }

        /* ------- 打印版本 & 用法横幅 ------- */
        System.out.printf("DNSRELAY, Version %s, Build: %s%n", VERSION, BUILD);
        System.out.println("Usage: dnsrelay [-d | -dd] [<dns-server>] [<db-file>]");

        /* ------- 把主要任务交给服务器类 ------- */
        new DnsRelayServer(upstream, table, level).start();
    }
}


