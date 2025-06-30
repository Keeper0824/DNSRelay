package dnsrelay;

public class Main {
    public static void main(String[] args) throws Exception {
        String upstream = "114.114.114.114";
        String table = "dnsrelay.txt";
        LogLevel level = LogLevel.NONE;

        for (String arg : args) {
            switch (arg) {
                case "-d"  -> level = LogLevel.NORMAL;
                case "-dd" -> level = LogLevel.DEBUG;
                default -> {
                    if (arg.matches("\\d+\\.\\d+\\.\\d+\\.\\d+"))     upstream = arg;
                    else                                             table = arg;
                }
            }
        }
        new DnsRelayServer(upstream, table, level).start();
    }

}

