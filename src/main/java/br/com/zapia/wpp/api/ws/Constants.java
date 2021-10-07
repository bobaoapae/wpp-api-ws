package br.com.zapia.wpp.api.ws;

public class Constants {

    public static final String WS_URL = "wss://web.whatsapp.com/ws";
    public static final String ORIGIN_WS = "https://web.whatsapp.com";
    public static final Integer[] WS_VERSION = new Integer[]{2, 2138, 13};
    public static final String[] WS_BROWSER_DESC = new String[]{"Zapia", "Edge", "1"};
    public static final int KEEP_ALIVE_INTERVAL_MS = 20 * 1000;
    public static final int WA_DEFAULT_EPHEMERAL = 7 * 24 * 60 * 60;
}
