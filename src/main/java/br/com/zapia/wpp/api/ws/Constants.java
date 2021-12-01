package br.com.zapia.wpp.api.ws;

import br.com.zapia.wpp.api.ws.model.MessageType;

import java.util.HashMap;
import java.util.Map;

public class Constants {

    public static final String WS_URL = "wss://web.whatsapp.com/ws";
    public static final String WS_URL_MD = "wss://web.whatsapp.com/ws/chat";
    public static final String ORIGIN_WS = "https://web.whatsapp.com";
    public static final Integer[] WS_VERSION = new Integer[]{2, 2138, 13};
    public static final String[] WS_BROWSER_DESC = new String[]{"Zapia", "Edge", "1"};
    public static final byte[] NOISE_WA_HEADER = new byte[]{87, 65, 5, 2};
    public static final int KEEP_ALIVE_INTERVAL_MS = 20 * 1000;
    public static final int WA_DEFAULT_EPHEMERAL = 7 * 24 * 60 * 60;
    public static final Map<MessageType, String> HKDFInfoKeys = new HashMap<>() {{
        put(MessageType.IMAGE, "WhatsApp Image Keys");
        put(MessageType.AUDIO, "WhatsApp Audio Keys");
        put(MessageType.VIDEO, "WhatsApp Video Keys");
        put(MessageType.DOCUMENT, "WhatsApp Document Keys");
        put(MessageType.STICKER, "WhatsApp Image Keys");
    }};
    public static final Map<MessageType, String> MediaPathMap = new HashMap<>() {{
        put(MessageType.IMAGE, "/mms/image");
        put(MessageType.AUDIO, "/mms/audio");
        put(MessageType.VIDEO, "/mms/video");
        put(MessageType.DOCUMENT, "/mms/document");
        put(MessageType.STICKER, "/mms/image");
    }};
}
