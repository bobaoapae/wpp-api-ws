package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.WhatsAppClient;
import br.com.zapia.wpp.api.ws.utils.Util;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.TimeZone;
import java.util.concurrent.CompletableFuture;
import java.util.logging.Level;

public class MessageCollectionItem extends BaseCollectionItem<MessageCollectionItem> {

    private boolean fromMe;
    private String remoteJid;
    private AckType ackType;
    private LocalDateTime timeStamp;
    private MessageContent messageContent;

    public MessageCollectionItem(WhatsAppClient whatsAppClient, JsonObject jsonObject) {
        super(whatsAppClient, jsonObject);
    }

    public boolean isFromMe() {
        return fromMe;
    }

    public String getRemoteJid() {
        return remoteJid;
    }

    public AckType getAckType() {
        return ackType;
    }

    public LocalDateTime getTimeStamp() {
        return timeStamp;
    }

    public MessageContent getMessageContent() {
        return messageContent;
    }

    @Override
    void build() {
        var messageKey = jsonObject.get("key").getAsJsonObject();
        id = messageKey.get("id").getAsString();
        remoteJid = Util.convertJidReceived(messageKey.get("remoteJid").getAsString());
        fromMe = messageKey.get("fromMe").getAsBoolean();
        if (jsonObject.has("status"))
            ackType = AckType.valueOf(jsonObject.get("status").getAsString().toUpperCase());
        timeStamp = LocalDateTime.ofInstant(Instant.ofEpochSecond(jsonObject.get("messageTimestamp").getAsInt()), TimeZone.getDefault().toZoneId());
        if (jsonObject.has("message"))
            messageContent = MessageContent.build(this, jsonObject.getAsJsonObject("message"));
    }

    @Override
    void update(MessageCollectionItem baseCollectionItem) {
        ackType = baseCollectionItem.getAckType();
        messageContent = baseCollectionItem.getMessageContent();
    }

    @Override
    void update(JsonElement jsonElement) {
        ackType = AckType.values()[jsonElement.getAsJsonObject().get("ack").getAsNumber().intValue() + 1];
    }

    public enum AckType {
        ERROR,
        PENDING,
        SERVER_ACK,
        DELIVERY_ACK,
        READ,
        PLAYED
    }

    public static abstract class MessageContent {

        protected transient final MessageCollectionItem messageCollectionItem;
        private final MessageType messageType;

        protected MessageContent(MessageCollectionItem messageCollectionItem, MessageType messageType) {
            this.messageCollectionItem = messageCollectionItem;
            this.messageType = messageType;
        }

        public MessageType getMessageType() {
            return messageType;
        }

        public MessageCollectionItem getMessageCollectionItem() {
            return messageCollectionItem;
        }

        public static MessageContent build(MessageCollectionItem messageCollectionItem, JsonObject jsonObject) {
            try {
                if (jsonObject.has("conversation"))
                    return new MessageTextContent(messageCollectionItem, jsonObject);
                if (jsonObject.has("imageMessage")) {
                    return new MessageImageContent(messageCollectionItem, jsonObject.get("imageMessage").getAsJsonObject());
                }
                if (jsonObject.has("videoMessage")) {
                    return new MessageVideoContent(messageCollectionItem, jsonObject.get("videoMessage").getAsJsonObject());
                }
            } catch (Exception e) {
                logger.log(Level.SEVERE, "BuildMessageContent", e);
            }
            return new NotSupportedMessageContent(messageCollectionItem, jsonObject);
        }
    }

    public static class NotSupportedMessageContent extends MessageContent {

        private final JsonObject jsonObject;

        public NotSupportedMessageContent(MessageCollectionItem messageCollectionItem, JsonObject jsonObject) {
            super(messageCollectionItem, MessageType.UNKNOWN);
            this.jsonObject = jsonObject;
        }

        public JsonObject getJsonObject() {
            return jsonObject;
        }
    }

    public static class MessageTextContent extends MessageContent {

        private final String text;

        public MessageTextContent(MessageCollectionItem messageCollectionItem, JsonObject jsonObject) {
            super(messageCollectionItem, MessageType.TEXT);
            this.text = jsonObject.get("conversation").getAsString();
        }

        public String getText() {
            return text;
        }
    }

    public static class MessageMediaContent extends MessageContent {

        private final String url;
        private final String mimeType;
        private final String fileSha256;
        private final int fileLength;
        private final String mediaKey;
        private final String fileEncSha256;
        private final String directPath;
        private final int mediaKeyTimeStamp;

        public MessageMediaContent(MessageCollectionItem messageCollectionItem, MessageType messageType, JsonObject jsonObject) {
            super(messageCollectionItem, messageType);
            this.url = jsonObject.get("url").getAsString();
            this.mimeType = jsonObject.get("mimetype").getAsString();
            this.fileSha256 = jsonObject.get("fileSha256").getAsString();
            this.fileLength = jsonObject.get("fileLength").getAsInt();
            this.mediaKey = jsonObject.get("mediaKey").getAsString();
            this.fileEncSha256 = jsonObject.get("fileEncSha256").getAsString();
            this.directPath = jsonObject.get("directPath").getAsString();
            this.mediaKeyTimeStamp = jsonObject.get("mediaKeyTimestamp").getAsInt();
        }

        public String getUrl() {
            return url;
        }

        public String getMimeType() {
            return mimeType;
        }

        public String getFileSha256() {
            return fileSha256;
        }

        public int getFileLength() {
            return fileLength;
        }

        public String getMediaKey() {
            return mediaKey;
        }

        public String getFileEncSha256() {
            return fileEncSha256;
        }

        public String getDirectPath() {
            return directPath;
        }

        public int getMediaKeyTimeStamp() {
            return mediaKeyTimeStamp;
        }

        public CompletableFuture<byte[]> downloadMedia() {
            return messageCollectionItem.whatsAppClient.downloadMessageMedia(url, Base64.getDecoder().decode(mediaKey), getMessageType());
        }
    }

    public static class MessageImageContent extends MessageMediaContent {

        private final int height;
        private final int width;
        private final String thumbnail;

        public MessageImageContent(MessageCollectionItem messageCollectionItem, JsonObject jsonObject) {
            super(messageCollectionItem, MessageType.IMAGE, jsonObject);
            this.height = jsonObject.get("height").getAsInt();
            this.width = jsonObject.get("width").getAsInt();
            this.thumbnail = jsonObject.get("jpegThumbnail").getAsString();
        }

        public int getHeight() {
            return height;
        }

        public int getWidth() {
            return width;
        }

        public String getThumbnail() {
            return thumbnail;
        }
    }

    public static class MessageVideoContent extends MessageMediaContent {

        private final int duration;
        private final String thumbnail;

        public MessageVideoContent(MessageCollectionItem messageCollectionItem, JsonObject jsonObject) {
            super(messageCollectionItem, MessageType.VIDEO, jsonObject);
            this.duration = jsonObject.get("seconds").getAsInt();
            this.thumbnail = jsonObject.get("jpegThumbnail").getAsString();
        }

        public int getDuration() {
            return duration;
        }

        public String getThumbnail() {
            return thumbnail;
        }
    }
}
