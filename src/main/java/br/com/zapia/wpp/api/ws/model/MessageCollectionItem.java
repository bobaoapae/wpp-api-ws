package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.WhatsAppClient;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

public class MessageCollectionItem extends BaseCollectionItem {

    private boolean fromMe;
    private String remoteJid;
    private AckType ackType;

    public MessageCollectionItem(WhatsAppClient whatsAppClient, JsonObject jsonObject) {
        super(whatsAppClient, jsonObject);
    }

    public boolean isFromMe() {
        return fromMe;
    }

    public String getRemoteJid() {
        return remoteJid;
    }

    @Override
    void build() {
        var messageKey = jsonObject.get("key").getAsJsonObject();
        id = messageKey.get("id").getAsString();
        remoteJid = messageKey.get("remoteJid").getAsString();
        fromMe = messageKey.get("fromMe").getAsBoolean();
        if (jsonObject.has("status"))
            ackType = AckType.valueOf(jsonObject.get("status").getAsString().toUpperCase());
    }

    @Override
    void update(BaseCollectionItem baseCollectionItem) {

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
}
