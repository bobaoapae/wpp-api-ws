package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.WhatsAppClient;
import com.google.gson.JsonObject;

public class MessageCollectionItem extends BaseCollectionItem {

    private boolean fromMe;
    private String remoteJid;

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
    void build(JsonObject jsonObject) {
        var messageKey = jsonObject.get("key").getAsJsonObject();
        id = messageKey.get("id").getAsString();
        remoteJid = messageKey.get("remoteJid").getAsString();
        fromMe = messageKey.get("fromMe").getAsBoolean();
    }

    @Override
    void update(BaseCollectionItem baseCollectionItem) {

    }
}
