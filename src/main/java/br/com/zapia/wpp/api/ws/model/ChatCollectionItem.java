package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.WhatsAppClient;
import com.google.gson.JsonObject;

public class ChatCollectionItem extends BaseCollectionItem {

    private final MessageCollection messageCollection;

    public ChatCollectionItem(WhatsAppClient whatsAppClient, JsonObject jsonObject) {
        super(whatsAppClient, jsonObject);
        this.messageCollection = new MessageCollection(whatsAppClient, this);
    }

    public MessageCollection getMessageCollection() {
        return messageCollection;
    }

    @Override
    void build(JsonObject jsonObject) {

    }

    @Override
    void update(BaseCollectionItem baseCollectionItem) {

    }
}
