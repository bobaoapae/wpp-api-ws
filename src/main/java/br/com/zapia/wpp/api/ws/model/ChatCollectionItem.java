package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.WhatsAppClient;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

public class ChatCollectionItem extends BaseCollectionItem {

    private MessageCollectionItem lastMessage;
    private final List<MessageCollectionItem> messages;

    public ChatCollectionItem(WhatsAppClient whatsAppClient, JsonObject jsonObject) {
        super(whatsAppClient, jsonObject);
        messages = new ArrayList<>();
    }

    public CompletableFuture<List<MessageCollectionItem>> loadMessages(int count) {
        return whatsAppClient.loadMessages(id, count, lastMessage);
    }

    @Override
    void build() {

    }

    @Override
    void update(BaseCollectionItem baseCollectionItem) {

    }

    @Override
    void update(JsonElement jsonElement) {

    }
}
