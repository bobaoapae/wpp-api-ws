package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.WhatsAppClient;
import com.google.gson.JsonElement;

import java.util.List;
import java.util.concurrent.CompletableFuture;

public class MessageCollection extends BaseCollection<MessageCollectionItem> {

    private final ChatCollectionItem chatCollectionItem;

    public MessageCollection(WhatsAppClient whatsAppClient, ChatCollectionItem chatCollectionItem) {
        super(whatsAppClient, CollectionType.MESSAGE);
        this.chatCollectionItem = chatCollectionItem;
    }

    public CompletableFuture<List<MessageCollectionItem>> loadMessages(int count) {
        return whatsAppClient.loadMessages(chatCollectionItem.getId(), count, getLastItem());
    }

    @Override
    public CompletableFuture<Void> sync() {
        return loadMessages(30).thenAccept(messageCollectionItems -> setSynced());
    }

    @Override
    protected List<MessageCollectionItem> processSync(JsonElement jsonElement) {
        return null;
    }
}
