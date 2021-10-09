package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.WhatsAppClient;
import com.google.gson.JsonElement;

import java.util.ArrayList;
import java.util.List;

public class ChatCollection extends BaseCollection<ChatCollectionItem> {
    public ChatCollection(WhatsAppClient whatsAppClient) {
        super(whatsAppClient, CollectionType.CHAT);
    }

    @Override
    protected List<ChatCollectionItem> processSync(JsonElement jsonElement) {
        var chats = jsonElement.getAsJsonArray();
        var chatsList = new ArrayList<ChatCollectionItem>();
        for (int i = 0; i < chats.size(); i++) {
            chatsList.add(new ChatCollectionItem(whatsAppClient, chats.get(i).getAsJsonArray().get(1).getAsJsonObject()));
        }

        return chatsList;
    }
}
