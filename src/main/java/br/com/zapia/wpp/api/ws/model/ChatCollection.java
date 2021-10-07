package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.WhatsAppClient;

import java.util.List;

public class ChatCollection extends BaseCollection<ChatCollectionItem> {
    public ChatCollection(WhatsAppClient whatsAppClient) {
        super(whatsAppClient, CollectionType.CHAT);
    }
}
