package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.WhatsAppClient;

public class QuickReplyCollection extends BaseCollection<QuickReplyCollectionItem> {

    public QuickReplyCollection(WhatsAppClient whatsAppClient) {
        super(whatsAppClient, CollectionType.QUICK_REPLY);
    }
}
