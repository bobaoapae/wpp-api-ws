package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.WhatsAppClient;

public class ContactCollection extends BaseCollection<ContactCollectionItem> {

    public ContactCollection(WhatsAppClient whatsAppClient) {
        super(whatsAppClient, CollectionType.CONTACTS);
    }
}
