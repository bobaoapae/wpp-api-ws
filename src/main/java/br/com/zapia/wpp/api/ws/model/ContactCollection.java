package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.WhatsAppClient;
import com.google.gson.JsonElement;

import java.util.List;

public class ContactCollection extends BaseCollection<ContactCollectionItem> {
    public ContactCollection(WhatsAppClient whatsAppClient) {
        super(whatsAppClient, CollectionType.CONTACTS);
    }

    @Override
    protected List<ContactCollectionItem> processSync(JsonElement jsonElement) {
        return null;
    }
}
