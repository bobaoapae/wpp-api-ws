package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.WhatsAppClient;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

public class ContactCollectionItem extends BaseCollectionItem {

    public ContactCollectionItem(WhatsAppClient whatsAppClient, JsonObject jsonObject) {
        super(whatsAppClient, jsonObject);
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
