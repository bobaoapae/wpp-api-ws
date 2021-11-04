package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.WhatsAppClient;
import com.google.gson.JsonObject;

public class ContactCollectionItem extends BaseCollectionItem<ContactCollectionItem> {

    private String name;
    private String shortName;
    private String pushName;

    public ContactCollectionItem(WhatsAppClient whatsAppClient, JsonObject jsonObject) {
        super(whatsAppClient, jsonObject);
    }

    public String getName() {
        return name;
    }

    public String getShortName() {
        return shortName;
    }

    public String getPushName() {
        return pushName;
    }

    @Override
    void build() {
        if (jsonObject.has("name") && !jsonObject.get("name").getAsString().isEmpty())
            name = jsonObject.get("name").getAsString();
        if (jsonObject.has("short") && !jsonObject.get("short").getAsString().isEmpty())
            shortName = jsonObject.get("short").getAsString();
        if (jsonObject.has("vname") && !jsonObject.get("vname").getAsString().isEmpty())
            pushName = jsonObject.get("vname").getAsString();
    }

    @Override
    protected void update(ContactCollectionItem baseCollectionItem) {
        name = baseCollectionItem.getName();
        shortName = baseCollectionItem.getShortName();
        pushName = baseCollectionItem.getPushName();
    }

    @Override
    protected void update(JsonObject jsonObject) {

    }
}
