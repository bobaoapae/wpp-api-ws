package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.WhatsAppClient;
import br.com.zapia.wpp.api.ws.utils.Util;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

public abstract class BaseCollectionItem {

    protected String id;
    protected final WhatsAppClient whatsAppClient;
    protected final JsonObject jsonObject;

    public BaseCollectionItem(WhatsAppClient whatsAppClient, JsonObject jsonObject) {
        this.whatsAppClient = whatsAppClient;
        this.jsonObject = jsonObject;
        buildFromJson();
    }

    //TODO: build base properties
    private void buildFromJson() {
        build();
        if (jsonObject.get("jid") != null && !jsonObject.get("jid").isJsonNull())
            id = Util.convertJidReceived(jsonObject.get("jid").getAsString());
        else if (jsonObject.get("id") != null && !jsonObject.get("id").isJsonNull())
            id = jsonObject.get("id").getAsString();
    }

    abstract void build();

    //TODO: update base properties
    public final void updateFromOther(BaseCollectionItem baseCollectionItem) {
        update(baseCollectionItem);
    }

    abstract void update(BaseCollectionItem baseCollectionItem);

    abstract void update(JsonElement jsonElement);

    public String getId() {
        return id;
    }
}
