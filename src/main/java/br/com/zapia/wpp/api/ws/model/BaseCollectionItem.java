package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.WhatsAppClient;
import br.com.zapia.wpp.api.ws.utils.Util;
import com.google.gson.JsonObject;

public abstract class BaseCollectionItem {

    protected String id;
    protected final WhatsAppClient whatsAppClient;

    public BaseCollectionItem(WhatsAppClient whatsAppClient, JsonObject jsonObject) {
        this.whatsAppClient = whatsAppClient;
        buildFromJson(jsonObject);
    }

    //TODO: build base properties
    private void buildFromJson(JsonObject jsonObject) {
        build(jsonObject);
        if (jsonObject.get("jid") != null && !jsonObject.get("jid").isJsonNull())
            id = Util.convertJidReceived(jsonObject.get("jid").getAsString());
        else if (jsonObject.get("id") != null && !jsonObject.get("id").isJsonNull())
            id = jsonObject.get("id").getAsString();
    }

    abstract void build(JsonObject jsonObject);

    //TODO: update base properties
    public final void updateFromOther(BaseCollectionItem baseCollectionItem) {
        update(baseCollectionItem);
    }

    abstract void update(BaseCollectionItem baseCollectionItem);

    public String getId() {
        return id;
    }
}
