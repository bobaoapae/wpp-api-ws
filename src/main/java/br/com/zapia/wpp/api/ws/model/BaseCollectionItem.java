package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.WhatsAppClient;
import br.com.zapia.wpp.api.ws.utils.Util;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class BaseCollectionItem<T extends BaseCollectionItem<T>> {

    protected static final Logger logger = Logger.getLogger(BaseCollectionItem.class.getName());

    protected String id;
    protected final WhatsAppClient whatsAppClient;
    protected final JsonObject jsonObject;
    protected BaseCollection<T> selfCollection;

    public BaseCollectionItem(WhatsAppClient whatsAppClient, JsonObject jsonObject) {
        this.whatsAppClient = whatsAppClient;
        this.jsonObject = jsonObject;
        buildFromJson();
    }

    public void setSelfCollection(BaseCollection<T> selfCollection) {
        this.selfCollection = selfCollection;
    }

    //TODO: build base properties
    private void buildFromJson() {
        try {
            build();
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Build CollectionItem", e);
        }
        if (jsonObject.get("jid") != null && !jsonObject.get("jid").isJsonNull())
            id = Util.convertJidReceived(jsonObject.get("jid").getAsString());
        else if (jsonObject.get("id") != null && !jsonObject.get("id").isJsonNull())
            id = jsonObject.get("id").getAsString();
    }

    abstract void build();

    //TODO: update base properties
    public final void updateFromOther(T baseCollectionItem) {
        update(baseCollectionItem);
    }

    abstract void update(T baseCollectionItem);

    abstract void update(JsonElement jsonElement);

    public String getId() {
        return id;
    }
}
