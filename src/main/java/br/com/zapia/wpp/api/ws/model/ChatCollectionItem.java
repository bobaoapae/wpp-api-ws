package br.com.zapia.wpp.api.ws.model;

import com.google.gson.JsonObject;

public class ChatCollectionItem extends BaseCollectionItem {

    //TODO: build specific properties
    @Override
    public ChatCollectionItem buildFromJson(JsonObject jsonObject) {
        super.buildFromJson(jsonObject);
        return this;
    }
}
