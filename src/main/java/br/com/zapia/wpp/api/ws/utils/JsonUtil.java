package br.com.zapia.wpp.api.ws.utils;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class JsonUtil {

    public static final JsonUtil I = new JsonUtil();

    private final Gson gson;

    private JsonUtil() {
        gson = new GsonBuilder().create();
    }

    public Gson getGson() {
        return gson;
    }
}
