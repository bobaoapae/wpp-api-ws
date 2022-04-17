package br.com.zapia.wpp.api.ws.utils;

import org.json.JSONObject;

import java.lang.reflect.Field;
import java.util.LinkedHashMap;

//TODO: remove this hacking(Stop using generic jsonobj/jsonarray and build some node models
public class SortedJSONObject extends JSONObject {

    public SortedJSONObject() {
        super();
        try {
            Field mapField = JSONObject.class.getDeclaredField("map");
            mapField.setAccessible(true);
            mapField.set(this, new LinkedHashMap());
            mapField.setAccessible(false);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

}
