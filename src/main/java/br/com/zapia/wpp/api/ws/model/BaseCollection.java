package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.WhatsAppClient;
import br.com.zapia.wpp.api.ws.binary.BinaryConstants;
import br.com.zapia.wpp.api.ws.model.communication.BaseQuery;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public abstract class BaseCollection<T extends BaseCollectionItem> {

    private final Object lockSync;
    private final WhatsAppClient whatsAppClient;
    private final CollectionType collectionType;
    private final Map<String, T> items;
    private boolean isSynced;

    public BaseCollection(WhatsAppClient whatsAppClient, CollectionType collectionType) {
        this.whatsAppClient = whatsAppClient;
        this.collectionType = collectionType;
        this.items = new ConcurrentHashMap<>();
        this.lockSync = new Object();
    }

    public boolean tryAddItem(String id, T item) {
        return items.putIfAbsent(id, item) == null;
    }

    public T getItem(String id) {
        if (items.containsKey(id)) {
            return items.get(id);
        }

        return null;
    }

    public List<T> getAllItems() {
        return items.values().stream().toList();
    }

    public final void receiveSyncData(List<T> items) {
        //TODO: process items, merge existing and add news

        synchronized (lockSync) {
            isSynced = true;
        }
    }

    public boolean isSynced() {
        synchronized (lockSync) {
            return isSynced;
        }
    }

    public final void sync() {
        synchronized (lockSync) {
            isSynced = false;
        }
        var query = new BaseQuery(collectionType.name().toLowerCase(), String.valueOf(whatsAppClient.getMsgCount()), null);
        whatsAppClient.sendBinary(query.toJsonArray(), new BinaryConstants.WA.WATags(collectionType.getWaMetric(), BinaryConstants.WA.WAFlag.ignore), null);
    }

}
