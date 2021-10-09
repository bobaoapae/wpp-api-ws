package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.WhatsAppClient;
import br.com.zapia.wpp.api.ws.binary.BinaryConstants;
import br.com.zapia.wpp.api.ws.model.communication.BaseQuery;
import com.google.gson.JsonElement;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class BaseCollection<T extends BaseCollectionItem> {

    private static final Logger logger = Logger.getLogger(BaseCollection.class.getName());

    private final Object lockSync;
    protected final WhatsAppClient whatsAppClient;
    private final CollectionType collectionType;
    private final Map<String, T> items;
    private final Map<EventType, List<ConsumerEventCancellable<List<T>>>> events;

    private CompletableFuture<JsonElement> syncFuture;
    private boolean isSynced;
    private boolean firstSync;

    public BaseCollection(WhatsAppClient whatsAppClient, CollectionType collectionType) {
        this.whatsAppClient = whatsAppClient;
        this.collectionType = collectionType;
        this.items = new LinkedHashMap<>();
        this.events = new ConcurrentHashMap<>();
        this.lockSync = new Object();
        this.firstSync = true;
    }

    public void listenToEvent(EventType eventType, ConsumerEventCancellable<List<T>> consumer) {
        if (!events.containsKey(eventType))
            events.put(eventType, new CopyOnWriteArrayList<>());

        events.get(eventType).add(consumer);
    }

    public boolean tryAddItem(String id, T item) {
        synchronized (items) {
            if (items.putIfAbsent(id, item) == null) {
                triggerEvent(EventType.ADD, List.of(item));

                return true;
            }

            return false;
        }
    }

    public boolean tryRemoveItem(String id) {
        synchronized (items) {
            var removed = items.remove(id);
            if (removed != null) {
                triggerEvent(EventType.REMOVE, List.of(removed));
                return true;
            }

            return false;
        }
    }

    public boolean changeItem(String id, T item) {
        synchronized (items) {
            if (items.containsKey(id)) {
                items.get(id).update(item);

                return true;
            }

            return false;
        }
    }

    public T getLastItem() {
        synchronized (items) {
            var values = items.values().stream().toList();
            if (values.size() > 0) {
                return values.get(values.size() - 1);
            }

            return null;
        }
    }

    public T getItem(String id) {
        synchronized (items) {
            if (items.containsKey(id)) {
                return items.get(id);
            }

            return null;
        }
    }

    public List<T> getAllItems() {
        synchronized (items) {
            return items.values().stream().toList();
        }
    }

    private void triggerEvent(EventType eventType, List<T> data) {
        if (!events.containsKey(eventType))
            return;

        for (var tConsumerEventCancellable : events.get(eventType)) {
            if (tConsumerEventCancellable.isCanceled())
                events.get(eventType).remove(tConsumerEventCancellable);
            else
                tConsumerEventCancellable.accept(data);
        }
    }

    private void receiveSyncData(List<T> items) {
        if (items == null)
            return;

        synchronized (lockSync) {
            if (isSynced)
                return;
            isSynced = true;
        }

        synchronized (this.items) {
            for (T item : items) {
                if (!tryAddItem(item.getId(), item)) {
                    logger.log(Level.SEVERE, "Fail on add item to collection: " + item.getId() + " - " + item.getClass().getName());
                }
            }
        }
    }

    protected abstract List<T> processSync(JsonElement jsonElement);

    public void setSynced() {
        synchronized (lockSync) {
            isSynced = true;
        }
    }

    public boolean isSynced() {
        synchronized (lockSync) {
            return isSynced;
        }
    }

    public CompletableFuture<JsonElement> getSyncFuture() {
        return syncFuture;
    }

    public CompletableFuture<Void> sync() {
        var epoch = "1";
        synchronized (lockSync) {
            isSynced = false;
            if (!firstSync) {
                firstSync = true;
            } else {
                epoch = String.valueOf(whatsAppClient.getMsgCount());
            }

            var query = new BaseQuery(collectionType.name().toLowerCase(), epoch, null);
            syncFuture = whatsAppClient.sendBinary(query.toJsonArray(), new BinaryConstants.WA.WATags(collectionType.getWaMetric(), BinaryConstants.WA.WAFlag.ignore), JsonElement.class);
            return syncFuture.thenAccept(jsonElement -> {
                receiveSyncData(processSync(jsonElement));
            });
        }
    }

}
