package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.WhatsAppClient;
import br.com.zapia.wpp.api.ws.binary.BinaryConstants;
import br.com.zapia.wpp.api.ws.model.communication.BaseQuery;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.lang.reflect.ParameterizedType;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

public abstract class BaseCollection<T extends BaseCollectionItem<T>> {

    private static final Logger logger = Logger.getLogger(BaseCollection.class.getName());

    private final Object lockSync;
    protected final WhatsAppClient whatsAppClient;
    private final CollectionType collectionType;
    private final Map<String, T> items;
    private final Map<EventType, List<ConsumerEventCancellable<List<T>>>> events;

    private final CompletableFuture<JsonArray> syncFuture;
    private boolean isSynced;
    private boolean firstSync;

    public BaseCollection(WhatsAppClient whatsAppClient, CollectionType collectionType) {
        this.whatsAppClient = whatsAppClient;
        this.collectionType = collectionType;
        this.items = new LinkedHashMap<>();
        this.events = new ConcurrentHashMap<>();
        this.lockSync = new Object();
        this.firstSync = true;
        this.syncFuture = new CompletableFuture<>();
    }

    public void listenToEvent(EventType eventType, ConsumerEventCancellable<List<T>> consumer) {
        if (!events.containsKey(eventType))
            events.put(eventType, new CopyOnWriteArrayList<>());

        events.get(eventType).add(consumer);
    }

    public boolean hasItem(String id) {
        synchronized (items) {
            return items.containsKey(id);
        }
    }

    public boolean tryAddItem(T item) {
        return tryAddItems(item);
    }

    public boolean tryAddItems(T... items) {
        synchronized (this.items) {
            var addItems = new ArrayList<T>();
            for (T item : items) {
                if (this.items.putIfAbsent(item.getId(), item) == null) {
                    item.setSelfCollection(this);
                    addItems.add(item);
                }
            }
            triggerEvent(EventType.ADD, addItems);
            return !addItems.isEmpty();
        }
    }

    public boolean tryRemoveItem(String id) {
        return tryRemoveItems(id);
    }

    public boolean tryRemoveItems(String... ids) {
        synchronized (items) {
            var removeds = new ArrayList<T>();
            for (String id : ids) {
                var removed = items.remove(id);
                if (removed != null) {
                    removeds.add(removed);
                }
                triggerEvent(EventType.REMOVE, removeds);
            }
            return !removeds.isEmpty();
        }
    }

    public boolean changeItem(String id, T item) {
        synchronized (items) {
            if (items.containsKey(id)) {
                var current = items.get(id);
                current.update(item);
                triggerEvent(EventType.CHANGE, List.of(current));

                return true;
            }

            return false;
        }
    }

    public boolean changeItem(String id, JsonElement jsonElement) {
        synchronized (items) {
            if (items.containsKey(id)) {
                var current = items.get(id);
                current.update(jsonElement);
                triggerEvent(EventType.CHANGE, List.of(current));

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

    public void triggerEvent(EventType eventType, List<T> data) {
        if (!events.containsKey(eventType))
            return;

        for (var tConsumerEventCancellable : events.get(eventType)) {
            try {
                if (tConsumerEventCancellable.isCanceled())
                    events.get(eventType).remove(tConsumerEventCancellable);
                else
                    tConsumerEventCancellable.accept(data);
            } catch (Exception e) {
                logger.log(Level.WARNING, "TriggerEvent - {" + eventType + "}", e);
            }
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
                if (!tryAddItem(item)) {
                    logger.log(Level.SEVERE, "Fail on add item to collection: " + item.getId() + " - " + item.getClass().getName());
                }
            }
        }
    }

    protected List<T> processSync(JsonElement jsonElement) {
        var dataArray = jsonElement.getAsJsonArray();
        var dataList = new ArrayList<T>();
        for (int i = 0; i < dataArray.size(); i++) {
            try {
                var instance = (T) ((Class) ((ParameterizedType) this.getClass().getGenericSuperclass()).getActualTypeArguments()[0]).getDeclaredConstructor(WhatsAppClient.class, JsonObject.class).newInstance(whatsAppClient, dataArray.get(i).getAsJsonArray().get(1).getAsJsonObject());
                dataList.add(instance);
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Fail to build instance for generic collection item", e);
            }
        }

        return dataList;
    }

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

    public CompletableFuture<JsonArray> getSyncFuture() {
        return syncFuture;
    }

    public CompletableFuture<Void> sync() {
        var epoch = "1";
        synchronized (lockSync) {
            isSynced = false;
            if (firstSync) {
                firstSync = false;
            } else {
                epoch = String.valueOf(whatsAppClient.getMsgCount());
            }

            var query = new BaseQuery(collectionType.name().toLowerCase(), epoch, null);
            return whatsAppClient.sendBinary(query.toJsonArray(), new BinaryConstants.WA.WATags(collectionType.getWaMetric(), BinaryConstants.WA.WAFlag.ignore), JsonArray.class).thenCompose(jsonElement -> {
                var duplicate = jsonElement.get(1).getAsJsonObject().get("duplicate");
                if (duplicate == null || !duplicate.getAsBoolean()) {
                    receiveSyncData(processSync(jsonElement.get(2).getAsJsonArray()));
                    return CompletableFuture.completedFuture(null);
                }
                return syncFuture.thenAccept(jsonElement1 -> {
                    receiveSyncData(processSync(jsonElement1.get(2).getAsJsonArray()));
                });
            });
        }
    }

}
