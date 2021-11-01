package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.WhatsAppClient;
import br.com.zapia.wpp.api.ws.utils.Util;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.*;
import java.util.concurrent.CompletableFuture;

public class ChatCollectionItem extends BaseCollectionItem<ChatCollectionItem> {

    private final Map<String, MessageCollectionItem> messages;
    private String name;
    private int unreadMessages;
    private int mute;
    private int pin;
    private boolean isReadOnly;
    private MessageCollectionItem lastMessage;

    public ChatCollectionItem(WhatsAppClient whatsAppClient, JsonObject jsonObject) {
        super(whatsAppClient, jsonObject);
        messages = new LinkedHashMap<>();
    }

    public CompletableFuture<List<MessageCollectionItem>> loadMessages(int count) {
        return whatsAppClient.loadMessages(id, count, lastMessage);
    }

    public CompletableFuture<MessageCollectionItem> sendMessage(SendMessageRequest sendMessageRequest) {
        return whatsAppClient.sendMessage(id, sendMessageRequest);
    }

    public void sendPresence(PresenceType presenceType) {
        whatsAppClient.sendChatPresenceUpdate(getId(), presenceType);
    }

    public void addMessage(MessageCollectionItem messageCollectionItem) {
        addMessages(messageCollectionItem);
    }

    public void addMessages(MessageCollectionItem... messageCollectionItem) {
        synchronized (messages) {
            for (MessageCollectionItem item : messageCollectionItem) {
                if (!messages.containsKey(item.getId())) {
                    messages.put(item.getId(), item);
                    if (!item.isFromMe() && Util.isNewMessage(whatsAppClient.getConnectTime(), item))
                        unreadMessages = Math.max(unreadMessages + 1, 1);
                }
            }
            triggerChange();
        }
    }

    public void removeMessage(String id) {
        removeMessages(id);
    }

    public void removeMessages(String... ids) {
        synchronized (messages) {
            for (String id : ids) {
                messages.remove(id);
            }
            triggerChange();
        }
    }

    public List<MessageCollectionItem> getMessages() {
        synchronized (messages) {
            return Collections.unmodifiableList(messages.values().stream().sorted(Comparator.comparing(MessageCollectionItem::getTimeStamp)).toList());
        }
    }

    public void setLastMessage(MessageCollectionItem lastMessage) {
        this.lastMessage = lastMessage;
        addMessage(lastMessage);
        triggerChange();
    }

    public void setPin(int pin) {
        this.pin = pin;
        triggerChange();
    }

    public void setUnreadMessages(int unreadMessages) {
        this.unreadMessages = unreadMessages;
        triggerChange();
    }

    public String getName() {
        return name;
    }

    public int getUnreadMessages() {
        return unreadMessages;
    }

    public int getMute() {
        return mute;
    }

    public int getPin() {
        return pin;
    }

    public boolean isReadOnly() {
        return isReadOnly;
    }

    public MessageCollectionItem getLastMessage() {
        return lastMessage;
    }

    @Override
    void build() {
        if (jsonObject.has("count") && !jsonObject.get("count").getAsString().isEmpty())
            unreadMessages = jsonObject.get("count").getAsInt();
        if (jsonObject.has("mute") && !jsonObject.get("mute").getAsString().isEmpty())
            mute = jsonObject.get("mute").getAsInt();
        if (jsonObject.has("pin") && !jsonObject.get("pin").getAsString().isEmpty())
            pin = jsonObject.get("pin").getAsInt();
        if (jsonObject.has("name"))
            name = jsonObject.get("name").getAsString();
        isReadOnly = jsonObject.has("read_only") && jsonObject.get("read_only").getAsBoolean();
    }

    @Override
    void update(ChatCollectionItem baseCollectionItem) {
        name = baseCollectionItem.getName();
        unreadMessages = baseCollectionItem.getUnreadMessages();
        mute = baseCollectionItem.getMute();
        pin = baseCollectionItem.getPin();
        isReadOnly = baseCollectionItem.isReadOnly();
    }

    @Override
    void update(JsonElement jsonElement) {

    }
}
