package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.WhatsAppClient;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

public class ChatCollectionItem extends BaseCollectionItem<ChatCollectionItem> {

    private final Map<String, MessageCollectionItem> messages;
    private String name;
    private int unreadMessages;
    private int mute;
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

    public void setLastMessage(MessageCollectionItem lastMessage) {
        if (selfCollection != null)
            selfCollection.triggerEvent(EventType.CHANGE, List.of(this));
        this.lastMessage = lastMessage;
    }

    public MessageCollectionItem getLastMessage() {
        return lastMessage;
    }

    public void addMessage(MessageCollectionItem messageCollectionItem) {
        synchronized (messages) {
            if (!messages.containsKey(messageCollectionItem.getId())) {
                messages.put(messageCollectionItem.getId(), messageCollectionItem);
            }
        }
    }

    public List<MessageCollectionItem> getMessages() {
        synchronized (messages) {
            return Collections.unmodifiableList(messages.values().stream().toList());
        }
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

    public boolean isReadOnly() {
        return isReadOnly;
    }

    @Override
    void build() {
        if (jsonObject.has("count") && !jsonObject.get("count").getAsString().isEmpty())
            unreadMessages = jsonObject.get("count").getAsInt();
        if (jsonObject.has("mute") && !jsonObject.get("mute").getAsString().isEmpty())
            mute = jsonObject.get("mute").getAsInt();
        if (jsonObject.has("name"))
            name = jsonObject.get("name").getAsString();
        isReadOnly = jsonObject.has("read_only") && jsonObject.get("read_only").getAsBoolean();
    }

    @Override
    void update(ChatCollectionItem baseCollectionItem) {
        name = baseCollectionItem.getName();
        unreadMessages = baseCollectionItem.getUnreadMessages();
        mute = baseCollectionItem.getMute();
        isReadOnly = baseCollectionItem.isReadOnly();
    }

    @Override
    void update(JsonElement jsonElement) {

    }
}
