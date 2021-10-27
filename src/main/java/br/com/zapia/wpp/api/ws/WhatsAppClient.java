package br.com.zapia.wpp.api.ws;

import br.com.zapia.wpp.api.ws.binary.BinaryConstants;
import br.com.zapia.wpp.api.ws.binary.WABinaryDecoder;
import br.com.zapia.wpp.api.ws.binary.WABinaryEncoder;
import br.com.zapia.wpp.api.ws.binary.protos.*;
import br.com.zapia.wpp.api.ws.model.*;
import br.com.zapia.wpp.api.ws.model.communication.*;
import br.com.zapia.wpp.api.ws.utils.Util;
import com.github.benmanes.caffeine.cache.AsyncLoadingCache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.google.common.hash.Hashing;
import com.google.common.primitives.Bytes;
import com.google.gson.*;
import com.google.protobuf.ByteString;
import com.google.protobuf.util.JsonFormat;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.qrcode.QRCodeWriter;
import ezvcard.Ezvcard;
import ezvcard.VCard;
import ezvcard.VCardVersion;
import ezvcard.parameter.TelephoneType;
import ezvcard.property.Telephone;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.framing.CloseFrame;
import org.java_websocket.handshake.ServerHandshake;
import org.whispersystems.curve25519.Curve25519;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;

public class WhatsAppClient extends WebSocketClient {

    private static final Logger logger = Logger.getLogger(WhatsAppClient.class.getName());
    private static final Curve25519 CURVE_25519 = Curve25519.getInstance(Curve25519.BEST);

    private final Function<Runnable, Runnable> runnableFactory;
    private final Function<Callable, Callable> callableFactory;
    private final Function<Runnable, Thread> threadFactory;
    private final ExecutorService executorService;
    private final ScheduledExecutorService scheduledExecutorService;

    private final Consumer<String> onQrCode;
    private final Runnable onConnect;
    private final Consumer<AuthInfo> onAuthInfo;
    private final Consumer<DriverState> onChangeDriverState;

    private final Object syncTag;
    private final Object syncIsSynced;
    private final Object syncPresence;
    private final Map<Class<? extends BaseCollection<? extends BaseCollectionItem<?>>>, BaseCollection<? extends BaseCollectionItem<?>>> collections;
    private final AsyncLoadingCache<String, CheckNumberExistResponse> cacheNumberExist;
    private final List<ScheduledFuture<?>> scheduledFutures;
    private final Map<String, CompletableFuture<JsonElement>> wsEvents;
    private final List<Runnable> runnableOnConnect;
    private final AtomicBoolean isSynced;

    private String serverId;
    private AuthInfo authInfo;
    private CommunicationKeys communicationKeys;
    private String lastQrCode;

    private DriverState driverState;
    private int msgCount;
    private LocalDateTime lastSeen;
    private LocalDateTime lastSendPresence;
    private PresenceType lastPresenceType;
    private MediaConnResponse.MediaConn cacheMediaConnResponse;
    private ScheduledFuture<?> refreshQrCodeScheduler;
    private ScheduledFuture<?> keepAliveScheduled;

    public WhatsAppClient(AuthInfo authInfo, Consumer<String> onQrCode, Runnable onConnect, Consumer<AuthInfo> onAuthInfo, Consumer<DriverState> onChangeDriverState, Function<Runnable, Runnable> runnableFactory, Function<Callable, Callable> callableFactory, Function<Runnable, Thread> threadFactory, ExecutorService executorService, ScheduledExecutorService scheduledExecutorService) {
        super(URI.create(Constants.WS_URL));
        this.authInfo = authInfo;
        this.onQrCode = onQrCode;
        this.onConnect = onConnect;
        this.onAuthInfo = onAuthInfo;
        this.onChangeDriverState = onChangeDriverState;
        this.runnableFactory = runnableFactory;
        this.callableFactory = callableFactory;
        this.threadFactory = threadFactory;
        this.executorService = executorService;
        this.scheduledExecutorService = scheduledExecutorService;
        this.syncTag = new Object();
        this.wsEvents = new ConcurrentHashMap<>();
        this.scheduledFutures = new ArrayList<>();
        this.collections = new HashMap<>();
        this.cacheNumberExist = Caffeine.newBuilder()
                .maximumSize(10_000)
                .expireAfterWrite(Duration.ofMinutes(5))
                .buildAsync(number -> sendJson(new CheckNumberExistRequest(number).toJson(), CheckNumberExistResponse.class).get());
        this.runnableOnConnect = new ArrayList<>();
        this.isSynced = new AtomicBoolean(false);
        this.syncIsSynced = new Object();
        this.syncPresence = new Object();
        setDriverState(DriverState.UNLOADED);
        setConnectionLostTimeout(0);
        getHeadersConnectWs().forEach(this::addHeader);
    }

    protected Map<String, String> getHeadersConnectWs() {
        var headers = new HashMap<String, String>();
        headers.put("Origin", Constants.ORIGIN_WS);
        return headers;
    }

    public String generateMessageTag(boolean longTag) {
        synchronized (syncTag) {
            var seconds = System.currentTimeMillis() / 1000L;
            var tag = (longTag ? seconds : (seconds % 1000)) + ".--" + msgCount;
            msgCount++;
            return tag;
        }
    }

    public String generateMessageID() {
        byte[] bytes = new byte[8];
        try {
            SecureRandom.getInstanceStrong().nextBytes(bytes);
        } catch (Exception ignore) {
            new Random().nextBytes(bytes);
        }
        return "3EB0" + Util.bytesToHex(bytes);
    }

    private void runOnSync(Runnable runnable) {
        synchronized (syncIsSynced) {
            if (isSynced.get()) {
                try {
                    runnable.run();
                } catch (Exception e) {
                    logger.log(Level.SEVERE, "Failed to run", e);
                }
            } else {
                runnableOnConnect.add(runnable);
            }
        }
    }

    public <T> CompletableFuture<T> sendJson(String data, Class<T> responseType) {
        return sendJson(generateMessageTag(false), data, responseType);
    }

    public <T> CompletableFuture<T> sendJson(String msgTag, String data, Class<T> responseType) {
        var response = new CompletableFuture<JsonElement>();
        response.handle((jsonElement, throwable) -> {
            wsEvents.remove(msgTag);
            return null;
        });
        wsEvents.put(msgTag, response);
        send(msgTag + "," + data);
        return response.thenApply(jsonElement -> Util.GSON.fromJson(jsonElement, responseType));
    }

    public <T> CompletableFuture<T> sendBinary(JsonArray jsonArray, BinaryConstants.WA.WATags waTags, Class<T> responseType) {
        return sendBinary(jsonArray, waTags, responseType, false);
    }

    public <T> CompletableFuture<T> sendBinary(JsonArray jsonArray, BinaryConstants.WA.WATags waTags, Class<T> responseType, boolean longTag) {
        return sendBinary(generateMessageTag(longTag), jsonArray, waTags, responseType);
    }

    public <T> CompletableFuture<T> sendBinary(String msgTag, JsonArray jsonArray, BinaryConstants.WA.WATags waTags, Class<T> responseType) {
        var response = new CompletableFuture<JsonElement>();
        try {
            var binary = new WABinaryEncoder().write(jsonArray);

            var encryptedBinary = Util.encryptWa(communicationKeys.getEncKey(), binary);

            var hmac = Hashing.hmacSha256(communicationKeys.getMacKey())
                    .newHasher()
                    .putBytes(encryptedBinary)
                    .hash().asBytes();

            var buffSend = Bytes.concat(
                    (msgTag + ",").getBytes(StandardCharsets.UTF_8),
                    waTags.toByteArray(),
                    hmac,
                    encryptedBinary
            );
            response.handle((jsonElement, throwable) -> {
                wsEvents.remove(msgTag);
                return null;
            });

            wsEvents.put(msgTag, response);
            send(buffSend);
            return response.thenApply(s -> Util.GSON.fromJson(s, responseType));
        } catch (Exception e) {
            logger.log(Level.SEVERE, "SendBinary", e);
            response.completeExceptionally(e);
            return response.thenApply(jsonElement -> null);
        }
    }

    private void createCollections() {
        collections.clear();
        collections.put(ChatCollection.class, new ChatCollection(this));
        collections.put(MessageCollection.class, new MessageCollection(this));
        collections.put(ContactCollection.class, new ContactCollection(this));
    }

    public <T extends BaseCollection<? extends BaseCollectionItem>> T getCollection(Class<T> collectionType) {
        var collection = collections.get(collectionType);
        if (collection != null)
            return collectionType.cast(collection);

        return null;
    }

    private void initLogin() {
        try {
            createCollections();
            if (authInfo == null) {
                byte[] bytes = new byte[16];
                SecureRandom.getInstanceStrong().nextBytes(bytes);
                var clientId = Base64.getEncoder().encodeToString(bytes);
                authInfo = new AuthInfo();
                authInfo.setClientId(clientId);
            }
            //startKeepAlive();
            sendInit().thenAccept(initResponse -> {
                if (initResponse.getStatus() == 200) {
                    serverId = initResponse.getRef();
                    refreshQrCodeScheduler = schedule(() -> {
                        refreshQrCode().thenAccept(refreshQrResponse -> {
                            if (refreshQrResponse.getStatus() != 200) {
                                close(CloseFrame.ABNORMAL_CLOSE, "Ws Closed due to many QR refresh");
                            } else {
                                logger.log(Level.INFO, "QrCode expired generating new one");
                                serverId = refreshQrResponse.getRef();
                                generateQrCode();
                            }
                        });
                    }, initResponse.getTtl(), initResponse.getTtl(), TimeUnit.MILLISECONDS);
                    if (authInfo.getSecret() == null) {
                        initNewSession();
                    } else {
                        sendLogin().thenAccept(loginResponse -> {
                            if (loginResponse.getStatus() != 200) {
                                logger.log(Level.WARNING, "Failed to restore previous session {status: " + loginResponse.getStatus() + "}, starting a new one");
                                initNewSession();
                            }
                        });
                    }
                } else {
                    logger.log(Level.SEVERE, "Init returned unexpected status: " + initResponse.getStatus());
                    close(CloseFrame.ABNORMAL_CLOSE, "Init returned unexpected status: " + initResponse.getStatus());
                }
            });
        } catch (Exception e) {
            logger.log(Level.SEVERE, "InitLogin", e);
            close(CloseFrame.ABNORMAL_CLOSE, "A error was occurred on initLogin, check logs to find the reason");
        }
    }

    private CompletableFuture<InitResponse> sendInit() {
        setDriverState(DriverState.INITIALIZING);
        return sendJson(new InitRequest(authInfo.getClientId()).toJson(), InitResponse.class);
    }

    public CompletableFuture<JsonElement> sendPresence(PresenceType presenceType) {
        synchronized (syncPresence) {
            if (lastSendPresence == null)
                lastSendPresence = LocalDateTime.now();

            if (presenceType == lastPresenceType && lastSendPresence.plusSeconds(15).isBefore(LocalDateTime.now())) {
                var fakeJsonResponse = new JsonObject();
                fakeJsonResponse.addProperty("status", 429);
                return CompletableFuture.completedFuture(fakeJsonResponse);
            }

            lastPresenceType = presenceType;
            lastSendPresence = LocalDateTime.now();

            var childs = new JsonArray();
            var child = new JsonArray();
            var data = new JsonObject();
            data.addProperty("type", presenceType.name().toLowerCase());
            child.add("presence");
            child.add(data);
            child.add(JsonNull.INSTANCE);
            childs.add(child);
            return sendBinary(new BaseAction("set", String.valueOf(msgCount), childs).toJsonArray(), new BinaryConstants.WA.WATags(BinaryConstants.WA.WAMetric.presence, BinaryConstants.WA.WAFlag.ignore), JsonElement.class);
        }
    }

    public void sendChatPresenceUpdate(String jid, PresenceType presenceType) {
        switch (presenceType) {
            case AVAILABLE, UNAVAILABLE -> {
                logger.log(Level.WARNING, "Invalid Presence Type: " + presenceType);
                throw new IllegalStateException("Invalid Presence Type: " + presenceType);
            }
        }
        var childs = new JsonArray();
        var child = new JsonArray();
        var data = new JsonObject();
        data.addProperty("type", presenceType.name().toLowerCase());
        data.addProperty("to", Util.convertJidToSend(jid));
        child.add("presence");
        child.add(data);
        child.add(JsonNull.INSTANCE);
        childs.add(child);
        sendBinary(new BaseAction("set", String.valueOf(msgCount), childs).toJsonArray(), new BinaryConstants.WA.WATags(BinaryConstants.WA.WAMetric.presence, BinaryConstants.WA.WAFlag.valueOf(presenceType.name().toLowerCase())), JsonElement.class);
    }

    public CompletableFuture<CheckNumberExistResponse> checkNumberExist(String number) {
        return cacheNumberExist.get(number);
    }

    public CompletableFuture<ChatCollectionItem> findChatFromNumber(String number) {
        return checkNumberExist(number).thenCompose(checkNumberExistResponse -> {
            if (checkNumberExistResponse.getStatus() == 200) {
                return findChatFromId(checkNumberExistResponse.getJid());
            }
            return CompletableFuture.completedFuture(null);
        });
    }

    public CompletableFuture<ChatCollectionItem> findChatFromId(String id) {
        var chatCache = getCollection(ChatCollection.class).getItem(id);
        if (chatCache != null) {
            return CompletableFuture.completedFuture(chatCache);
        }

        return findContactFromId(id).thenApply(contactCollectionItem -> {
            //TODO: others default properties
            var jsonObject = new JsonObject();
            jsonObject.addProperty("jid", contactCollectionItem.getId());
            var chat = new ChatCollectionItem(this, jsonObject);
            if (!getCollection(ChatCollection.class).tryAddItem(id, chat))
                logger.log(Level.WARNING, "Fail on add chat to collection: " + id);

            return chat;
        });
    }

    public CompletableFuture<ContactCollectionItem> findContactFromNumber(String number) {
        return checkNumberExist(number).thenCompose(checkNumberExistResponse -> {
            if (checkNumberExistResponse.getStatus() == 200) {
                return findContactFromId(checkNumberExistResponse.getJid());
            }
            return CompletableFuture.completedFuture(null);
        });
    }

    public CompletableFuture<ContactCollectionItem> findContactFromId(String id) {
        var contactCache = getCollection(ContactCollection.class).getItem(id);
        if (contactCache != null) {
            return CompletableFuture.completedFuture(contactCache);
        }

        //TODO: others default properties
        var jsonObject = new JsonObject();
        jsonObject.addProperty("jid", id);
        var contact = new ContactCollectionItem(this, jsonObject);
        if (!getCollection(ContactCollection.class).tryAddItem(id, contact))
            logger.log(Level.WARNING, "Fail on add contact to collection: " + id);

        return CompletableFuture.completedFuture(contact);
    }

    public CompletableFuture<JsonElement> findProfilePicture(String jid) {
        var query = new JsonArray();
        query.add("query");
        query.add("ProfilePicThumb");
        query.add(Util.convertJidToSend(jid));
        return sendJson(Util.GSON.toJson(query), JsonElement.class);
    }

    public CompletableFuture<List<MessageCollectionItem>> loadMessages(String jid, int count, MessageCollectionItem lastMessage) {
        String index = null;
        String fromMe = null;
        if (lastMessage != null) {
            index = lastMessage.getId();
            fromMe = lastMessage.isFromMe() ? "true" : "false";
        }
        if (!getCollection(ChatCollection.class).hasItem(jid))
            return CompletableFuture.failedFuture(new IllegalStateException("Chat not found on local collection to load messages, try use findChat before. {" + jid + "}"));
        return sendBinary(
                new LoadMessagesRequest(String.valueOf(msgCount), Util.convertJidToSend(jid), "before", count, index, fromMe).toJsonArray(),
                new BinaryConstants.WA.WATags(BinaryConstants.WA.WAMetric.queryMessages, BinaryConstants.WA.WAFlag.ignore),
                JsonElement.class)
                .thenApply(jsonElement -> {
                    var messagesList = new ArrayList<MessageCollectionItem>();

                    try {
                        var jsonArray = ((JsonArray) jsonElement).get(2).getAsJsonArray();
                        for (int i = 0; i < jsonArray.size(); i++) {
                            messagesList.add(new MessageCollectionItem(this, jsonArray.get(i).getAsJsonArray().get(2).getAsJsonObject()));
                        }

                        var chat = getCollection(ChatCollection.class).getItem(jid);

                        for (MessageCollectionItem messageCollectionItem : messagesList) {
                            if (!getCollection(MessageCollection.class).tryAddItem(messageCollectionItem.getId(), messageCollectionItem)) {
                                logger.log(Level.WARNING, "Fail on add received message to collection: " + messageCollectionItem.getId());
                                throw new RuntimeException("Fail on add received message to collection: " + messageCollectionItem.getId());
                            }
                            chat.addMessage(messageCollectionItem);
                        }

                    } catch (Exception e) {
                        logger.log(Level.WARNING, "LoadMessages", e);
                    }
                    return messagesList;
                });
    }

    public CompletableFuture<MessageCollectionItem> sendMessage(String jid, SendMessageRequest messageSend) {
        return sendPresence(PresenceType.AVAILABLE).thenCompose(ignore -> {
            return prepareMessageContent(messageSend).thenCompose(content -> {
                var builder = WebMessageInfo.newBuilder();
                builder
                        .setKey(MessageKey.newBuilder().setRemoteJid(Util.convertJidToSend(jid)).setFromMe(true).setId(generateMessageID()))
                        .setMessage(content)
                        .setMessageTimestamp(System.currentTimeMillis() / 1000L)
                        .setStatus(WebMessageInfo.WebMessageInfoStatus.PENDING);
                if (jid.contains("@g.us")) {
                    builder.setParticipant(authInfo.getWid());
                }
                var jsonObj = new JsonObject();
                jsonObj.addProperty("epoch", String.valueOf(msgCount));
                jsonObj.addProperty("type", "relay");

                var msg = builder.build();

                var childs = new JsonArray();
                var child = new JsonArray();
                child.add("message");
                child.add(JsonNull.INSTANCE);
                child.add(Util.GSON.toJsonTree(msg.toByteArray()));
                childs.add(child);

                var jsonArray = new JsonArray();
                jsonArray.add("action");
                jsonArray.add(jsonObj);
                jsonArray.add(childs);

                //TODO: build message and add to collection before send

                MessageCollectionItem messageCollectionItem;
                try {
                    messageCollectionItem = new MessageCollectionItem(this, JsonParser.parseString(JsonFormat.printer().print(msg)).getAsJsonObject());
                    if (!getCollection(MessageCollection.class).tryAddItem(messageCollectionItem.getId(), messageCollectionItem))
                        throw new RuntimeException("Error on add to MessageCollection");
                    if (!getCollection(ChatCollection.class).hasItem(jid))
                        throw new RuntimeException("Chat not found on local collection to send message, try use findChat before. {" + jid + "}");
                    getCollection(ChatCollection.class).getItem(jid).addMessage(messageCollectionItem);
                } catch (Exception e) {
                    logger.log(Level.SEVERE, "Error on build MessageCollectionItem before send", e);
                    return CompletableFuture.failedFuture(e);
                }

                MessageCollectionItem finalMessageCollectionItem = messageCollectionItem;
                return sendBinary(
                        builder.getKey().getId(),
                        jsonArray,
                        new BinaryConstants.WA.WATags(BinaryConstants.WA.WAMetric.message, jid.equals(authInfo.getWid()) ? BinaryConstants.WA.WAFlag.acknowledge : BinaryConstants.WA.WAFlag.ignore),
                        JsonElement.class).thenApply(jsonElement -> {
                    //TODO: check return status
                    return finalMessageCollectionItem;
                });
            });
        });
    }

    //TODO: others message types
    private CompletableFuture<Message.Builder> prepareMessageContent(SendMessageRequest messageSend) {
        try {
            var msgBuilder = Message.newBuilder();
            ContextInfo.Builder contextInfo = null;
            if (messageSend.getQuotedMsg() != null) {
                try {
                    contextInfo = ContextInfo.newBuilder();
                    if (messageSend.getQuotedMsg().isFromMe()) {
                        contextInfo.setParticipant(authInfo.getWid());
                    } else if (!Util.isStringNullOrEmpty(messageSend.getQuotedMsg().getParticipant())) {
                        contextInfo.setParticipant(messageSend.getQuotedMsg().getParticipant());
                        contextInfo.setRemoteJid(Util.convertJidToSend(messageSend.getQuotedMsg().getRemoteJid()));
                    } else {
                        contextInfo.setParticipant(Util.convertJidToSend(messageSend.getQuotedMsg().getRemoteJid()));
                    }
                    contextInfo.setStanzaId(messageSend.getQuotedMsg().getId());
                    var quotedMessageBuilder = WebMessageInfo.newBuilder();
                    JsonFormat.parser().ignoringUnknownFields().merge(Util.GSON.toJson(messageSend.getQuotedMsg().getJsonObject()), quotedMessageBuilder);
                    var msg = quotedMessageBuilder.build();
                    contextInfo.setQuotedMessage(msg.getMessage());
                } catch (Exception e) {
                    logger.log(Level.SEVERE, "Prepare quoted message to reply", e);
                }
            }
            switch (messageSend.getMessageType()) {
                case TEXT: {
                    if (contextInfo == null) {
                        msgBuilder.setConversation(messageSend.getText());
                    } else {
                        var extendedTextBuilder = ExtendedTextMessage.newBuilder();
                        extendedTextBuilder
                                .setText(messageSend.getText())
                                .setContextInfo(contextInfo);
                        msgBuilder.setExtendedTextMessage(extendedTextBuilder);
                    }
                    return CompletableFuture.completedFuture(msgBuilder);
                }
                case LOCATION:
                case LIVE_LOCATION: {
                    var locationMsgBuilder = LocationMessage.newBuilder();
                    locationMsgBuilder
                            .setDegreesLatitude(messageSend.getLocation().getLat())
                            .setDegreesLongitude(messageSend.getLocation().getLng())
                            .setAddress(messageSend.getLocation().getName());
                    if (contextInfo != null) {
                        locationMsgBuilder.setContextInfo(contextInfo);
                    }
                    msgBuilder.setLocationMessage(locationMsgBuilder);
                    return CompletableFuture.completedFuture(msgBuilder);
                }
                case CONTACT: {
                    VCard vcard = new VCard();
                    vcard.setFormattedName(messageSend.getvCard().getName());
                    Telephone tel = new Telephone(messageSend.getvCard().getTelephone());
                    tel.getTypes().add(TelephoneType.CELL);
                    vcard.addProperty(tel);

                    var contact = findContactFromNumber(tel.getText()).join();
                    if (contact != null) {
                        tel.setParameter("waid", contact.getId().split("@")[0]);
                    }
                    var vcardStr = Ezvcard.write(vcard).version(VCardVersion.V3_0).go();
                    if (contact != null) {
                        vcardStr = vcardStr.replace("WAID", "waid");
                    }

                    var contactMsgBuilder = ContactMessage.newBuilder();
                    contactMsgBuilder
                            .setVcard(vcardStr)
                            .setDisplayName(vcard.getFormattedName().getValue());
                    if (contextInfo != null) {
                        contactMsgBuilder.setContextInfo(contextInfo);
                    }
                    msgBuilder.setContactMessage(contactMsgBuilder);
                    return CompletableFuture.completedFuture(msgBuilder);
                }
                case BUTTONS_MESSAGE: {
                    var buttonsMsgBuilder = ButtonsMessage.newBuilder();
                    for (String button : messageSend.getButtons().getButtons()) {
                        buttonsMsgBuilder.addButtons(Button.newBuilder().setButtonText(ButtonText.newBuilder().setDisplayText(button)).setButtonId(generateMessageID()).setType(Button.ButtonType.RESPONSE));
                    }
                    buttonsMsgBuilder
                            .setFooterText(messageSend.getButtons().getFooter())
                            .setContentText(messageSend.getButtons().getTitle())
                            .setHeaderType(ButtonsMessage.ButtonsMessageHeaderType.TEXT);
                    buttonsMsgBuilder.setText(messageSend.getText() == null || messageSend.getText().isEmpty() ? " " : messageSend.getText());
                    if (contextInfo != null) {
                        buttonsMsgBuilder.setContextInfo(contextInfo);
                    }
                    msgBuilder.setButtonsMessage(buttonsMsgBuilder);
                    return CompletableFuture.completedFuture(msgBuilder);
                }
                case LIST_MESSAGE: {
                    var listMsgBuilder = ListMessage.newBuilder();
                    listMsgBuilder.setListType(ListMessage.ListMessageListType.SINGLE_SELECT);
                    for (SendMessageRequest.Section section : messageSend.getWhatsAppList().getSections()) {
                        var sectionBuilder = Section.newBuilder();
                        sectionBuilder.setTitle(section.getTitle());
                        for (SendMessageRequest.SectionItem row : section.getRows()) {
                            var rowBuilder = Row.newBuilder();
                            rowBuilder.setTitle(row.getTitle())
                                    .setDescription(row.getDescription() == null ? "" : row.getDescription())
                                    .setRowId(generateMessageID());
                            sectionBuilder.addRows(rowBuilder);
                        }
                        listMsgBuilder.addSections(sectionBuilder);
                    }
                    listMsgBuilder.setTitle(messageSend.getWhatsAppList().getTitle())
                            .setDescription(messageSend.getWhatsAppList().getDescription())
                            .setFooterText(messageSend.getWhatsAppList().getFooter())
                            .setButtonText(messageSend.getWhatsAppList().getButtonText());
                    if (contextInfo != null) {
                        listMsgBuilder.setContextInfo(contextInfo);
                    }
                    msgBuilder.setListMessage(listMsgBuilder);
                    return CompletableFuture.completedFuture(msgBuilder);
                }
                case DOCUMENT:
                case IMAGE:
                case VIDEO:
                case AUDIO:
                case STICKER:
                    return prepareMessageMedia(msgBuilder, messageSend, contextInfo).thenApply(otherMsgBuilder -> otherMsgBuilder);
                default: {
                    logger.log(Level.SEVERE, "Unsupported message type to send: {" + messageSend.getMessageType() + "}");
                    return CompletableFuture.failedFuture(new Exception("Unsupported message type to send: {" + messageSend.getMessageType() + "}"));
                }
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "PrepareMessageContent", e);
            return CompletableFuture.failedFuture(e);
        }
    }

    private CompletableFuture<Message.Builder> prepareMessageMedia(Message.Builder msgBuilder, SendMessageRequest messageSend, ContextInfo.Builder contextInfo) {
        if (messageSend.getMessageType() == MessageType.STICKER && messageSend.getText() != null && !messageSend.getText().isEmpty()) {
            return CompletableFuture.failedFuture(new IllegalStateException("Cannot send caption with a sticker"));
        }

        return CompletableFuture.supplyAsync(() -> {
            try {
                var streamFile = Base64.getDecoder().decode(messageSend.getFile().getEncodedFile());

                var mimeType = Util.detectMimeType(streamFile);


                if (messageSend.getMessageType() == MessageType.STICKER && !mimeType.equals("image/webp")) {
                    streamFile = Util.convertImageToWebp(Util.scaleImage(streamFile, 512, 512));
                    mimeType = "image/webp";
                }

                var encryptedStream = Util.encryptStream(streamFile, messageSend.getMessageType());

                var sha256EncB64 = Util.encodeURIComponent(Base64.getEncoder().encodeToString(encryptedStream.getSha256Enc()).replace("+", "-").replace("/", "_").replace("=", ""));

                var mediaConn = getMediaConn().join();

                for (MediaConnResponse.MediaConn.Host host : mediaConn.getHosts()) {
                    try {
                        var auth = Util.encodeURIComponent(mediaConn.getAuth());
                        var url = "https://" + host.getHostname() + Constants.MediaPathMap.get(messageSend.getMessageType()) + "/" + sha256EncB64 + "?auth=" + auth + "&token=" + sha256EncB64;


                        HttpRequest requestBodyOfInputStream = HttpRequest.newBuilder()
                                .header("Content-Type", "application/octet-stream")
                                .header("Origin", Constants.ORIGIN_WS)
                                .POST(HttpRequest.BodyPublishers.ofByteArray(encryptedStream.getEncryptedStream()))
                                .uri(URI.create(url))
                                .build();

                        var client = HttpClient.newHttpClient();
                        var response = client.send(requestBodyOfInputStream, HttpResponse.BodyHandlers.ofString());

                        try {
                            var bodyResponse = response.body();

                            if (bodyResponse == null || bodyResponse.isEmpty()) {
                                throw new Exception("Body Response is empty");
                            }

                            var uploadMediaResponse = Util.GSON.fromJson(bodyResponse, UploadMediaResponse.class);

                            if (uploadMediaResponse.getUrl() == null || uploadMediaResponse.getUrl().isEmpty()) {
                                throw new Exception("Upload URL is empty");
                            }

                            switch (messageSend.getMessageType()) {
                                case DOCUMENT: {
                                    var documentBuilder = DocumentMessage.newBuilder();
                                    documentBuilder
                                            .setUrl(uploadMediaResponse.getUrl())
                                            .setDirectPath(uploadMediaResponse.getDirect_path())
                                            .setMediaKey(ByteString.copyFrom(encryptedStream.getMediaKey()))
                                            .setMediaKeyTimestamp(System.currentTimeMillis() / 1000L)
                                            .setMimetype(mimeType)
                                            .setFileEncSha256(ByteString.copyFrom(encryptedStream.getSha256Enc()))
                                            .setFileSha256(ByteString.copyFrom(encryptedStream.getSha256Plain()))
                                            .setFileLength(encryptedStream.getFileLength())
                                            .setFileName(messageSend.getFile().getFileName());
                                    if (contextInfo != null) {
                                        documentBuilder.setContextInfo(contextInfo);
                                    }
                                    msgBuilder.setDocumentMessage(documentBuilder);
                                    break;
                                }
                                case IMAGE: {
                                    var imageBuilder = ImageMessage.newBuilder();
                                    var dimension = Util.getImageDimension(streamFile);
                                    imageBuilder
                                            .setUrl(uploadMediaResponse.getUrl())
                                            .setDirectPath(uploadMediaResponse.getDirect_path())
                                            .setMediaKeyTimestamp(System.currentTimeMillis() / 1000L)
                                            .setMediaKey(ByteString.copyFrom(encryptedStream.getMediaKey()))
                                            .setMimetype(mimeType)
                                            .setFileEncSha256(ByteString.copyFrom(encryptedStream.getSha256Enc()))
                                            .setFileSha256(ByteString.copyFrom(encryptedStream.getSha256Plain()))
                                            .setFileLength(encryptedStream.getFileLength())
                                            .setHeight((int) dimension.getHeight())
                                            .setWidth((int) dimension.getWidth())
                                            .setJpegThumbnail(ByteString.copyFrom(Util.generateThumbnail(streamFile, messageSend.getMessageType())));
                                    if (contextInfo != null) {
                                        imageBuilder.setContextInfo(contextInfo);
                                    }
                                    msgBuilder.setImageMessage(imageBuilder);
                                    break;
                                }
                                case VIDEO: {
                                    var videoBuilder = VideoMessage.newBuilder();
                                    videoBuilder
                                            .setUrl(uploadMediaResponse.getUrl())
                                            .setDirectPath(uploadMediaResponse.getDirect_path())
                                            .setMediaKey(ByteString.copyFrom(encryptedStream.getMediaKey()))
                                            .setMediaKeyTimestamp(System.currentTimeMillis() / 1000L)
                                            .setMimetype(mimeType)
                                            .setFileEncSha256(ByteString.copyFrom(encryptedStream.getSha256Enc()))
                                            .setFileSha256(ByteString.copyFrom(encryptedStream.getSha256Plain()))
                                            .setFileLength(encryptedStream.getFileLength())
                                            .setSeconds(Util.getMediaDuration(streamFile))
                                            .setGifPlayback(messageSend.getFile().isForceGif())
                                            .setJpegThumbnail(ByteString.copyFrom(Util.generateThumbnail(streamFile, messageSend.getMessageType())));
                                    if (contextInfo != null) {
                                        videoBuilder.setContextInfo(contextInfo);
                                    }
                                    msgBuilder.setVideoMessage(videoBuilder);
                                    break;
                                }
                                case AUDIO: {
                                    var audioBuilder = AudioMessage.newBuilder();
                                    audioBuilder
                                            .setUrl(uploadMediaResponse.getUrl())
                                            .setDirectPath(uploadMediaResponse.getDirect_path())
                                            .setMediaKey(ByteString.copyFrom(encryptedStream.getMediaKey()))
                                            .setMediaKeyTimestamp(System.currentTimeMillis() / 1000L)
                                            .setMimetype(mimeType)
                                            .setFileEncSha256(ByteString.copyFrom(encryptedStream.getSha256Enc()))
                                            .setFileSha256(ByteString.copyFrom(encryptedStream.getSha256Plain()))
                                            .setFileLength(encryptedStream.getFileLength())
                                            .setSeconds(Util.getMediaDuration(streamFile))
                                            .setPtt(messageSend.getFile().isForcePtt());
                                    if (contextInfo != null) {
                                        audioBuilder.setContextInfo(contextInfo);
                                    }
                                    msgBuilder.setAudioMessage(audioBuilder);
                                    break;
                                }
                                case STICKER: {
                                    var stickerBuilder = StickerMessage.newBuilder();
                                    stickerBuilder
                                            .setUrl(uploadMediaResponse.getUrl())
                                            .setDirectPath(uploadMediaResponse.getDirect_path())
                                            .setMediaKey(ByteString.copyFrom(encryptedStream.getMediaKey()))
                                            .setMediaKeyTimestamp(System.currentTimeMillis() / 1000L)
                                            .setMimetype(mimeType)
                                            .setFileEncSha256(ByteString.copyFrom(encryptedStream.getSha256Enc()))
                                            .setFileSha256(ByteString.copyFrom(encryptedStream.getSha256Plain()))
                                            .setFileLength(encryptedStream.getFileLength())
                                            .setPngThumbnail(ByteString.copyFrom(Util.generateThumbnail(Base64.getDecoder().decode(messageSend.getFile().getEncodedFile()), messageSend.getMessageType())));
                                    if (contextInfo != null) {
                                        stickerBuilder.setContextInfo(contextInfo);
                                    }
                                    msgBuilder.setStickerMessage(stickerBuilder);
                                    break;
                                }
                            }
                            break;

                        } catch (Exception e) {
                            cacheMediaConnResponse = null;
                            mediaConn = getMediaConn().join();
                            throw new Exception(response.body(), e);
                        }


                    } catch (Exception e) {
                        var isLast = host.equals(mediaConn.getHosts()[mediaConn.getHosts().length - 1]);
                        var append = isLast ? "" : ", retrying...";
                        logger.log(Level.WARNING, "Error uploading media to {" + host.getHostname() + "}" + append, e);
                    }
                }

                return msgBuilder;

            } catch (Exception e) {
                logger.log(Level.SEVERE, "PrepareMessageMedia", e);
                throw new CompletionException(e);
            }
        }, executorService);
    }

    private CompletableFuture<MediaConnResponse.MediaConn> getMediaConn() {
        if (cacheMediaConnResponse != null && cacheMediaConnResponse.getFetchDate().plusSeconds(cacheMediaConnResponse.getTtl()).isAfter(LocalDateTime.now())) {
            return CompletableFuture.completedFuture(cacheMediaConnResponse);
        }
        return sendJson(new MediaConnRequest().toJson(), MediaConnResponse.class).thenApply(mediaConnResponse -> {
            mediaConnResponse.getMedia_conn().setFetchDate(LocalDateTime.now());
            cacheMediaConnResponse = mediaConnResponse.getMedia_conn();
            return cacheMediaConnResponse;
        });
    }

    public CompletableFuture<byte[]> downloadMessageMedia(String url, byte[] mediaKey, MessageType messageType) {
        return CompletableFuture.supplyAsync(() -> {
            try {
                HttpRequest httpRequest = HttpRequest.newBuilder()
                        .header("Origin", Constants.ORIGIN_WS)
                        .GET()
                        .uri(URI.create(url))
                        .build();

                var client = HttpClient.newHttpClient();
                var response = client.send(httpRequest, HttpResponse.BodyHandlers.ofByteArray());
                if (response.statusCode() >= 400) {
                    throw new Exception("Error on download data from WhatsApp Server: " + new String(response.body(), StandardCharsets.UTF_8));
                }
                return Util.decryptStream(response.body(), mediaKey, messageType);
            } catch (Exception e) {
                logger.log(Level.SEVERE, "DownloadMessageMedia", e);
                throw new RuntimeException(e);
            }
        }, executorService);
    }

    private void initNewSession() {
        try {
            setDriverState(DriverState.INIT_NEW_SESSION);
            var keyPair = CURVE_25519.generateKeyPair();
            authInfo.setPrivateKey(Base64.getEncoder().encodeToString(keyPair.getPrivateKey()));
            authInfo.setPublicKey(Base64.getEncoder().encodeToString(keyPair.getPublicKey()));
            generateQrCode();
        } catch (Exception e) {
            logger.log(Level.SEVERE, "InitNewSession", e);
        }
    }

    private CompletableFuture<LoginResponse> sendLogin() {
        setDriverState(DriverState.RESTORING_OLD_SESSION);
        return sendJson(new LoginRequest(authInfo).toJson(), LoginResponse.class);
    }

    private void generateQrCode() {
        try {
            var stringQrCode = serverId + "," + authInfo.getPublicKey() + "," + authInfo.getClientId();
            var barcodeWriter = new QRCodeWriter();
            var bitMatrix = barcodeWriter.encode(stringQrCode, BarcodeFormat.QR_CODE, 400, 400);
            var outputStream = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(bitMatrix, "png", outputStream);
            lastQrCode = "data:image/png;base64," + Base64.getEncoder().encodeToString(outputStream.toByteArray());
            if (onQrCode != null) {
                executorService.submit(runnableFactory.apply(() -> {
                    onQrCode.accept(lastQrCode);
                }));
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "GenerateQrCode", e);
            close(CloseFrame.ABNORMAL_CLOSE, "Ws Closed due to error on generate QrCode");
        }
    }

    private CompletableFuture<RefreshQrResponse> refreshQrCode() {
        return sendJson(new RefreshQrRequest().toJson(), RefreshQrResponse.class);
    }

    //See WhatsApp Web {openStream} function
    private CompletableFuture<Void> syncCollections() {
        setDriverState(DriverState.WAITING_SYNC);
        var chat = getCollection(ChatCollection.class).sync();
        var contact = getCollection(ContactCollection.class).sync();
        return chat.thenCompose(unused -> contact);
        /**
         * sendBinary(new BaseQuery("status", "1", null).toJsonArray(), new BinaryConstants.WA.WATags(BinaryConstants.WA.WAMetric.queryStatus, BinaryConstants.WA.WAFlag.ignore), null);
         *             if (authInfo.isBusiness()) {
         *                 sendBinary(new BaseQuery("quick_reply", "1", null).toJsonArray(), new BinaryConstants.WA.WATags(BinaryConstants.WA.WAMetric.queryQuickReply, BinaryConstants.WA.WAFlag.ignore), null);
         *             }
         */
    }

    private void generateCommunicationKeys() {
        try {
            var decodedSecret = Base64.getDecoder().decode(authInfo.getSecret());
            if (decodedSecret.length != 144) {
                throw new Exception("incorrect secret length received: " + decodedSecret.length);
            }

            var sharedKey = CURVE_25519.calculateAgreement(Arrays.copyOf(decodedSecret, 32), Base64.getDecoder().decode(authInfo.getPrivateKey()));

            var expandedKey = Util.hkdfExpand(sharedKey, 80, null);

            var hmacValidationKey = Arrays.copyOfRange(expandedKey, 32, 64);

            var hmacValidationMessage = Bytes.concat(Arrays.copyOf(decodedSecret, 32), Arrays.copyOfRange(decodedSecret, 64, decodedSecret.length));


            var hmac = Hashing.hmacSha256(hmacValidationKey)
                    .newHasher()
                    .putBytes(hmacValidationMessage)
                    .hash().asBytes();

            if (!Arrays.equals(hmac, Arrays.copyOfRange(decodedSecret, 32, 64))) {
                throw new Exception("HMAC Validation Failed");
            }

            var keysEncrypted = Bytes.concat(Arrays.copyOfRange(expandedKey, 64, expandedKey.length), Arrays.copyOfRange(decodedSecret, 64, decodedSecret.length));


            byte[] key = Arrays.copyOf(expandedKey, 32);

            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            byte[] iv = Arrays.copyOf(keysEncrypted, 16);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

            var keysDecrypted = cipher.doFinal(Arrays.copyOfRange(keysEncrypted, 16, keysEncrypted.length));

            var encKey = Arrays.copyOf(keysDecrypted, 32);
            var macKey = Arrays.copyOfRange(keysDecrypted, 32, 64);

            communicationKeys = new CommunicationKeys(sharedKey, expandedKey, keysEncrypted, keysDecrypted, encKey, macKey);

            executorService.submit(runnableFactory.apply(() -> {
                sendPresence(PresenceType.AVAILABLE);
                syncCollections().thenAccept(unused -> {
                    synchronized (syncIsSynced) {
                        for (Runnable runnable : runnableOnConnect) {
                            try {
                                runnable.run();
                            } catch (Exception e) {
                                logger.log(Level.SEVERE, "Failed to run", e);
                            }
                        }
                        runnableOnConnect.clear();
                        isSynced.set(true);
                    }
                    for (ChatCollectionItem chatItem : getCollection(ChatCollection.class).getAllItems()) {

                    }
                    if (onConnect != null) {
                        onConnect.run();
                    }
                    setDriverState(DriverState.CONNECTED);
                });
            }));

            if (onAuthInfo != null) {
                executorService.submit(runnableFactory.apply(() -> {
                    onAuthInfo.accept(authInfo);
                }));
            }

        } catch (Exception e) {
            logger.log(Level.SEVERE, "GenerateCommunicationKeys", e);
        }
    }

    private void startKeepAlive() {
        keepAliveScheduled = schedule(() -> {
            if (lastSeen == null) lastSeen = LocalDateTime.now();

            /*var currentTime = LocalDateTime.now();
            if (lastSeen.plusSeconds(25).isBefore(currentTime)) {
                close(CloseFrame.ABNORMAL_CLOSE, "Ws Closed due to timeout on receive pong from server  ");
            }*/
            send("?,,");
        }, 0, Constants.KEEP_ALIVE_INTERVAL_MS, TimeUnit.MILLISECONDS);
    }

    private ScheduledFuture<?> schedule(Runnable runnable, long initialDelay, long delay, TimeUnit timeUnit) {
        synchronized (scheduledFutures) {
            var scheduledFuture = scheduledExecutorService.scheduleAtFixedRate(runnable, initialDelay, delay, timeUnit);
            scheduledFutures.add(scheduledFuture);
            return scheduledFuture;
        }
    }

    public DriverState getDriverState() {
        return driverState;
    }

    public void setDriverState(DriverState driverState) {
        this.driverState = driverState;
        if (onChangeDriverState != null) {
            executorService.submit(runnableFactory.apply(() -> {
                onChangeDriverState.accept(driverState);
            }));
        }
    }

    public int getMsgCount() {
        return msgCount;
    }

    public String getLastQrCode() {
        return lastQrCode;
    }

    @Override
    public void connect() {
        super.connect();
        setDriverState(DriverState.CONNECTING);
    }

    @Override
    public void onOpen(ServerHandshake handshakedata) {
        initLogin();
    }

    @Override
    public void onMessage(ByteBuffer bytes) {
        try {
            var byteArray = bytes.array();
            int commaIndex = -1;
            for (int i = 0; i < byteArray.length; i++) {
                if (byteArray[i] == (byte) ',') {
                    commaIndex = i;
                    break;
                }
            }

            if (commaIndex > 0) {
                var bytesTag = Arrays.copyOf(byteArray, commaIndex);
                var bytesMsg = Arrays.copyOfRange(byteArray, commaIndex + 1, byteArray.length);
                var msgTag = new String(bytesTag);

                if (communicationKeys == null) {
                    throw new IllegalStateException("Received encrypted buffer without communicationKeys");
                }

                var checksum = Arrays.copyOf(bytesMsg, 32);
                var data = Arrays.copyOfRange(bytesMsg, 32, bytesMsg.length);

                var hmac = Hashing.hmacSha256(communicationKeys.getMacKey())
                        .newHasher()
                        .putBytes(data)
                        .hash().asBytes();

                if (!Arrays.equals(hmac, checksum)) {
                    throw new Exception("HMAC Validation Failed");
                }

                var decryptedBytes = Util.decryptWa(communicationKeys.getEncKey(), data);

                var binaryDecoder = new WABinaryDecoder(decryptedBytes);
                var jsonDecoded = binaryDecoder.read();

                if (wsEvents.containsKey(msgTag)) {
                    var response = wsEvents.get(msgTag);
                    response.complete(jsonDecoded);
                } else {
                    var binaryType = jsonDecoded.get(0).getAsString();
                    switch (binaryType) {
                        case "response": {
                            var duplicate = jsonDecoded.get(1).getAsJsonObject().get("duplicate");
                            var responseType = jsonDecoded.get(1).getAsJsonObject().get("type").getAsString();
                            if (duplicate != null && duplicate.getAsBoolean()) {
                                logger.log(Level.INFO, "Received duplicated response: " + responseType);
                                return;
                            }
                            switch (responseType) {
                                case "chat": {
                                    var chatCollection = getCollection(ChatCollection.class);
                                    chatCollection.getSyncFuture().complete(jsonDecoded.get(2).getAsJsonArray());
                                    break;
                                }
                                case "contacts": {
                                    var chatCollection = getCollection(ContactCollection.class);
                                    chatCollection.getSyncFuture().complete(jsonDecoded.get(2).getAsJsonArray());
                                    break;
                                }
                                default:
                                    logger.log(Level.WARNING, "Received unexpected Binary Response type: {" + responseType + "} - with content: {" + jsonDecoded + "}");
                            }
                            break;
                        }
                        case "action": {
                            var actionsGrouped = Util.groupActionsByType(jsonDecoded.get(2).getAsJsonArray());
                            for (String key : actionsGrouped.keySet()) {
                                var current = actionsGrouped.getAsJsonArray(key);
                                switch (key) {
                                    case "msg": {
                                        var addType = jsonDecoded.get(1).getAsJsonObject().get("add").getAsString();
                                        switch (addType) {
                                            case "relay":
                                            case "update": {
                                                var msgBuilder = WebMessageInfo.newBuilder();
                                                JsonFormat.parser().ignoringUnknownFields().merge(Util.GSON.toJson(current.get(0).getAsJsonArray().get(2).getAsJsonObject()), msgBuilder);
                                                var msg = msgBuilder.build();
                                                var messageCollectionItem = new MessageCollectionItem(this, JsonParser.parseString(JsonFormat.printer().print(msg)).getAsJsonObject());
                                                switch (addType) {
                                                    case "relay": {
                                                        if (!getCollection(MessageCollection.class).tryAddItem(messageCollectionItem.getId(), messageCollectionItem))
                                                            logger.log(Level.WARNING, "Fail on add received message to collection: " + messageCollectionItem.getId());
                                                        runOnSync(() -> {
                                                            if (getCollection(ChatCollection.class).hasItem(messageCollectionItem.getRemoteJid()))
                                                                getCollection(ChatCollection.class).getItem(messageCollectionItem.getRemoteJid()).addMessage(messageCollectionItem);
                                                            else
                                                                logger.log(Level.WARNING, "Received new message but chat was not found: " + messageCollectionItem.getId());
                                                        });
                                                        break;
                                                    }
                                                    case "update": {
                                                        runOnSync(() -> {
                                                            if (!getCollection(MessageCollection.class).changeItem(messageCollectionItem.getId(), messageCollectionItem))
                                                                logger.log(Level.WARNING, "Fail on update received message: " + messageCollectionItem.getId());
                                                        });
                                                        break;
                                                    }
                                                }
                                                break;
                                            }
                                            case "last": {
                                                for (int i = 0; i < current.size(); i++) {
                                                    var msgObj = current.get(i).getAsJsonArray().get(2).getAsJsonObject();
                                                    var msgBuilder = WebMessageInfo.newBuilder();
                                                    JsonFormat.parser().ignoringUnknownFields().merge(Util.GSON.toJson(msgObj), msgBuilder);
                                                    var msg = msgBuilder.build();
                                                    var messageCollectionItem = new MessageCollectionItem(this, JsonParser.parseString(JsonFormat.printer().print(msg)).getAsJsonObject());
                                                    runOnSync(() -> {
                                                        if (!getCollection(MessageCollection.class).hasItem(messageCollectionItem.getId()) && !getCollection(MessageCollection.class).tryAddItem(messageCollectionItem.getId(), messageCollectionItem))
                                                            logger.log(Level.WARNING, "Fail on add received last message to collection: " + messageCollectionItem.getId());
                                                        if (getCollection(ChatCollection.class).hasItem(messageCollectionItem.getRemoteJid()))
                                                            getCollection(ChatCollection.class).getItem(messageCollectionItem.getRemoteJid()).setLastMessage(messageCollectionItem);
                                                        else
                                                            logger.log(Level.WARNING, "Received last message but chat was not found: " + messageCollectionItem.getRemoteJid());
                                                    });
                                                }
                                                break;
                                            }

                                            default:
                                                logger.log(Level.WARNING, "Received unexpected action msg type: {" + addType + "} - with content: {" + current + "}");
                                        }
                                        break;
                                    }
                                    default:
                                        logger.log(Level.WARNING, "Received unexpected action type: {" + key + "} - with content: {" + actionsGrouped.get(key) + "}");
                                }
                            }
                            break;
                        }
                        default:
                            logger.log(Level.WARNING, "Received unexpected Binary type: {" + binaryType + "} - with content: {" + jsonDecoded + "}");
                    }
                }

            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "OnMessage", e);
        }
    }

    @Override
    public void onMessage(String message) {
        try {
            if (message.charAt(0) == '!') {
                var timestamp = Long.parseLong(message.substring(1));
                lastSeen = LocalDateTime.ofInstant(Instant.ofEpochMilli(timestamp), TimeZone.getDefault().toZoneId());
            } else {
                var msgSplit = message.split(",", 2);
                var msgTag = msgSplit[0];
                var msgContent = msgSplit[1];
                if (msgContent == null || msgContent.isEmpty()) {
                    return;
                }
                var jsonElement = JsonParser.parseString(msgContent);


                if (wsEvents.containsKey(msgTag)) {
                    var response = wsEvents.get(msgTag);
                    response.complete(jsonElement);
                } else if (jsonElement.isJsonArray()) {
                    var jsonArray = jsonElement.getAsJsonArray();
                    switch (jsonArray.get(0).getAsString()) {
                        case "Conn":
                            if (refreshQrCodeScheduler != null) {
                                refreshQrCodeScheduler.cancel(true);
                                refreshQrCodeScheduler = null;
                            }
                            var connResponse = Util.GSON.fromJson(jsonArray.get(1).getAsJsonObject(), ConnResponse.class);
                            authInfo.setBrowserToken(connResponse.getBrowserToken());
                            authInfo.setClientToken(connResponse.getClientToken());
                            authInfo.setServerToken(connResponse.getServerToken());
                            if (connResponse.getSecret() != null) {
                                authInfo.setSecret(connResponse.getSecret());
                            }
                            authInfo.setPushName(connResponse.getPushname());
                            authInfo.setWid(connResponse.getWid());
                            authInfo.setBusiness(connResponse.getPlatform().contains("smb"));
                            generateCommunicationKeys();
                            break;
                        case "Stream":
                            break;
                        case "Props":
                            break;
                        case "Msg":
                            var content = jsonArray.get(1).getAsJsonObject();
                            var cmd = content.get("cmd").getAsString();
                            switch (cmd) {
                                case "ack":
                                    if (!getCollection(MessageCollection.class).changeItem(content.get("id").getAsString(), content))
                                        logger.log(Level.WARNING, "Fail on update received message: " + content.get("id").getAsString());
                                    break;
                                case "acks":
                                    var ids = content.getAsJsonArray("id");
                                    for (int i = 0; i < ids.size(); i++) {
                                        var id = ids.get(i).getAsString();
                                        if (!getCollection(MessageCollection.class).changeItem(id, content))
                                            logger.log(Level.WARNING, "Fail on update received message: " + id);
                                    }
                                    break;
                                default:
                                    logger.log(Level.WARNING, "Received unexpected msg cmd: {" + cmd + "} with content {" + content + "}");
                            }
                            break;
                        default:
                            logger.log(Level.WARNING, "Received unexpected tag: {" + jsonArray.get(0).getAsString() + "} with content: {" + jsonArray + "}");
                    }
                }
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "OnMessage", e);
        }
    }

    @Override
    public void onClose(int code, String reason, boolean remote) {
        logger.log(Level.WARNING, "Ws Disconnected with code: {" + code + "} and reason: {" + reason + "}");
        synchronized (scheduledFutures) {
            for (var scheduledFuture : scheduledFutures) {
                if (!scheduledFuture.isCancelled())
                    scheduledFuture.cancel(true);
            }
            scheduledFutures.clear();
        }
    }

    @Override
    public void onError(Exception ex) {
        logger.log(Level.SEVERE, "Unexpected Error on WebSocket", ex);
    }
}
