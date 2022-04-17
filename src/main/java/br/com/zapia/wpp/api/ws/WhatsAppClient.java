package br.com.zapia.wpp.api.ws;

import br.com.zapia.wpp.api.ws.binary.BinaryArray;
import br.com.zapia.wpp.api.ws.binary.BinaryConstants;
import br.com.zapia.wpp.api.ws.binary.WABinaryDecoder;
import br.com.zapia.wpp.api.ws.binary.WABinaryEncoder;
import br.com.zapia.wpp.api.ws.binary.protos.*;
import br.com.zapia.wpp.api.ws.model.*;
import br.com.zapia.wpp.api.ws.model.communication.*;
import br.com.zapia.wpp.api.ws.utils.SortedJSONObject;
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
import org.json.JSONArray;
import org.json.JSONObject;
import org.jsoup.Jsoup;
import org.whispersystems.curve25519.Curve25519KeyPair;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.File;
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
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;

public class WhatsAppClient extends WebSocketClient {

    private static final Logger logger = Logger.getLogger(WhatsAppClient.class.getName());

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
    private final AsyncLoadingCache<String, CheckIdIsOnWhatsAppResponse> cacheCheckIdExist;
    private final List<ScheduledFuture<?>> scheduledFutures;
    private final Map<String, CompletableFuture<JsonElement>> wsEvents;
    private final Map<String, List<Consumer<NodeWhatsAppFrame>>> wsListeners;
    private final List<Runnable> runnableOnConnect;
    private boolean isSynced;
    private final boolean autoReconnect;
    private boolean mdVersion;

    private String serverId;
    private AuthInfo authInfo;
    private CommunicationKeys communicationKeys;
    private String lastQrCode;

    private final AtomicReference<CompletableFuture<IWhatsAppFrame>> awaiterNexMessage;
    private MDCreds mdCreds;
    private NoiseHandler noiseHandler;
    private Curve25519KeyPair ephemeralKeyPair;

    private DriverState driverState;
    private int msgCount;
    private LocalDateTime connectTime;
    private LocalDateTime lastSeen;
    private LocalDateTime lastSendPresence;
    private PresenceType lastPresenceType;
    private MediaConnResponse.MediaConn cacheMediaConnResponse;
    private ScheduledFuture<?> refreshQrCodeScheduler;
    private ScheduledFuture<?> keepAliveScheduled;

    public WhatsAppClient(AuthInfo authInfo, Consumer<String> onQrCode, boolean forceMd, Runnable onConnect, Consumer<AuthInfo> onAuthInfo, Consumer<DriverState> onChangeDriverState, Function<Runnable, Runnable> runnableFactory, Function<Callable, Callable> callableFactory, Function<Runnable, Thread> threadFactory, ExecutorService executorService, ScheduledExecutorService scheduledExecutorService) {
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
        this.wsListeners = new ConcurrentHashMap<>();
        this.scheduledFutures = new ArrayList<>();
        this.collections = new HashMap<>();
        this.cacheCheckIdExist = Caffeine.newBuilder()
                .maximumSize(10_000)
                .expireAfterWrite(Duration.ofMinutes(5))
                .buildAsync(number -> sendJson(new CheckIdIsOnWhatsApp(number).toJson(), CheckIdIsOnWhatsAppResponse.class).get());
        this.runnableOnConnect = new ArrayList<>();
        this.syncIsSynced = new Object();
        this.syncPresence = new Object();
        this.autoReconnect = true;
        this.awaiterNexMessage = new AtomicReference<>();
        setDriverState(DriverState.UNLOADED);
        setConnectionLostTimeout(0);
        getHeadersConnectWs().forEach(this::addHeader);
        if (forceMd) {
            mdVersion = true;
            uri = URI.create(Constants.WS_URL_MD);
        }
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
        return ("3EB0" + Util.bytesToHex(bytes)).toUpperCase();
    }

    private void runOnSync(Runnable runnable) {
        synchronized (syncIsSynced) {
            if (isSynced) {
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

    public CompletableFuture<IWhatsAppFrame> sendAndAwaitNextMessage(byte[] data) {
        var response = new CompletableFuture<IWhatsAppFrame>();
        awaiterNexMessage.set(response);
        try {
            sendRawMessage(data);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "SendAndAwaitNextMessage", e);
            response.completeExceptionally(e);
        }
        return response;
    }

    public void sendNode(JSONArray jsonArray) {
        var node = new WABinaryEncoder(true).write(Util.GSON.fromJson(jsonArray.toString(), JsonArray.class));
        sendRawMessage(node);
    }

    public void sendRawMessage(byte[] data) {
        try {
            var bytes = noiseHandler.encodeFrame(data);
            send(bytes);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "sendRawMessage", e);
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
            var binary = new WABinaryEncoder(false).write(jsonArray);

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
        collections.put(QuickReplyCollection.class, new QuickReplyCollection(this));
    }

    public <T extends BaseCollection<? extends BaseCollectionItem<?>>> T getCollection(Class<T> collectionType) {
        var collection = collections.get(collectionType);
        if (collection != null)
            return collectionType.cast(collection);

        return null;
    }

    private void initMdEventListeners() {
        onWsListener("CB:iq,type:set,pair-device", nodeWhatsAppFrame -> {
            var response = new JSONArray()
                    .put("iq")
                    .put(new SortedJSONObject().put("to", "@s.whatsapp.net").put("type", "result").put("id", nodeWhatsAppFrame.getAttrs().get("id").getAsString()))
                    .put(new JsonArray());
            sendNode(response);

            var refs = nodeWhatsAppFrame.getData().get(0).getAsJsonArray().get(2).getAsJsonArray();
            var count = new AtomicInteger(0);
            refreshQrCodeScheduler = schedule(() -> {
                var nextCount = count.getAndIncrement();
                if (nextCount > refs.size()) {
                    close(CloseFrame.ABNORMAL_CLOSE, "Ws Closed due to many QR refresh");
                } else {
                    var ref = refs.get(nextCount).getAsJsonArray().get(2).getAsString();
                    generateMDQrCode(ref);
                }
            }, 0, 60000, TimeUnit.MILLISECONDS);
        });
    }

    private void initLogin() {
        try {
            if (mdVersion) {
                initMdEventListeners();
                if (mdCreds == null) {
                    var signedIdentityKey = Util.CURVE_25519.generateKeyPair();
                    var noiseKeyPair = Util.CURVE_25519.generateKeyPair();
                    var signedPreKey = Util.signedKeyPair(signedIdentityKey, 1);
                    var registrationId = Util.getRandomBytes(2)[0] & 0x3fff;
                    var advSecretKey = Base64.getEncoder().encodeToString(Util.getRandomBytes(32));
                    var nextPreKeyId = 1;
                    var firstUnuploadedPreKeyId = 1;
                    var serverhasPreKeys = false;
                    mdCreds = new MDCreds(noiseKeyPair, signedIdentityKey, signedPreKey, registrationId, advSecretKey, nextPreKeyId, firstUnuploadedPreKeyId, serverhasPreKeys);
                }
                ephemeralKeyPair = Util.CURVE_25519.generateKeyPair();
                noiseHandler = new NoiseHandler(ephemeralKeyPair);
                noiseHandler.init();
                sendInitMD().thenAccept(handshakeMessage -> {
                    byte[] keyEnc;
                    try {
                        keyEnc = noiseHandler.processHandshake(handshakeMessage, mdCreds.getNoiseKey());
                    } catch (Exception e) {
                        logger.log(Level.SEVERE, "processHandshake", e);
                        close(CloseFrame.ABNORMAL_CLOSE, "Ws Closed due to exception on processHandshake");
                        return;
                    }

                    var node = mdCreds.getMeInfo() == null ? generateRegistrationNode() : generateLoginNode();

                    byte[] payloadEnc;

                    try {
                        payloadEnc = noiseHandler.encrypt(node);
                    } catch (Exception e) {
                        logger.log(Level.SEVERE, "encrypt node", e);
                        close(CloseFrame.ABNORMAL_CLOSE, "Ws Closed due to exception on encrypt node");
                        return;
                    }

                    var handShakeResponse = HandshakeMessage.newBuilder().setClientFinish(ClientFinish.newBuilder().setStatic(ByteString.copyFrom(keyEnc)).setPayload(ByteString.copyFrom(payloadEnc)));

                    try {
                        sendRawMessage(handShakeResponse.build().toByteArray());
                    } catch (Exception e) {
                        logger.log(Level.SEVERE, "sendRawMessage", e);
                        close(CloseFrame.ABNORMAL_CLOSE, "Ws Closed due to exception on sendRawMessage");
                        return;
                    }

                    noiseHandler.finishInit();

                    //TODO: startKeepAlive
                });
            } else {
                createCollections();
                if (authInfo == null) {
                    byte[] bytes = new byte[16];
                    SecureRandom.getInstanceStrong().nextBytes(bytes);
                    var clientId = Base64.getEncoder().encodeToString(bytes);
                    authInfo = new AuthInfo();
                    authInfo.setClientId(clientId);
                }
                startKeepAlive();
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
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "InitLogin", e);
            close(CloseFrame.ABNORMAL_CLOSE, "A error was occurred on initLogin, check logs to find the reason");
        }
    }

    private byte[] generateRegistrationNode() {

        var appVersionBuf = Base64.getDecoder().decode(Constants.ENCODED_VERSION);

        var companion = CompanionProps.newBuilder()
                .setOs(Constants.WS_BROWSER_DESC[0])
                .setVersion(AppVersion.newBuilder().setPrimary(10)).setPlatformType(CompanionProps.CompanionPropsPlatformType.CHROME)
                .setRequireFullSync(false);

        var companionRegData = CompanionRegData.newBuilder()
                .setBuildHash(ByteString.copyFrom(appVersionBuf))
                .setCompanionProps(companion.build().toByteString())
                .setERegid(ByteString.copyFrom(BinaryArray.of(mdCreds.getRegistrationId(), 4).data()))
                .setEKeytype(ByteString.copyFrom(BinaryArray.of(5, 1).data()))
                .setEIdent(ByteString.copyFrom(mdCreds.getSignedIdentityKey().getPublicKey()))
                .setESkeyId(ByteString.copyFrom(BinaryArray.of(mdCreds.getSignedPreKey().getKeyId(), 3).data()))
                .setESkeyVal(ByteString.copyFrom(mdCreds.getSignedPreKey().getKeyPair().getPublicKey()))
                .setESkeySig(ByteString.copyFrom(mdCreds.getSignedPreKey().getSignature()));

        var userAgent = UserAgent.newBuilder()
                .setAppVersion(AppVersion.newBuilder().setPrimary(Constants.WS_VERSION[0]).setSecondary(Constants.WS_VERSION[1]).setTertiary(Constants.WS_VERSION[2]))
                .setPlatform(UserAgent.UserAgentPlatform.WEB)
                .setReleaseChannel(UserAgent.UserAgentReleaseChannel.RELEASE)
                .setMcc("000")
                .setMnc("000")
                .setDevice(Constants.WS_BROWSER_DESC[1])
                .setOsVersion(Constants.WS_BROWSER_DESC[2])
                .setManufacturer("")
                .setOsBuildNumber("0.1")
                .setLocaleLanguageIso6391("en")
                .setLocaleCountryIso31661Alpha2("US");

        var clientPayLoad = ClientPayload.newBuilder();
        clientPayLoad.setConnectReason(ClientPayload.ClientPayloadConnectReason.USER_ACTIVATED)
                .setConnectType(ClientPayload.ClientPayloadConnectType.WIFI_UNKNOWN)
                .setPassive(true)
                .setRegData(companionRegData)
                .setUserAgent(userAgent)
                .setWebInfo(WebInfo.newBuilder().setWebSubPlatform(WebInfo.WebInfoWebSubPlatform.WEB_BROWSER));

        return clientPayLoad.build().toByteArray();
    }

    private byte[] generateLoginNode() {
        return null;
    }

    private CompletableFuture<InitResponse> sendInit() {
        setDriverState(DriverState.INITIALIZING);
        return sendJson(new InitRequest(authInfo.getClientId()).toJson(), InitResponse.class);
    }

    private CompletableFuture<HandshakeMessage> sendInitMD() {
        setDriverState(DriverState.INITIALIZING);

        var init = HandshakeMessage.newBuilder().setClientHello(ClientHello.newBuilder().setEphemeral(ByteString.copyFrom(ephemeralKeyPair.getPublicKey()))).build();
        return sendAndAwaitNextMessage(init.toByteArray()).thenApply(whatsAppFrame -> {
            try {
                return HandshakeMessage.parseFrom(((BinaryWhatsAppFrame) whatsAppFrame).getData());
            } catch (Exception e) {
                logger.log(Level.SEVERE, "sendInitMD", e);
                throw new CompletionException(e);
            }
        });
    }

    private void initNewSession() {
        try {
            setDriverState(DriverState.INIT_NEW_SESSION);
            var keyPair = Util.CURVE_25519.generateKeyPair();
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

    private CompletableFuture<Boolean> respondToChallenge(String challenge) throws Exception {
        setDriverState(DriverState.RESOLVING_CHALLENGE);
        var bytes = Base64.getDecoder().decode(challenge);

        var tempCommunicationKeys = generateCommunicationKeys();

        var hmac = Hashing.hmacSha256(tempCommunicationKeys.getMacKey())
                .newHasher()
                .putBytes(bytes)
                .hash().asBytes();

        var signed = Base64.getEncoder().encodeToString(hmac);

        var json = new JSONArray()
                .put("admin")
                .put("challenge")
                .put(signed)
                .put(authInfo.getServerToken())
                .put(authInfo.getClientId());

        return sendJson(json.toString(), JsonObject.class).thenApply(jsonObject -> {
            if (jsonObject.get("status").getAsInt() == 200)
                return true;

            logger.log(Level.SEVERE, "Failed to resolve challenge {status: " + jsonObject.get("status") + "}, starting a new one");
            return false;
        });
    }

    private void generateMDQrCode(String ref) {
        try {
            var stringQrCode = ref + "," + Base64.getEncoder().encodeToString(mdCreds.getNoiseKey().getPublicKey()) + "," + Base64.getEncoder().encodeToString(mdCreds.getSignedIdentityKey().getPublicKey()) + "," + mdCreds.getAdvSecretKey();
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

    private CommunicationKeys generateCommunicationKeys() throws Exception {
        try {
            var decodedSecret = Base64.getDecoder().decode(authInfo.getSecret());
            if (decodedSecret.length != 144) {
                throw new Exception("incorrect secret length received: " + decodedSecret.length);
            }

            var sharedKey = Util.CURVE_25519.calculateAgreement(Arrays.copyOf(decodedSecret, 32), Base64.getDecoder().decode(authInfo.getPrivateKey()));

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

            return new CommunicationKeys(sharedKey, expandedKey, keysEncrypted, keysDecrypted, encKey, macKey);

        } catch (Exception e) {
            logger.log(Level.SEVERE, "GenerateCommunicationKeys", e);
            throw e;
        }
    }

    //See WhatsApp Web {openStream} function
    private CompletableFuture<Void> syncCollections() {
        setDriverState(DriverState.WAITING_SYNC);
        /*sendBinary(new BaseQuery("quick_reply", "1", null).toJsonArray(), new BinaryConstants.WA.WATags(BinaryConstants.WA.WAMetric.queryQuickReply, BinaryConstants.WA.WAFlag.ignore), JsonElement.class).thenAccept(jsonElement -> {
            System.out.println(jsonElement);
        });*/
        var chat = getCollection(ChatCollection.class).sync();
        var contact = getCollection(ContactCollection.class).sync();
        var quickReply = authInfo.isBusiness() ? getCollection(QuickReplyCollection.class).sync() : CompletableFuture.allOf();
        return CompletableFuture.allOf(chat, contact, quickReply);
        /**
         * sendBinary(new BaseQuery("status", "1", null).toJsonArray(), new BinaryConstants.WA.WATags(BinaryConstants.WA.WAMetric.queryStatus, BinaryConstants.WA.WAFlag.ignore), null);
         *             if (authInfo.isBusiness()) {
         *                 sendBinary(new BaseQuery("quick_reply", "1", null).toJsonArray(), new BinaryConstants.WA.WATags(BinaryConstants.WA.WAMetric.queryQuickReply, BinaryConstants.WA.WAFlag.ignore), null);
         *             }
         */
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

    public CompletableFuture<CheckIdIsOnWhatsAppResponse> checkNumberExist(String number) {
        return checkIdExist(number + "@c.us");
    }

    public CompletableFuture<CheckIdIsOnWhatsAppResponse> checkIdExist(String id) {
        return cacheCheckIdExist.get(id);
    }

    public CompletableFuture<ChatCollectionItem> findChatFromNumber(String number) {
        return checkNumberExist(number).thenCompose(checkIdIsOnWhatsAppResponse -> {
            if (checkIdIsOnWhatsAppResponse.getStatus() == 200) {
                return findChatFromId(checkIdIsOnWhatsAppResponse.getJid());
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
            if (contactCollectionItem == null)
                return null;

            //TODO: others default properties
            var jsonObject = new JsonObject();
            jsonObject.addProperty("jid", contactCollectionItem.getId());
            var chat = new ChatCollectionItem(this, jsonObject);
            if (!getCollection(ChatCollection.class).tryAddItem(chat)) {
                logger.log(Level.SEVERE, "Fail on add chat to collection: " + id);
                throw new RuntimeException("Fail on add chat to collection: " + id);
            }

            return chat;
        });
    }

    public CompletableFuture<ContactCollectionItem> findContactFromNumber(String number) {
        return checkNumberExist(number).thenCompose(checkIdIsOnWhatsAppResponse -> {
            if (checkIdIsOnWhatsAppResponse.getStatus() == 200) {
                return findContactFromId(checkIdIsOnWhatsAppResponse.getJid());
            }
            return CompletableFuture.completedFuture(null);
        });
    }

    public CompletableFuture<ContactCollectionItem> findContactFromId(String id) {
        var contactCache = getCollection(ContactCollection.class).getItem(id);
        if (contactCache != null) {
            return CompletableFuture.completedFuture(contactCache);
        }

        return checkIdExist(id).thenApply(checkIdIsOnWhatsAppResponse -> {
            if (checkIdIsOnWhatsAppResponse.getStatus() == 200) {

                //TODO: others default properties
                var jsonObject = new JsonObject();
                jsonObject.addProperty("jid", id);
                var contact = new ContactCollectionItem(this, jsonObject);
                if (!getCollection(ContactCollection.class).tryAddItem(contact)) {
                    logger.log(Level.SEVERE, "Fail on add contact to collection: " + id);
                    throw new RuntimeException("Fail on add contact to collection: " + id);
                }

                return contact;
            }

            return null;
        });
    }

    public CompletableFuture<byte[]> findProfilePicture(String jid) {
        var query = new JsonArray();
        query.add("query");
        query.add("ProfilePicThumb");
        query.add(Util.convertJidToSend(jid));
        return sendJson(Util.GSON.toJson(query), JsonObject.class).thenApply(jsonObject -> {
            if (jsonObject.has("eurl") && !jsonObject.get("eurl").getAsString().isEmpty()) {
                try {
                    HttpRequest httpRequest = HttpRequest.newBuilder()
                            .header("Origin", Constants.ORIGIN_WS)
                            .GET()
                            .uri(URI.create(jsonObject.get("eurl").getAsString()))
                            .build();
                    var client = HttpClient.newHttpClient();

                    var response = client.send(httpRequest, HttpResponse.BodyHandlers.ofByteArray());
                    return response.body();
                } catch (Exception e) {
                    logger.log(Level.SEVERE, "downloadProfilePicture", e);
                    throw new RuntimeException(e);
                }
            }
            return null;
        });
    }

    public CompletableFuture<Boolean> updateProfilePicture(File file) {
        try {
            return updateProfilePicture(Util.encodeFile(file));
        } catch (Exception e) {
            logger.log(Level.SEVERE, "UpdateProfilePicture", e);
            return CompletableFuture.failedFuture(e);
        }
    }

    public CompletableFuture<Boolean> updateProfilePicture(String base64Picture) {
        try {
            var msgTag = generateMessageTag(false);


            var actionQuery = new JSONArray();
            actionQuery
                    .put("action")
                    .put(new SortedJSONObject().put("epoch", String.valueOf(msgCount)).put("type", "set"))
                    .put(new JSONArray().put(
                            new JSONArray()
                                    .put("picture")
                                    .put(new SortedJSONObject().put("jid", Util.convertJidToSend(authInfo.getWid())).put("id", msgTag).put("type", "set"))
                                    .put(
                                            new JSONArray()
                                                    .put(new JSONArray().put("image").put(JSONObject.NULL).put(Util.scaleImage(Base64.getDecoder().decode(base64Picture), 640, 640)))
                                                    .put(new JSONArray().put("preview").put(JSONObject.NULL).put(Util.scaleImage(Base64.getDecoder().decode(base64Picture), 96, 96)))
                                    )
                    ));
            return sendBinary(msgTag, Util.GSON.fromJson(actionQuery.toString(), JsonArray.class), new BinaryConstants.WA.WATags(BinaryConstants.WA.WAMetric.picture, BinaryConstants.WA.WAFlag.other), JsonObject.class).thenApply(jsonObject -> {
                return jsonObject.has("status") && jsonObject.get("status").getAsInt() == 200;
            });
        } catch (Exception e) {
            logger.log(Level.SEVERE, "UpdateProfilePicture", e);
            return CompletableFuture.failedFuture(e);
        }
    }

    public CompletableFuture<Boolean> clearChat(String jid, boolean includeStarred) {
        return findChatFromId(jid).thenCompose(chatCollectionItem -> {
            if (chatCollectionItem == null) {
                logger.log(Level.SEVERE, "Chat not found to clear messages {" + jid + "}");
                return CompletableFuture.completedFuture(false);
            }
            return clearChat(chatCollectionItem, includeStarred);
        });
    }

    public CompletableFuture<Boolean> clearChat(ChatCollectionItem chatCollectionItem, boolean includeStarred) {
        return getChatIndex(chatCollectionItem).thenCompose(chatIndex -> {
            var actionQuery = new JSONArray();
            actionQuery
                    .put("action")
                    .put(new SortedJSONObject().put("epoch", String.valueOf(msgCount)).put("type", "set"))
                    .put(new JSONArray().put(
                            new JSONArray()
                                    .put("chat")
                                    .put(chatIndex.put("jid", Util.convertJidToSend(chatCollectionItem.getId())).put("type", "clear").put("star", includeStarred ? "true" : "false"))
                                    .put(JSONObject.NULL)
                    ));

            return sendBinary(Util.GSON.fromJson(actionQuery.toString(), JsonArray.class), new BinaryConstants.WA.WATags(BinaryConstants.WA.WAMetric.chat, BinaryConstants.WA.WAFlag.ignore), JsonObject.class).thenApply(jsonObject -> {
                if (jsonObject.get("status").getAsInt() == 200) {
                    var lastMsgId = String.valueOf(chatIndex.get("index"));
                    var msgsRemove = chatCollectionItem.getMessages().stream().filter(messageCollectionItem -> !messageCollectionItem.getId().equals(lastMsgId) && (!includeStarred || !messageCollectionItem.isStarred())).map(BaseCollectionItem::getId).toList().toArray(new String[0]);
                    chatCollectionItem.removeMessages(msgsRemove);
                    getCollection(MessageCollection.class).tryRemoveItems(msgsRemove);
                    return true;
                }

                return false;
            });
        });
    }

    public CompletableFuture<JsonElement> deleteMessage(MessageCollectionItem messageCollectionItem) {
        return findChatFromId(messageCollectionItem.getRemoteJid()).thenCompose(chatCollectionItem -> {
            var tag = Math.round(new Random().nextInt() * 1000000);
            var actionQuery = new JSONArray();
            actionQuery
                    .put("action")
                    .put(new SortedJSONObject().put("epoch", String.valueOf(msgCount)).put("type", "set"))
                    .put(new JSONArray().put(
                            new JSONArray()
                                    .put("chat")
                                    .put(new SortedJSONObject().put("jid", Util.convertJidToSend(chatCollectionItem.getId())).put("modify_tag", String.valueOf(tag)).put("type", "clear"))
                                    .put(
                                            new JSONArray()
                                                    .put(new JSONArray().put("item").put(new SortedJSONObject().put("owner", messageCollectionItem.isFromMe() ? "true" : "false").put("index", messageCollectionItem.getId())).put(JSONObject.NULL))
                                    )
                    ));

            return sendBinary(Util.GSON.fromJson(actionQuery.toString(), JsonArray.class), new BinaryConstants.WA.WATags(BinaryConstants.WA.WAMetric.chat, BinaryConstants.WA.WAFlag.ignore), JsonObject.class).thenApply(jsonObject -> {
                if (jsonObject.get("status").getAsInt() == 200) {
                    chatCollectionItem.removeMessage(messageCollectionItem.getId());
                    if (!getCollection(MessageCollection.class).tryRemoveItem(messageCollectionItem.getId())) {
                        logger.log(Level.SEVERE, "Fail on remove message {" + messageCollectionItem.getId() + "} from chat {" + chatCollectionItem.getId() + "}");
                    }
                }
                return jsonObject;
            });
        });
    }

    public CompletableFuture<JsonElement> revokeMessage(MessageCollectionItem messageCollectionItem) {
        if (messageCollectionItem.isFromMe()) {
            var protocolMessageBuilder = ProtocolMessage.newBuilder();
            protocolMessageBuilder.setKey(MessageKey.newBuilder().setRemoteJid(Util.convertJidToSend(messageCollectionItem.getRemoteJid())).setFromMe(messageCollectionItem.isFromMe()).setId(messageCollectionItem.getId()))
                    .setType(ProtocolMessage.ProtocolMessageType.REVOKE);

            var msg = generateMessageFromContent(messageCollectionItem.getRemoteJid(), Message.newBuilder().setProtocolMessage(protocolMessageBuilder));

            return relayMessage(msg);
        }
        return CompletableFuture.completedFuture(new JsonObject());
    }

    //TODO: generateForwardMessageContextInfo
    /*public CompletableFuture<JsonElement> forwardMessage(String jid, MessageCollectionItem messageCollectionItem) {
        return findChatFromId(jid).thenCompose(chatCollectionItem -> {
            if (chatCollectionItem == null) {
                return CompletableFuture.completedFuture(null);
            }
            var webMsgInfo = new AtomicReference<WebMessageInfo>();
            try {
                webMsgInfo.set(Util.convertMessageCollectionItemToWebMessageInfo(messageCollectionItem));
            } catch (Exception e) {
                logger.log(Level.SEVERE, "Error on convert to webMsgInfo", e);
                return CompletableFuture.failedFuture(e);
            }

            var score = 0;

        });
    }*/

    public CompletableFuture<Boolean> pinChat(String jid) {
        return findChatFromId(jid).thenCompose(chatCollectionItem -> {
            if (chatCollectionItem == null) {
                return CompletableFuture.failedFuture(new Exception("Chat not found to pin: " + jid));
            }

            return pinChat(chatCollectionItem);
        });
    }

    public CompletableFuture<Boolean> pinChat(ChatCollectionItem chatCollectionItem) {
        var pinTime = System.currentTimeMillis() / 1000L;
        var actionQuery = new JSONArray();
        actionQuery
                .put("action")
                .put(new SortedJSONObject().put("epoch", String.valueOf(msgCount)).put("type", "set"))
                .put(new JSONArray().put(
                        new JSONArray()
                                .put("chat")
                                .put(new SortedJSONObject().put("jid", Util.convertJidToSend(chatCollectionItem.getId())).put("type", "pin").put("pin", pinTime))
                                .put(JSONObject.NULL)
                ));

        return sendBinary(Util.GSON.fromJson(actionQuery.toString(), JsonArray.class), new BinaryConstants.WA.WATags(BinaryConstants.WA.WAMetric.chat, BinaryConstants.WA.WAFlag.ignore), JsonObject.class).thenApply(jsonObject -> {
            if (jsonObject.get("status").getAsInt() == 200) {
                chatCollectionItem.setPin((int) pinTime);
                return true;
            }
            return false;
        });
    }

    public CompletableFuture<Boolean> unPinChat(String jid) {
        return findChatFromId(jid).thenCompose(chatCollectionItem -> {
            if (chatCollectionItem == null) {
                return CompletableFuture.failedFuture(new Exception("Chat not found to pin: " + jid));
            }

            return unPinChat(chatCollectionItem);
        });
    }

    public CompletableFuture<Boolean> unPinChat(ChatCollectionItem chatCollectionItem) {
        var actionQuery = new JSONArray();
        actionQuery
                .put("action")
                .put(new SortedJSONObject().put("epoch", String.valueOf(msgCount)).put("type", "set"))
                .put(new JSONArray().put(
                        new JSONArray()
                                .put("chat")
                                .put(new SortedJSONObject().put("jid", Util.convertJidToSend(chatCollectionItem.getId())).put("type", "pin").put("previous", chatCollectionItem.getPin()))
                                .put(JSONObject.NULL)
                ));

        return sendBinary(Util.GSON.fromJson(actionQuery.toString(), JsonArray.class), new BinaryConstants.WA.WATags(BinaryConstants.WA.WAMetric.chat, BinaryConstants.WA.WAFlag.ignore), JsonObject.class).thenApply(jsonObject -> {
            if (jsonObject.get("status").getAsInt() == 200) {
                chatCollectionItem.setPin(0);
                return true;
            }
            return false;
        });
    }

    public CompletableFuture<Boolean> markChatRead(String jid) {
        return findChatFromId(jid).thenCompose(chatCollectionItem -> {
            if (chatCollectionItem == null)
                return CompletableFuture.completedFuture(false);
            return markChatRead(chatCollectionItem);
        });
    }

    public CompletableFuture<Boolean> markChatRead(ChatCollectionItem chatCollectionItem) {
        return markChatUnReadOrRead(chatCollectionItem, true).thenApply(aBoolean -> {
            if (aBoolean)
                chatCollectionItem.setUnreadMessages(0);
            return aBoolean;
        });
    }

    public CompletableFuture<Boolean> markChatUnRead(String jid) {
        return findChatFromId(jid).thenCompose(chatCollectionItem -> {
            if (chatCollectionItem == null)
                return CompletableFuture.completedFuture(false);
            return markChatUnRead(chatCollectionItem);
        });
    }

    public CompletableFuture<Boolean> markChatUnRead(ChatCollectionItem chatCollectionItem) {
        return markChatUnReadOrRead(chatCollectionItem, false).thenApply(aBoolean -> {
            if (aBoolean)
                chatCollectionItem.setUnreadMessages(-1);
            return aBoolean;
        });
    }

    private CompletableFuture<Boolean> markChatUnReadOrRead(ChatCollectionItem chatCollectionItem, boolean read) {
        if (read && chatCollectionItem.getUnreadMessages() == 0) {
            return CompletableFuture.completedFuture(true);
        }

        if (!read && (chatCollectionItem.getUnreadMessages() == -1 || chatCollectionItem.getUnreadMessages() > 0)) {
            return CompletableFuture.completedFuture(true);
        }

        return getChatIndex(chatCollectionItem).thenCompose(chatIndex -> {
            var count = !read ? -2 : chatCollectionItem.getUnreadMessages();
            var actionQuery = new JSONArray();
            actionQuery
                    .put("action")
                    .put(new SortedJSONObject().put("epoch", String.valueOf(msgCount)).put("type", "set"))
                    .put(new JSONArray().put(
                            new JSONArray()
                                    .put("read")
                                    .put(chatIndex.put("jid", Util.convertJidToSend(chatCollectionItem.getId())).put("count", String.valueOf(count)))
                                    .put(JSONObject.NULL)
                    ));
            return sendBinary(Util.GSON.fromJson(actionQuery.toString(), JsonArray.class), new BinaryConstants.WA.WATags(BinaryConstants.WA.WAMetric.read, BinaryConstants.WA.WAFlag.ignore), JsonObject.class).thenApply(jsonObject1 -> {
                return jsonObject1.get("status").getAsInt() == 200;
            });
        });
    }

    private CompletableFuture<JSONObject> getChatIndex(String jid) {
        return findChatFromId(jid).thenCompose(chatCollectionItem -> {
            if (chatCollectionItem == null) {
                return CompletableFuture.failedFuture(new Exception("Chat not found to build chatIndex: " + jid));
            }
            return getChatIndex(chatCollectionItem);
        });
    }

    private CompletableFuture<JSONObject> getChatIndex(ChatCollectionItem chatCollectionItem) {
        var msgs = new CompletableFuture<List<MessageCollectionItem>>();
        if (chatCollectionItem.getMessages().isEmpty()) {
            chatCollectionItem.loadMessages(1).thenAccept(msgs::complete);
        } else {
            msgs.complete(chatCollectionItem.getMessages());
        }
        return msgs.thenApply(messageCollectionItems -> {
            var lastMsg = messageCollectionItems.get(messageCollectionItems.size() - 1);

            var jsonObject = new SortedJSONObject().put("index", lastMsg.getId()).put("owner", lastMsg.isFromMe() ? "true" : "false");
            if (Util.isGroupJid(chatCollectionItem.getId())) {
                if (lastMsg.isFromMe()) {
                    jsonObject.put("participant", Util.convertJidToSend(authInfo.getWid()));
                } else {
                    jsonObject.put("participant", Util.convertJidToSend(lastMsg.getParticipant()));
                }
            }
            return jsonObject;
        });
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
                        if (((JsonArray) jsonElement).get(2).isJsonArray()) {
                            var jsonArray = ((JsonArray) jsonElement).get(2).getAsJsonArray();
                            for (int i = 0; i < jsonArray.size(); i++) {
                                messagesList.add(new MessageCollectionItem(this, jsonArray.get(i).getAsJsonArray().get(2).getAsJsonObject()));
                            }

                            var chat = getCollection(ChatCollection.class).getItem(jid);

                            var msgsArray = messagesList.toArray(new MessageCollectionItem[0]);

                            if (!getCollection(MessageCollection.class).tryAddItems(msgsArray)) {
                                logger.log(Level.SEVERE, "Fail on add received messages to collection");
                                throw new RuntimeException("Fail on add received messages to collection");
                            }

                            chat.addMessages(msgsArray);
                        }

                    } catch (Exception e) {
                        logger.log(Level.SEVERE, "LoadMessages", e);
                    }
                    return messagesList;
                });
    }

    public CompletableFuture<MessageCollectionItem> sendMessage(String jid, SendMessageRequest messageSend) {
        return findChatFromId(jid).thenCompose(chatCollectionItem -> {
            if (chatCollectionItem == null) {
                logger.log(Level.SEVERE, "Chat not found to send message. {" + jid + "}");
                return CompletableFuture.failedFuture(new Exception("Chat not found to send message. {" + jid + "}"));
            }

            return sendMessage(chatCollectionItem, messageSend);
        });
    }

    public CompletableFuture<MessageCollectionItem> sendMessage(ChatCollectionItem chatCollectionItem, SendMessageRequest messageSend) {
        return sendPresence(PresenceType.AVAILABLE).thenCompose(ignore -> {
            var readChatIfNeed = chatCollectionItem.getUnreadMessages() > 0 ? markChatRead(chatCollectionItem) : CompletableFuture.completedFuture(true);
            return readChatIfNeed.thenCompose(aBoolean ->
                    prepareMessageContent(messageSend).thenCompose(content ->
                            buildAndRelayMessage(chatCollectionItem, generateMessageFromContent(chatCollectionItem.getId(), content))));
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
                        msgBuilder.setConversation(Util.emptyStringOrValue(messageSend.getText()));
                    } else {
                        var extendedTextBuilder = ExtendedTextMessage.newBuilder();
                        extendedTextBuilder
                                .setText(Util.emptyStringOrValue(messageSend.getText()))
                                .setContextInfo(contextInfo);
                        msgBuilder.setExtendedTextMessage(extendedTextBuilder);
                    }
                    return CompletableFuture.completedFuture(msgBuilder);
                }
                case EXTENDED_TEXT: {
                    var extendedTextBuilder = ExtendedTextMessage.newBuilder();
                    extendedTextBuilder
                            .setText(Util.emptyStringOrValue(messageSend.getText()))
                            .setCanonicalUrl(messageSend.getWebSite())
                            .setMatchedText(messageSend.getWebSite());
                    var docWebSite = Jsoup.connect(messageSend.getWebSite()).get();
                    var title = docWebSite.title();
                    var description = docWebSite.select("meta[name=description]").first();
                    var image = docWebSite.select("meta[property=og:image]").first();

                    if (image != null) {
                        HttpRequest httpRequest = HttpRequest.newBuilder()
                                .header("Origin", Constants.ORIGIN_WS)
                                .GET()
                                .uri(URI.create(image.attr("content")))
                                .build();

                        var client = HttpClient.newHttpClient();
                        var response = client.send(httpRequest, HttpResponse.BodyHandlers.ofByteArray());
                        if (response.statusCode() >= 400) {
                            logger.log(Level.WARNING, "Fail on download image logo to build website preview message");
                        } else {
                            extendedTextBuilder.setJpegThumbnail(ByteString.copyFrom(response.body()));
                        }
                    }

                    if (description != null) {
                        extendedTextBuilder.setDescription(description.attr("content"));
                    }

                    extendedTextBuilder.setTitle(Util.emptyStringOrValue(title));
                    if (contextInfo != null) {
                        extendedTextBuilder.setContextInfo(contextInfo);
                    }
                    msgBuilder.setExtendedTextMessage(extendedTextBuilder);
                    return CompletableFuture.completedFuture(msgBuilder);
                }
                case LOCATION:
                case LIVE_LOCATION: {
                    var locationMsgBuilder = LocationMessage.newBuilder();
                    locationMsgBuilder
                            .setDegreesLatitude(messageSend.getLocation().getLat())
                            .setDegreesLongitude(messageSend.getLocation().getLng())
                            .setAddress(Util.emptyStringOrValue(messageSend.getLocation().getName()));
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
                        logger.log(Level.SEVERE, "Error uploading media to {" + host.getHostname() + "}" + append, e);
                    }
                }

                return msgBuilder;

            } catch (Exception e) {
                logger.log(Level.SEVERE, "PrepareMessageMedia", e);
                throw new CompletionException(e);
            }
        }, executorService);
    }

    private WebMessageInfo generateMessageFromContent(String jid, Message.Builder content) {
        var builder = WebMessageInfo.newBuilder();
        builder
                .setKey(MessageKey.newBuilder().setRemoteJid(Util.convertJidToSend(jid)).setFromMe(true).setId(generateMessageID()))
                .setMessage(content)
                .setMessageTimestamp(System.currentTimeMillis() / 1000L)
                .setStatus(WebMessageInfo.WebMessageInfoStatus.PENDING);
        if (jid.contains("@g.us")) {
            builder.setParticipant(authInfo.getWid());
        }
        return builder.build();
    }

    private CompletableFuture<JsonElement> relayMessage(WebMessageInfo msg) {
        var actionQuery = new JSONArray();
        actionQuery
                .put("action")
                .put(new SortedJSONObject().put("epoch", String.valueOf(msgCount)).put("type", "relay"))
                .put(new JSONArray().put(
                        new JSONArray()
                                .put("message")
                                .put(JSONObject.NULL)
                                .put(new JSONArray(msg.toByteArray()))
                ));

        return sendBinary(
                msg.getKey().getId(),
                Util.GSON.fromJson(actionQuery.toString(), JsonArray.class),
                new BinaryConstants.WA.WATags(BinaryConstants.WA.WAMetric.message, msg.getKey().getRemoteJid().equals(authInfo.getWid()) ? BinaryConstants.WA.WAFlag.acknowledge : BinaryConstants.WA.WAFlag.ignore),
                JsonElement.class);
    }

    private CompletableFuture<MessageCollectionItem> buildAndRelayMessage(ChatCollectionItem chatCollectionItem, WebMessageInfo msg) {
        var messageCollectionItem = new AtomicReference<MessageCollectionItem>(null);
        try {
            messageCollectionItem.set(new MessageCollectionItem(this, JsonParser.parseString(JsonFormat.printer().print(msg)).getAsJsonObject()));
            if (!getCollection(MessageCollection.class).tryAddItem(messageCollectionItem.get()))
                throw new RuntimeException("Error on add to MessageCollection");
            chatCollectionItem.addMessage(messageCollectionItem.get());
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error on build MessageCollectionItem before send", e);
            return CompletableFuture.failedFuture(e);
        }

        return relayMessage(msg).thenApply(jsonElement -> {
            //TODO: check return status
            return messageCollectionItem.get();
        });
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

    private boolean dispatchWsListener(String tag, NodeWhatsAppFrame frame) {
        var triggered = false;
        if (wsListeners.containsKey(tag)) {
            triggered = true;
            for (Consumer<NodeWhatsAppFrame> iWhatsAppFrameCallable : wsListeners.get(tag)) {
                iWhatsAppFrameCallable.accept(frame);
            }
        }

        return triggered;
    }

    private void onWsListener(String tag, Consumer<NodeWhatsAppFrame> consumer) {
        if (!wsListeners.containsKey(tag)) {
            wsListeners.put(tag, new ArrayList<>());
        }

        var consumerMock = new Consumer<NodeWhatsAppFrame>() {
            @Override
            public void accept(NodeWhatsAppFrame nodeWhatsAppFrame) {
                executorService.submit(() -> consumer.accept(nodeWhatsAppFrame));
            }
        };

        wsListeners.get(tag).add(consumerMock);
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

    public AuthInfo getAuthInfo() {
        return authInfo;
    }

    public LocalDateTime getConnectTime() {
        return connectTime;
    }

    @Override
    public void connect() {
        super.connect();
        setDriverState(DriverState.CONNECTING);
    }

    @Override
    public void onOpen(ServerHandshake handshakedata) {
        wsEvents.clear();
        wsListeners.clear();
        collections.clear();
        executorService.submit(runnableFactory.apply(this::initLogin));
    }

    @Override
    public void onMessage(ByteBuffer bytes) {
        try {
            if (mdVersion) {
                var results = noiseHandler.decodeFrame(bytes.array());
                var awaiter = awaiterNexMessage.getAndSet(null);
                for (IWhatsAppFrame result : results) {
                    var triggered = false;
                    if (awaiter != null) {
                        triggered = true;
                        awaiter.completeAsync(() -> result, executorService);
                    }

                    if (result instanceof NodeWhatsAppFrame nodeWhatsAppFrame) {

                        var tag = nodeWhatsAppFrame.getTag();
                        var attributes = nodeWhatsAppFrame.getAttrs();
                        var data = nodeWhatsAppFrame.getData();

                        var msgId = attributes.has("id") && attributes.get("id").isJsonPrimitive() ? attributes.get("id").getAsString() : "";
                        var firstDataTag = data.size() > 0 && data.get(0).isJsonArray() ? data.get(0).getAsJsonArray().get(0).getAsString() : "";

                        triggered = dispatchWsListener("%s%s".formatted(Constants.DEF_TAG_PREFIX, msgId), nodeWhatsAppFrame) || triggered;


                        for (String keyObj : attributes.keySet()) {
                            var value = attributes.get(keyObj).getAsString();
                            triggered = dispatchWsListener("%s%s,%s:%s,%s".formatted(Constants.DEF_CALLBACK_PREFIX, tag, keyObj, value, firstDataTag), nodeWhatsAppFrame) || triggered;
                            triggered = dispatchWsListener("%s%s,%s:%s".formatted(Constants.DEF_CALLBACK_PREFIX, tag, keyObj, value), nodeWhatsAppFrame) || triggered;
                            triggered = dispatchWsListener("%s%s,%s".formatted(Constants.DEF_CALLBACK_PREFIX, tag, keyObj), nodeWhatsAppFrame) || triggered;
                        }

                        triggered = dispatchWsListener("%s%s,,%s".formatted(Constants.DEF_CALLBACK_PREFIX, tag, firstDataTag), nodeWhatsAppFrame) || triggered;
                        triggered = dispatchWsListener("%s%s".formatted(Constants.DEF_CALLBACK_PREFIX, tag), nodeWhatsAppFrame) || triggered;

                        if (!triggered) {
                            logger.log(Level.WARNING, "Received unexpected message {msgId: %s, data: %s}".formatted(msgId, new Gson().toJson(nodeWhatsAppFrame.getNode())));
                        }

                        /*switch (tag) {
                            case "iq": {
                                switch (firstDataTag) {
                                    case "pair-device": {
                                        var response = new JSONArray()
                                                .put("iq")
                                                .put(new SortedJSONObject().put("to", "@s.whatsapp.net").put("type", "result").put("id", attributes.get("id").getAsString()))
                                                .put(new JsonArray());
                                        sendNode(response);
                                        break;
                                    }
                                    default: {
                                        logger.log(Level.WARNING, "Received unexpected iq tag : {" + firstDataTag + "} - with content: {" + data + "}");
                                    }
                                }
                                break;
                            }
                            default: {
                                logger.log(Level.WARNING, "Received unexpected tag type: {" + tag + "} - with content: {" + nodeWhatsAppFrame.getNode() + "}");
                            }
                        }*/
                    }
                }
            } else {
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

                    var binaryDecoder = new WABinaryDecoder(decryptedBytes, false);
                    var jsonDecoded = binaryDecoder.read();

                    if (wsEvents.containsKey(msgTag)) {
                        var response = wsEvents.get(msgTag);
                        executorService.submit(runnableFactory.apply(() -> {
                            response.complete(jsonDecoded);
                        }));
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
                                        chatCollection.getSyncFuture().complete(jsonDecoded);
                                        break;
                                    }
                                    case "contacts": {
                                        var contactCollection = getCollection(ContactCollection.class);
                                        contactCollection.getSyncFuture().complete(jsonDecoded);
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
                                                            if (!getCollection(MessageCollection.class).tryAddItem(messageCollectionItem))
                                                                logger.log(Level.SEVERE, "Fail on add received message to collection: " + messageCollectionItem.getId());
                                                            runOnSync(() -> {
                                                                findChatFromId(messageCollectionItem.getRemoteJid()).thenAccept(chatCollectionItem -> {
                                                                    if (chatCollectionItem == null)
                                                                        logger.log(Level.WARNING, "Received new message but chat was not found: " + messageCollectionItem.getId());
                                                                    else
                                                                        chatCollectionItem.addMessage(messageCollectionItem);
                                                                });
                                                            });
                                                            break;
                                                        }
                                                        case "update": {
                                                            runOnSync(() -> {
                                                                if (!getCollection(MessageCollection.class).changeItem(messageCollectionItem.getId(), messageCollectionItem))
                                                                    logger.log(Level.SEVERE, "Fail on update received message: " + messageCollectionItem.getId());
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
                                                            if (!getCollection(MessageCollection.class).hasItem(messageCollectionItem.getId()) && !getCollection(MessageCollection.class).tryAddItem(messageCollectionItem))
                                                                logger.log(Level.SEVERE, "Fail on add received last message to collection: " + messageCollectionItem.getId());
                                                            findChatFromId(messageCollectionItem.getRemoteJid()).thenAccept(chatCollectionItem -> {
                                                                if (chatCollectionItem == null)
                                                                    logger.log(Level.WARNING, "Received last message but chat was not found: " + messageCollectionItem.getRemoteJid());
                                                                else
                                                                    chatCollectionItem.setLastMessage(messageCollectionItem);
                                                            });
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
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "OnMessage", e);
        }
    }

    @Override
    public void onMessage(String message) {
        try {
            if (mdVersion) {
                System.out.println(message);
            } else {
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
                        executorService.submit(runnableFactory.apply(() -> {
                            response.complete(jsonElement);
                        }));
                    } else if (jsonElement.isJsonArray()) {
                        var jsonArray = jsonElement.getAsJsonArray();
                        switch (jsonArray.get(0).getAsString()) {
                            case "Cmd":
                                var cmdObj = jsonArray.get(1).getAsJsonObject();
                                switch (cmdObj.get("type").getAsString()) {
                                    case "challenge":
                                        var challenge = cmdObj.get("challenge").getAsString();
                                        respondToChallenge(challenge).thenAccept(aBoolean -> {
                                            if (!aBoolean)
                                                close(CloseFrame.REFUSE, "Error on resolve challenge");
                                        });
                                        break;
                                    case "upgrade_md_prod":
                                        uri = URI.create(Constants.WS_URL_MD);
                                        mdVersion = true;
                                        close(CloseFrame.NORMAL, "Upgrade to MD Version");
                                        break;
                                    default:
                                        logger.log(Level.WARNING, "Received unexpected cmd tag: {" + cmdObj.get("type").getAsString() + "} with content: {" + cmdObj + "}");
                                }
                                break;
                            case "Stream":
                                break;
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
                                communicationKeys = generateCommunicationKeys();

                                connectTime = LocalDateTime.now();

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
                                            isSynced = true;
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
                                break;
                            case "Props":
                                break;
                            case "Msg":
                                var content = jsonArray.get(1).getAsJsonObject();
                                var cmd = content.get("cmd").getAsString();
                                switch (cmd) {
                                    case "ack":
                                        if (!getCollection(MessageCollection.class).changeItem(content.get("id").getAsString(), content))
                                            logger.log(Level.SEVERE, "Fail on update received message: " + content.get("id").getAsString());
                                        break;
                                    case "acks":
                                        var ids = content.getAsJsonArray("id");
                                        for (int i = 0; i < ids.size(); i++) {
                                            var id = ids.get(i).getAsString();
                                            if (!getCollection(MessageCollection.class).changeItem(id, content))
                                                logger.log(Level.SEVERE, "Fail on update received message: " + id);
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
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "OnMessage", e);
        }
    }

    @Override
    public void onClose(int code, String reason, boolean remote) {
        logger.log(Level.SEVERE, "Ws Disconnected with code: {" + code + "} and reason: {" + reason + "}. fromRemote: {" + remote + "}");
        synchronized (scheduledFutures) {
            for (var scheduledFuture : scheduledFutures) {
                if (!scheduledFuture.isCancelled())
                    scheduledFuture.cancel(true);
            }
            scheduledFutures.clear();
        }
        if (autoReconnect)
            executorService.submit(this::reconnect);
    }

    @Override
    public void onError(Exception ex) {
        logger.log(Level.SEVERE, "Unexpected Error on WebSocket", ex);
    }
}
