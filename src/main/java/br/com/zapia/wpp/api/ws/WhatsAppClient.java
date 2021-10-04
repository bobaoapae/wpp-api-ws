package br.com.zapia.wpp.api.ws;

import at.favre.lib.crypto.HKDF;
import br.com.zapia.wpp.api.ws.model.*;
import br.com.zapia.wpp.api.ws.utils.JsonUtil;
import br.com.zapia.wpp.api.ws.binary.WABinaryDecoder;
import com.google.common.hash.Hashing;
import com.google.common.primitives.Bytes;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.qrcode.QRCodeWriter;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.framing.CloseFrame;
import org.java_websocket.handshake.ServerHandshake;
import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.*;
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
    private final Consumer<AuthInfo> onAuthInfo;

    private final Map<UUID, CompletableFuture<JsonElement>> wsEvents;

    private String serverId;
    private AuthInfo authInfo;
    private CommunicationKeys communicationKeys;

    private LocalDateTime lastSeen;
    private ScheduledFuture refreshQrCodeScheduler;

    public WhatsAppClient(AuthInfo authInfo, Consumer<String> onQrCode, Consumer<AuthInfo> onAuthInfo, Function<Runnable, Runnable> runnableFactory, Function<Callable, Callable> callableFactory, Function<Runnable, Thread> threadFactory, ExecutorService executorService, ScheduledExecutorService scheduledExecutorService) {
        super(URI.create(Constants.WS_URL));
        this.authInfo = authInfo;
        this.onQrCode = onQrCode;
        this.onAuthInfo = onAuthInfo;
        this.runnableFactory = runnableFactory;
        this.callableFactory = callableFactory;
        this.threadFactory = threadFactory;
        this.executorService = executorService;
        this.scheduledExecutorService = scheduledExecutorService;

        this.wsEvents = new ConcurrentHashMap<>();
        getHeadersConnectWs().forEach(this::addHeader);
    }

    protected Map<String, String> getHeadersConnectWs() {
        var headers = new HashMap<String, String>();
        headers.put("Origin", Constants.ORIGIN_WS);
        return headers;
    }

    public <T> CompletableFuture<T> sendJson(String data, Class<T> responseType) {
        UUID uuid = UUID.randomUUID();
        var response = new CompletableFuture<JsonElement>();
        wsEvents.put(uuid, response);
        send(uuid + "," + data);
        return response.thenApply(jsonElement -> JsonUtil.I.getGson().fromJson(jsonElement, responseType));
    }

    /*public <T> CompletableFuture<T> sendBinary(BaseQuery baseQuery, Class<T> responseType) {
        UUID uuid = UUID.randomUUID();
        var response = new CompletableFuture<String>();
        wsEvents.put(uuid, response);
        send(uuid + "," + data);
        return response.thenApply(s -> JsonUtil.I.getGson().fromJson(s, responseType));
    }*/

    private void initLogin() {
        try {
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
                    refreshQrCodeScheduler = scheduledExecutorService.scheduleWithFixedDelay(() -> {
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
                }
            });
        } catch (Exception e) {
            logger.log(Level.SEVERE, "InitLogin", e);

        }
    }

    private CompletableFuture<InitResponse> sendInit() {
        return sendJson(new InitRequest(authInfo.getClientId()).toJson(), InitResponse.class);
    }

    private CompletableFuture<LoginResponse> sendLogin() {
        return sendJson(new LoginRequest(authInfo).toJson(), LoginResponse.class);
    }

    private CompletableFuture<RefreshQrResponse> refreshQrCode() {
        return sendJson(new RefreshQrRequest().toJson(), RefreshQrResponse.class);
    }

    private void generateQrCode() {
        try {
            var stringQrCode = serverId + "," + authInfo.getPublicKey() + "," + authInfo.getClientId();
            var barcodeWriter = new QRCodeWriter();
            var bitMatrix = barcodeWriter.encode(stringQrCode, BarcodeFormat.QR_CODE, 400, 400);
            var outputStream = new ByteArrayOutputStream();
            MatrixToImageWriter.writeToStream(bitMatrix, "png", outputStream);
            var base64QrCode = Base64.getEncoder().encodeToString(outputStream.toByteArray());
            executorService.submit(runnableFactory.apply(() -> {
                onQrCode.accept("data:image/png;base64," + base64QrCode);
            }));
        } catch (Exception e) {
            logger.log(Level.SEVERE, "GenerateQrCode", e);
            close(CloseFrame.ABNORMAL_CLOSE, "Ws Closed due to error on generate QrCode");
        }
    }

    private void initNewSession() {
        try {
            var keyPair = CURVE_25519.generateKeyPair();
            authInfo.setPrivateKey(Base64.getEncoder().encodeToString(keyPair.getPrivateKey()));
            authInfo.setPublicKey(Base64.getEncoder().encodeToString(keyPair.getPublicKey()));
            generateQrCode();
        } catch (Exception e) {
            logger.log(Level.SEVERE, "InitNewSession", e);
        }
    }

    private void generateCommunicationKeys() {
        try {
            var decodedSecret = Base64.getDecoder().decode(authInfo.getSecret());
            if (decodedSecret.length != 144) {
                throw new Exception("incorrect secret length received: " + decodedSecret.length);
            }

            var sharedKey = CURVE_25519.calculateAgreement(Arrays.copyOf(decodedSecret, 32), Base64.getDecoder().decode(authInfo.getPrivateKey()));

            var hkdf = HKDF.fromHmacSha256();

            var staticSalt32Byte = new byte[]{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0};

            var expandedKey = hkdf.extractAndExpand(staticSalt32Byte, sharedKey, null, 80);

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
                onAuthInfo.accept(authInfo);
            }));

        } catch (Exception e) {
            logger.log(Level.SEVERE, "GenerateCommunicationKeys", e);
        }
    }

    private void startKeepAlive() {
        scheduledExecutorService.scheduleAtFixedRate(() -> {
            if (lastSeen == null) lastSeen = LocalDateTime.now();

            var currentTime = LocalDateTime.now();
            if (lastSeen.plusSeconds(25).isBefore(currentTime)) {
                close(CloseFrame.ABNORMAL_CLOSE, "Ws Closed due to timeout on receive pong from server  ");
            } else {
                send("?,,");
            }
        }, 0, Constants.KEEP_ALIVE_INTERVAL_MS, TimeUnit.MILLISECONDS);
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

                SecretKeySpec secretKey = new SecretKeySpec(communicationKeys.getEncKey(), "AES");
                byte[] iv = Arrays.copyOf(data, 16);
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
                cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
                var decryptedBytes = Bytes.concat(cipher.update(Arrays.copyOfRange(data, 16, data.length)), cipher.doFinal());

                var binaryDecoder = new WABinaryDecoder(decryptedBytes);
                var jsonDecoded = binaryDecoder.read();
                var binaryType = jsonDecoded.get(0).getAsString();
                switch (binaryType) {
                    case "response": {
                        var responseType = jsonDecoded.get(1).getAsJsonObject().get("type").getAsString();
                        switch (responseType) {
                            case "chat": {
                                var chats = jsonDecoded.get(2).getAsJsonArray();
                                for (int i = 0; i < chats.size(); i++) {
                                    var chat = chats.get(i).getAsJsonArray().get(1).getAsJsonObject();
                                }
                            }
                            default:
                                logger.log(Level.WARNING, "Unexpected Binary Response Type: " + responseType);
                        }
                        break;
                    }
                    default:
                        logger.log(Level.WARNING, "Unexpected Binary Type: " + binaryType);
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
                var jsonElement = JsonParser.parseString(msgContent);

                UUID uuid = null;
                try {
                    uuid = UUID.fromString(msgTag);
                } catch (Exception ignore) {

                }
                if (uuid != null && wsEvents.containsKey(uuid)) {
                    var response = wsEvents.remove(uuid);
                    response.complete(jsonElement);
                } else if (jsonElement.isJsonArray()) {
                    var jsonArray = jsonElement.getAsJsonArray();
                    switch (jsonArray.get(0).getAsString()) {
                        case "Conn":
                            if (refreshQrCodeScheduler != null) {
                                refreshQrCodeScheduler.cancel(true);
                                refreshQrCodeScheduler = null;
                            }
                            var connResponse = JsonUtil.I.getGson().fromJson(jsonArray.get(1).getAsJsonObject(), ConnResponse.class);
                            authInfo.setBrowserToken(connResponse.getBrowserToken());
                            authInfo.setClientToken(connResponse.getClientToken());
                            authInfo.setServerToken(connResponse.getServerToken());
                            if (connResponse.getSecret() != null) {
                                authInfo.setSecret(connResponse.getSecret());
                            }
                            authInfo.setPushName(connResponse.getPushname());
                            authInfo.setWid(connResponse.getWid());
                            generateCommunicationKeys();
                            break;
                        case "Stream":
                            break;
                        case "Props":
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
    }

    @Override
    public void onError(Exception ex) {
        logger.log(Level.SEVERE, "Unexpected Error on WebSocket", ex);
    }
}
