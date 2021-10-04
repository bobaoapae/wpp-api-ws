package br.com.zapia.wpp.api.ws;

import at.favre.lib.crypto.HKDF;
import br.com.zapia.wpp.api.ws.model.CommunicationKeys;
import br.com.zapia.wpp.api.ws.model.ConnResponse;
import br.com.zapia.wpp.api.ws.model.InitRequest;
import br.com.zapia.wpp.api.ws.model.InitResponse;
import br.com.zapia.wpp.api.ws.utils.JsonUtil;
import br.com.zapia.wpp.api.ws.binary.WABinaryDecoder;
import com.google.common.hash.Hashing;
import com.google.common.primitives.Bytes;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.zxing.BarcodeFormat;
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
import java.net.URI;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
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

    private final String clientId;

    private final Map<UUID, CompletableFuture<String>> wsEvents;

    private Curve25519KeyPair keyPair;
    private CommunicationKeys communicationKeys;

    private String serverId;
    private String browserToken;
    private String clientToken;
    private String secret;
    private String serverToken;
    private String pushName;
    private String wid;

    private LocalDateTime lastSeen;

    public WhatsAppClient(String clientId, Consumer<String> onQrCode, Function<Runnable, Runnable> runnableFactory, Function<Callable, Callable> callableFactory, Function<Runnable, Thread> threadFactory, ExecutorService executorService, ScheduledExecutorService scheduledExecutorService) {
        super(URI.create(Constants.WS_URL));
        this.clientId = clientId;
        this.onQrCode = onQrCode;
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

    public <T> CompletableFuture<T> sendQuery(String data, Class<T> responseType) {
        UUID uuid = UUID.randomUUID();
        var response = new CompletableFuture<String>();
        wsEvents.put(uuid, response);
        send(uuid + "," + data);
        return response.thenApply(s -> JsonUtil.I.getGson().fromJson(s, responseType));
    }

    private void initLogin() {
        startKeepAlive();
        sendInit().thenAccept(initResponse -> {
            if (initResponse.getStatus() == 200) {
                serverId = initResponse.getRef();
                if (keyPair == null) {
                    generateQrCode();
                }
            }
        });
    }

    private CompletableFuture<InitResponse> sendInit() {
        return sendQuery(new InitRequest(clientId).toString(), InitResponse.class);
    }

    private Curve25519KeyPair generateKeyPairQrCode() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return CURVE_25519.generateKeyPair();
    }

    private void generateQrCode() {
        try {
            keyPair = generateKeyPairQrCode();
            var publicKey = keyPair.getPublicKey();
            var privateKey = keyPair.getPrivateKey();
            var stringQrCode = serverId + "," + Base64.getEncoder().encodeToString(publicKey) + "," + clientId;
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
        }
    }

    private void generateCommunicationKeys() {
        try {
            var decodedSecret = Base64.getDecoder().decode(secret);
            if (decodedSecret.length != 144) {
                throw new Exception("incorrect secret length received: " + decodedSecret.length);
            }

            var sharedKey = CURVE_25519.calculateAgreement(Arrays.copyOf(decodedSecret, 32), keyPair.getPrivateKey());

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

        } catch (Exception e) {
            logger.log(Level.SEVERE, "GenerateCommunicationKeys", e);
        }
    }

    private void handleWsMessage(String msgTag, String msgContent, boolean isBinary) {
        try {
            JsonElement jsonElement = null;

            if (isBinary) {
                if (communicationKeys == null) {
                    throw new IllegalStateException("Received encrypted buffer without communicationKeys");
                }

                var msgContentBytes = Base64.getDecoder().decode(msgContent);
                var checksum = Arrays.copyOf(msgContentBytes, 32);
                var data = Arrays.copyOfRange(msgContentBytes, 32, msgContentBytes.length);

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
                var jsonArray = new JsonArray();
                for (var x = 2; x < jsonDecoded.size(); x++) {
                    jsonArray.add(jsonDecoded.get(x));
                }
                jsonElement = jsonArray;
            }

            UUID uuid = null;
            try {
                uuid = UUID.fromString(msgTag);
            } catch (Exception ignore) {

            }
            if (uuid != null && wsEvents.containsKey(uuid)) {
                var response = wsEvents.remove(uuid);
                response.complete(msgContent);
            } else {
                if (!isBinary)
                    jsonElement = JsonParser.parseString(msgContent);

                if (jsonElement.isJsonArray()) {
                    if (!isBinary) {
                        handleJsonWsMessage(jsonElement.getAsJsonArray());
                    } else {
                        var array = jsonElement.getAsJsonArray();
                        for (var x = 0; x < array.size(); x++) {
                            handleJsonWsMessage(array.get(x).getAsJsonArray());
                        }
                    }
                }
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "HandleWsMessage - tag: {" + msgTag + "} - content: {" + msgContent + "}", e);
        }
    }

    private void handleJsonWsMessage(JsonArray jsonArray) {
        switch (jsonArray.get(0).getAsString()) {
            case "Conn":
                var connResponse = JsonUtil.I.getGson().fromJson(jsonArray.get(1).getAsJsonObject(), ConnResponse.class);
                browserToken = connResponse.getBrowserToken();
                clientToken = connResponse.getClientToken();
                serverToken = connResponse.getServerToken();
                secret = connResponse.getSecret();
                pushName = connResponse.getPushname();
                wid = connResponse.getWid();
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
            var tag = new String(bytesTag);
            handleWsMessage(tag, Base64.getEncoder().encodeToString(bytesMsg), true);
        }
    }

    @Override
    public void onMessage(String message) {
        if (message.charAt(0) == '!') {
            var timestamp = Long.parseLong(message.substring(1));
            lastSeen = LocalDateTime.ofInstant(Instant.ofEpochMilli(timestamp), TimeZone.getDefault().toZoneId());
        } else {
            var msgSplit = message.split(",", 2);
            var msgTag = msgSplit[0];
            var msgContent = msgSplit[1];
            handleWsMessage(msgTag, msgContent, false);
        }
    }

    @Override
    public void onClose(int code, String reason, boolean remote) {

    }

    @Override
    public void onError(Exception ex) {

    }
}
