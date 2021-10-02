package br.com.zapia.wpp.api.ws;

import at.favre.lib.crypto.HKDF;
import br.com.zapia.wpp.api.ws.model.ConnResponse;
import br.com.zapia.wpp.api.ws.model.InitRequest;
import br.com.zapia.wpp.api.ws.model.InitResponse;
import br.com.zapia.wpp.api.ws.utils.JsonUtil;
import com.github.glusk.caesar.PlainText;
import com.github.glusk.caesar.hashing.Hmac;
import com.github.glusk.caesar.hashing.ImmutableMessageDigest;
import com.google.common.hash.Hashing;
import com.google.gson.JsonParser;
import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.qrcode.QRCodeWriter;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;
import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import java.util.function.Function;

public class WhatsAppClient extends WebSocketClient {

    private static final Curve25519 CURVE_25519 = Curve25519.getInstance(Curve25519.BEST);

    private final Function<Runnable, Runnable> runnableFactory;
    private final Function<Callable, Callable> callableFactory;
    private final Function<Runnable, Thread> threadFactory;
    private final ExecutorService executorService;
    private final ScheduledExecutorService scheduledExecutorService;

    private final Consumer<String> onQrCode;

    private final String clientId;

    private final Map<UUID, CompletableFuture<String>> wsEvents;

    private String serverId;
    private String browserToken;
    private String clientToken;
    private String secret;
    private String serverToken;
    private Curve25519KeyPair keyPair;
    private String pushName;
    private String wid;

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
            e.printStackTrace();
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

            var expandedTest = hkdf.extractAndExpand(staticSalt32Byte, sharedKey, null, 80);

            var hmacValidationKey = Arrays.copyOfRange(expandedTest, 32, 64);

            var outputStream = new ByteArrayOutputStream();
            outputStream.write(Arrays.copyOf(decodedSecret, 32));
            outputStream.write(Arrays.copyOfRange(decodedSecret, 64, decodedSecret.length));


            var hmac = Hashing.hmacSha256(hmacValidationKey)
                    .newHasher()
                    .putBytes(outputStream.toByteArray())
                    .hash().asBytes();
            if (!Arrays.equals(hmac, Arrays.copyOfRange(decodedSecret, 32, 64))) {
                throw new Exception("HMAC Validation Failed");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void onOpen(ServerHandshake handshakedata) {
        initLogin();
    }

    @Override
    public void onMessage(String message) {
        var msgSplit = message.split(",", 2);
        var msgTag = msgSplit[0];
        var msgContent = msgSplit[1];

        switch (msgTag) {
            case "s1":
            case "s2":
            case "s3": {
                var jsonElement = JsonParser.parseString(msgContent);
                if (jsonElement.isJsonArray()) {
                    var jsonArray = jsonElement.getAsJsonArray();
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
                    }
                }
                break;
            }
            default: {
                try {
                    var uuid = UUID.fromString(msgTag);
                    if (wsEvents.containsKey(uuid)) {
                        var response = wsEvents.remove(uuid);
                        response.complete(msgContent);
                    }
                } catch (Exception ignored) {

                }
                try {
                    var jsonElement = JsonParser.parseString(msgContent);
                } catch (Exception ignored) {

                }
            }
        }
    }

    @Override
    public void onClose(int code, String reason, boolean remote) {

    }

    @Override
    public void onError(Exception ex) {

    }
}
