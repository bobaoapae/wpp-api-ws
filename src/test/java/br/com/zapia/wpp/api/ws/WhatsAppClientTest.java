package br.com.zapia.wpp.api.ws;

import br.com.zapia.wpp.api.ws.model.AuthInfo;
import br.com.zapia.wpp.api.ws.utils.JsonUtil;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.*;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.*;

@TestMethodOrder(value = MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WhatsAppClientTest {

    private WhatsAppClient whatsAppClient;
    private CompletableFuture<AuthInfo> onAuthInfo;
    private AuthInfo authInfo;

    @Order(0)
    @Test
    public void testJson(){
        var bytes = new byte[100];
        var json = JsonParser.parseString(JsonUtil.I.getGson().toJson(bytes));
        var byteArray = JsonUtil.I.getGson().fromJson(json, byte[].class);
        System.out.println("a");
    }

    @Order(1)
    @Test
    public void createClient() {
        onAuthInfo = new CompletableFuture<>();
        whatsAppClient = new WhatsAppClientBuilder().withOnQrCode(s -> {
            System.out.println(s);
        }).withOnAuthInfo(authInfo1 -> {
            onAuthInfo.complete(authInfo1);
        }).builder();
        whatsAppClient.connect();
    }

    /*@Order(2)
    @Test
    public void waitForAuthInfo() throws ExecutionException, InterruptedException, TimeoutException {
        authInfo = onAuthInfo.get(30, TimeUnit.SECONDS);
        assertNotNull(authInfo);
    }

    @Order(3)
    @Test
    public void disconnectWs() throws InterruptedException {
        whatsAppClient.closeBlocking();
    }

    @Order(4)
    @Test
    public void createClientWithAuthInfo() {
        onAuthInfo = new CompletableFuture<>();
        whatsAppClient = new WhatsAppClientBuilder().withAuthInfo(authInfo).withOnQrCode(s -> {
            System.out.println(s);
        }).withOnAuthInfo(authInfo1 -> {
            onAuthInfo.complete(authInfo1);
        }).builder();
        whatsAppClient.connect();
    }

    @Order(5)
    @Test
    public void waitForAuthInfo2() throws ExecutionException, InterruptedException, TimeoutException {
        authInfo = onAuthInfo.get(10, TimeUnit.SECONDS);
        assertNotNull(authInfo);
    }*/

    @Order(99)
    @Test
    public void waitDisconnect() throws InterruptedException {
        while (!whatsAppClient.isClosed()) {
            Thread.sleep(100);
        }
    }

}
