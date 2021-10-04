package br.com.zapia.wpp.api.ws;

import br.com.zapia.wpp.api.ws.model.AuthInfo;
import org.junit.jupiter.api.*;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;

@TestMethodOrder(value = MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WhatsAppClientTest {

    private WhatsAppClient whatsAppClient;
    private String clientId;
    private CompletableFuture<AuthInfo> onAuthInfo;
    private AuthInfo authInfo;

    @Order(1)
    @Test
    public void createClient() {
        onAuthInfo = new CompletableFuture<>();
        whatsAppClient = new WhatsAppClientBuilder().onQrCode(s -> {
            System.out.println(s);
        }).onAuthInfo(authInfo1 -> {
            onAuthInfo.complete(authInfo1);
        }).builder();
        whatsAppClient.connect();
    }

    @Order(2)
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
        whatsAppClient = new WhatsAppClientBuilder().authInfo(authInfo).onQrCode(s -> {
            System.out.println(s);
        }).onAuthInfo(authInfo1 -> {
            onAuthInfo.complete(authInfo1);
        }).builder();
        whatsAppClient.connect();
    }

    @Order(5)
    @Test
    public void waitForAuthInfo2() throws ExecutionException, InterruptedException, TimeoutException {
        authInfo = onAuthInfo.get(10, TimeUnit.SECONDS);
        assertNotNull(authInfo);
    }

    @Order(99)
    @Test
    public void waitDisconnect() throws InterruptedException {
        while (!whatsAppClient.isClosed()) {
            Thread.sleep(100);
        }
    }

}
