package br.com.zapia.wpp.api.ws;

import org.junit.jupiter.api.*;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.function.Consumer;

import static org.junit.jupiter.api.Assertions.*;

@TestMethodOrder(value = MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WhatsAppClientTest {

    private WhatsAppClient whatsAppClient;
    private String clientId;

    @Order(0)
    @Test
    public void createClientId() throws NoSuchAlgorithmException {
        byte[] bytes = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(bytes);
        clientId = Base64.getEncoder().encodeToString(bytes);
        assertNotNull(clientId);
        assertFalse(clientId.isEmpty());
    }

    @Order(1)
    @Test
    public void createClient(){
        whatsAppClient = new WhatsAppClientBuilder().clientId(clientId).onQrCode(s -> {
            System.out.println(s);
        }).builder();
        whatsAppClient.connect();
    }

    @Order(99)
    @Test
    public void waitDisconnect() throws InterruptedException {
        while(!whatsAppClient.isClosed()){
            Thread.sleep(100);
        }
    }

}
