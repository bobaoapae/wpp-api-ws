package br.com.zapia.wpp.api.ws;

import br.com.zapia.wpp.api.ws.model.*;
import br.com.zapia.wpp.api.ws.utils.Util;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.*;

import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@TestMethodOrder(value = MethodOrderer.OrderAnnotation.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class WhatsAppClientTest {

    private WhatsAppClient whatsAppClient;
    private CompletableFuture<AuthInfo> onAuthInfo;
    private CompletableFuture<Void> onConnect;
    private AuthInfo authInfo;
    private ChatCollectionItem chatCollectionItem;
    private CompletableFuture<MessageCollectionItem> eventAddMsg;
    private CompletableFuture<MessageCollectionItem> eventUpdateMsg;

    @Order(0)
    @Test
    public void testJson() {
        var bytes = new byte[100];
        var json = JsonParser.parseString(Util.GSON.toJson(bytes));
        var byteArray = Util.GSON.fromJson(json, byte[].class);
        System.out.println("a");
    }

    @Order(1)
    @Test
    public void createClient() {
        onAuthInfo = new CompletableFuture<>();
        onConnect = new CompletableFuture<>();
        whatsAppClient = new WhatsAppClientBuilder().withOnQrCode(s -> {
            System.out.println(s);
        }).withOnConnect(() -> {
            onConnect.complete(null);
        }).withOnAuthInfo(authInfo1 -> {
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
    public void waitForConnect() throws ExecutionException, InterruptedException, TimeoutException {
        onConnect.get(30, TimeUnit.SECONDS);
        eventAddMsg = new CompletableFuture<>();
        eventUpdateMsg = new CompletableFuture<>();
        whatsAppClient.getCollection(MessageCollection.class).listenToEvent(EventType.ADD, new ConsumerEventCancellable<>() {
            @Override
            public void accept(List<MessageCollectionItem> messageCollectionItems) {
                eventAddMsg.complete(messageCollectionItems.get(0));
            }
        });
        whatsAppClient.getCollection(MessageCollection.class).listenToEvent(EventType.CHANGE, new ConsumerEventCancellable<>() {
            @Override
            public void accept(List<MessageCollectionItem> messageCollectionItems) {
                eventUpdateMsg.complete(messageCollectionItems.get(0));
            }
        });
    }

    @Order(4)
    @Test
    public void checkNumberExist() throws ExecutionException, InterruptedException, TimeoutException {
        var result = whatsAppClient.checkNumberExist("5544991050665").get(30, TimeUnit.SECONDS);
        assertEquals(result.getStatus(), 200);
    }

    @Order(5)
    @Test
    public void findChatFromNumber() throws ExecutionException, InterruptedException, TimeoutException {
        chatCollectionItem = whatsAppClient.findChatFromNumber("5544991050665").get(30, TimeUnit.SECONDS);
        assertNotNull(chatCollectionItem);
    }

    @Order(6)
    @Test
    public void loadMessages() throws ExecutionException, InterruptedException, TimeoutException {
        var messages = chatCollectionItem.loadMessages(30).get(30, TimeUnit.SECONDS);
    }

    @Order(7)
    @Test
    public void sendTextMessage() throws ExecutionException, InterruptedException, TimeoutException {
        var message = whatsAppClient.sendMessage("554491050665@c.us", new MessageSend.Builder().withText("teste").build()).get(30, TimeUnit.SECONDS);
    }

    /*@Order(3)
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
