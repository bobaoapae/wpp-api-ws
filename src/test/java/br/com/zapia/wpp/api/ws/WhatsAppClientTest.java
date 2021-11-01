package br.com.zapia.wpp.api.ws;

import br.com.zapia.wpp.api.ws.model.*;
import br.com.zapia.wpp.api.ws.utils.Util;
import com.google.gson.JsonParser;
import org.junit.jupiter.api.*;

import java.io.File;
import java.io.IOException;
import java.util.List;
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
    private CompletableFuture<Void> onConnect;
    private AuthInfo authInfo;
    private ChatCollectionItem chatCollectionItem;
    private CompletableFuture<MessageCollectionItem> eventAddMsg;
    private CompletableFuture<MessageCollectionItem> eventUpdateMsg;
    private MessageCollectionItem msgReceived;
    private MessageCollectionItem lastMsgSend;

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
        }).withOnChangeDriverState(driverState -> {
            System.out.println(driverState);
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
        TimeUnit.SECONDS.sleep(3);
    }

    @Order(7)
    @Test
    public void sendTextMessage() throws ExecutionException, InterruptedException, TimeoutException {
        var message = whatsAppClient.sendMessage("554491050665@c.us", new SendMessageRequest.Builder().withText("teste").build()).get(30, TimeUnit.SECONDS);
    }

    @Order(8)
    @Test
    public void sendDocumentMessage() throws ExecutionException, InterruptedException, TimeoutException, IOException {
        var message = whatsAppClient.sendMessage("554491050665@c.us", new SendMessageRequest.Builder().withFile(new File("pom.xml")).build()).get(30, TimeUnit.SECONDS);
    }

    @Order(9)
    @Test
    public void sendImageMessage() throws ExecutionException, InterruptedException, TimeoutException, IOException {
        var message = whatsAppClient.sendMessage("554491050665@c.us", new SendMessageRequest.Builder().withFile(new File("img.png")).build()).get(30, TimeUnit.SECONDS);
    }

    @Order(10)
    @Test
    public void sendSticker() throws ExecutionException, InterruptedException, TimeoutException, IOException {
        var message = whatsAppClient.sendMessage("554491050665@c.us", new SendMessageRequest.Builder().withFile(new File("img.png"), fileBuilder -> fileBuilder.withForceSticker(true)).build()).get(30, TimeUnit.SECONDS);
    }

    @Order(11)
    @Test
    public void sendVideoMessage() throws ExecutionException, InterruptedException, TimeoutException, IOException {
        var message = whatsAppClient.sendMessage("554491050665@c.us", new SendMessageRequest.Builder().withFile(new File("video.mp4")).build()).get(60, TimeUnit.SECONDS);
    }

    @Order(12)
    @Test
    public void sendGifMessage() throws ExecutionException, InterruptedException, TimeoutException, IOException {
        var message = whatsAppClient.sendMessage("554491050665@c.us", new SendMessageRequest.Builder().withFile(new File("video.mp4"), fileBuilder -> fileBuilder.withForceGif(true)).build()).get(60, TimeUnit.SECONDS);
    }

    @Order(13)
    @Test
    public void sendAudioMessage() throws ExecutionException, InterruptedException, TimeoutException, IOException {
        var message = whatsAppClient.sendMessage("554491050665@c.us", new SendMessageRequest.Builder().withFile(new File("audio.ogg")).build()).get(60, TimeUnit.SECONDS);
    }

    @Order(14)
    @Test
    public void sendPttMessage() throws ExecutionException, InterruptedException, TimeoutException, IOException {
        var message = whatsAppClient.sendMessage("554491050665@c.us", new SendMessageRequest.Builder().withFile(new File("audio.ogg"), fileBuilder -> fileBuilder.withForcePtt(true)).build()).get(60, TimeUnit.SECONDS);
    }

    @Order(15)
    @Test
    public void sendContactMsg() throws ExecutionException, InterruptedException, TimeoutException {
        var message = whatsAppClient.sendMessage("554491050665@c.us", new SendMessageRequest.Builder().withVCard("João", "5544991050665").build()).get(60, TimeUnit.SECONDS);
    }

    @Order(16)
    @Test
    public void sendButtonMsg() throws ExecutionException, InterruptedException, TimeoutException {
        var message = whatsAppClient.sendMessage("554491050665@c.us", new SendMessageRequest.Builder().withButtons("title", "footer", buttonsBuilder -> buttonsBuilder.withButton("button1").withButton("button2").withButton("button3")).build()).get(60, TimeUnit.SECONDS);
    }

    @Order(17)
    @Test
    public void sendListMsg() throws ExecutionException, InterruptedException, TimeoutException {
        if (!authInfo.isBusiness()) {
            var message = whatsAppClient.sendMessage("554491050665@c.us", new SendMessageRequest.Builder().withList(listBuilder -> {
                listBuilder
                        .withTitle("Title")
                        .withDescription("Description")
                        .withFooter("Footer")
                        .withButtonText("Button Text");
                for (int x = 0; x < 10; x++) {
                    listBuilder.withSection("Section " + x, sectionBuilder -> {
                        for (int y = 0; y < 20; y++) {
                            sectionBuilder.withRow("Row " + y);
                        }
                    });
                }
            }).build()).get(60, TimeUnit.SECONDS);
        }
    }

    @Order(18)
    @Test
    public void checkLastMsg() throws InterruptedException {
        TimeUnit.SECONDS.sleep(3);
        var lastMsg = chatCollectionItem.getLastMessage();
        assertNotNull(lastMsg);
    }

    @Order(19)
    @Test
    public void receiveMsg() throws ExecutionException, InterruptedException, TimeoutException {
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
        msgReceived = eventAddMsg.get(60, TimeUnit.SECONDS);
        assertNotNull(msgReceived);
    }

    @Order(20)
    @Test
    public void downloadMsg() throws InterruptedException, ExecutionException, TimeoutException {
        if (msgReceived.getMessageContent() instanceof MessageCollectionItem.MessageMediaContent messageMediaContent) {
            var file = messageMediaContent.downloadMedia().get(60, TimeUnit.SECONDS);
            assertNotNull(file);
        }
    }

    @Order(21)
    @Test
    public void sendQuotedMessage() throws InterruptedException, ExecutionException, TimeoutException {
        lastMsgSend = whatsAppClient.sendMessage("554491050665@c.us", new SendMessageRequest.Builder().withText("teste").withQuotedMsg(msgReceived).build()).get(60, TimeUnit.SECONDS);
        assertNotNull(lastMsgSend);
    }

    @Order(22)
    @Test
    public void sendPresenceOnline() throws InterruptedException, ExecutionException, TimeoutException {
        var response = whatsAppClient.sendPresence(PresenceType.AVAILABLE).get(60, TimeUnit.SECONDS);
        assertNotNull(response);
    }

    @Order(23)
    @Test
    public void sendChatComposing() {
        whatsAppClient.sendChatPresenceUpdate(chatCollectionItem.getId(), PresenceType.COMPOSING);
    }

    @Order(24)
    @Test
    public void sendChatRecording() {
        whatsAppClient.sendChatPresenceUpdate(chatCollectionItem.getId(), PresenceType.RECORDING);
    }

    @Order(25)
    @Test
    public void sendChatPaused() {
        whatsAppClient.sendChatPresenceUpdate(chatCollectionItem.getId(), PresenceType.PAUSED);
    }

    @Order(26)
    @Test
    public void getProfilePic() throws InterruptedException, ExecutionException, TimeoutException {
        var profilePic = whatsAppClient.findProfilePicture(chatCollectionItem.getId()).get(30, TimeUnit.SECONDS);
        assertNotNull(profilePic);
    }

    @Order(27)
    @Test
    public void updateProfilePic() throws InterruptedException, ExecutionException, TimeoutException {
        var result = whatsAppClient.updateProfilePicture(new File("profile.jpg")).get(30, TimeUnit.SECONDS);
        assertNotNull(result);
    }

    @Order(28)
    @Test
    public void revokeMessage() throws InterruptedException, ExecutionException, TimeoutException {
        var result = whatsAppClient.revokeMessage(lastMsgSend).get(30, TimeUnit.SECONDS);
        assertNotNull(result);
    }


    @Order(29)
    @Test
    public void deleteMessage() throws InterruptedException, ExecutionException, TimeoutException {
        var result = whatsAppClient.deleteMessage(msgReceived).get(30, TimeUnit.SECONDS);
        assertNotNull(result);
    }

    @Order(30)
    @Test
    public void markChatUnRead() throws InterruptedException, ExecutionException, TimeoutException {
        TimeUnit.SECONDS.sleep(3);
        var result = whatsAppClient.markChatUnRead(chatCollectionItem).get(30, TimeUnit.SECONDS);
        assertNotNull(result);
        assertTrue(result);
        assertEquals(-1, chatCollectionItem.getUnreadMessages());
    }

    @Order(31)
    @Test
    public void markChatRead() throws InterruptedException, ExecutionException, TimeoutException {
        TimeUnit.SECONDS.sleep(3);
        var result = whatsAppClient.markChatRead(chatCollectionItem).get(30, TimeUnit.SECONDS);
        assertNotNull(result);
        assertTrue(result);
        assertEquals(0, chatCollectionItem.getUnreadMessages());
    }

    @Order(32)
    @Test
    public void clearChat() throws InterruptedException, ExecutionException, TimeoutException {
        TimeUnit.SECONDS.sleep(3);
        var result = whatsAppClient.clearChat(chatCollectionItem, true).get(30, TimeUnit.SECONDS);
        assertNotNull(result);
        assertTrue(result);
    }


    @Order(33)
    @Test
    public void pinChat() throws InterruptedException, ExecutionException, TimeoutException {
        var result = whatsAppClient.pinChat(chatCollectionItem.getId()).get(30, TimeUnit.SECONDS);
        assertNotNull(result);
        assertTrue(result);
        assertTrue(chatCollectionItem.getPin() > 0);
    }


    @Order(34)
    @Test
    public void unpinChat() throws InterruptedException, ExecutionException, TimeoutException {
        var result = whatsAppClient.unPinChat(chatCollectionItem.getId()).get(30, TimeUnit.SECONDS);
        assertNotNull(result);
        assertTrue(result);
        assertTrue(chatCollectionItem.getPin() <= 0);
    }


    @Order(99)
    @Test
    public void waitDisconnect() throws InterruptedException {
        while (!whatsAppClient.isClosed()) {
            Thread.sleep(100);
        }
    }

}
