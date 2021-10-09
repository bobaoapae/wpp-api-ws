package br.com.zapia.wpp.api.ws.model;

public class MessageSend {

    private final MessageType messageType;
    private final String text;

    private MessageSend(MessageType messageType, String text) {
        this.messageType = messageType;
        this.text = text;
    }

    public MessageType getMessageType() {
        return messageType;
    }

    public String getText() {
        return text;
    }

    public static class Builder {

        private MessageType messageType;
        private String text;

        public Builder() {
        }

        public Builder withText(String text) {
            this.text = text;
            this.messageType = MessageType.TEXT;
            return this;
        }

        public MessageSend build() {
            return new MessageSend(messageType, text);
        }
    }
}
