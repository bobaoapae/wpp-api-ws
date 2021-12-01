package br.com.zapia.wpp.api.ws.binary;

public class WhatsAppBinaryBuffer extends BinaryBuffer {

    private int peekSize() {
        return (buffer.get(0) << 16) | buffer.getShort(1);
    }

    public boolean canPeek() {
        return !(buffer.remaining() < 3) && peekSize() <= buffer.remaining();
    }

    public void resetPosition() {
        buffer.position(0);
    }

}
