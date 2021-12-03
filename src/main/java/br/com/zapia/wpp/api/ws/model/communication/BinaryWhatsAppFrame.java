package br.com.zapia.wpp.api.ws.model.communication;

public class BinaryWhatsAppFrame implements IWhatsAppFrame {

    private final byte[] data;

    public BinaryWhatsAppFrame(byte[] data) {
        this.data = data;
    }

    public byte[] getData() {
        return data;
    }
}
