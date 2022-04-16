package br.com.zapia.wpp.api.ws.binary;

import it.auties.bytes.Bytes;

import java.util.LinkedList;
import java.util.List;

public class BinaryMessage {
    private final Bytes raw;

    private final LinkedList<Bytes> decoded;

    public BinaryMessage(Bytes raw) {
        this.raw = raw;
        var decoded = new LinkedList<Bytes>();
        while (raw.readableBytes() >= 3) {
            var length = decodeLength(raw);
            if (length < 0) {
                continue;
            }

            decoded.add(raw.readBuffer(length));
        }

        this.decoded = decoded;
    }

    private int decodeLength(Bytes buffer) {
        return (buffer.readByte() << 16) | buffer.readUnsignedShort();
    }

    public BinaryMessage(byte[] array) {
        this(Bytes.of(array));
    }

    public List<Bytes> getDecoded() {
        return decoded;
    }
}
