package br.com.zapia.wpp.api.ws.binary;


/**
 * Copy from WhatsappWeb4j+
 */
public class BinaryMessage {
    /**
     * The raw binary array used to construct this object
     */
    BinaryArray raw;

    /**
     * The raw binary array sliced at [3, {@code length})
     */
    BinaryArray decoded;

    /**
     * The length of the decoded message
     */
    int length;

    /**
     * Constructs a new instance of this wrapper from a binary array
     *
     * @param array the non-null binary array
     */
    public BinaryMessage(BinaryArray array) {
        this.raw = array;
        this.length = array.cut(3).toInt();
        this.decoded = array.slice(3, length + 3);
    }

    /**
     * Constructs a new instance of this wrapper from an array of bytes
     *
     * @param array the non-null array of bytes
     */
    public BinaryMessage(byte[] array) {
        this(BinaryArray.of(array));
    }

    public BinaryArray getRaw() {
        return raw;
    }

    public BinaryArray getDecoded() {
        return decoded;
    }

    public int getLength() {
        return length;
    }
}
