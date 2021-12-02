package br.com.zapia.wpp.api.ws.binary;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.function.Consumer;

/**
 * Copy from WhatsappWeb4j+
 */
public class BinaryBuffer {
    protected ByteBuffer buffer;

    public BinaryBuffer(ByteBuffer buffer) {
        this.buffer = buffer;
    }

    public BinaryBuffer(int size) {
        this(ByteBuffer.allocate(size));
    }

    public BinaryBuffer() {
        this(256);
    }

    public static BinaryBuffer fromString(String string) {
        return fromBytes(string.getBytes(StandardCharsets.UTF_8));
    }

    public static BinaryBuffer fromBytes(byte... bytes) {
        return new BinaryBuffer(ByteBuffer.wrap(bytes));
    }

    public byte readInt8() {
        return buffer.get();
    }

    public int readUInt8() {
        return Byte.toUnsignedInt(readInt8());
    }

    public int readUInt16() {
        return Short.toUnsignedInt(buffer.getShort());
    }

    public int readInt32() {
        return buffer.getInt();
    }

    public long readUInt32() {
        return Integer.toUnsignedLong(readInt32());
    }

    public long readInt64() {
        return buffer.getLong();
    }

    public BigInteger readUInt64() {
        return new BigInteger(Long.toUnsignedString(readInt64()));
    }

    public float readFloat32() {
        return buffer.getFloat();
    }

    public double readFloat64() {
        return buffer.getDouble();
    }

    public int readVarInt() {
        var tmp = 0;
        if ((tmp = readInt8()) >= 0) {
            return tmp;
        }

        var result = tmp & 0x7f;
        if ((tmp = readInt8()) >= 0) {
            return result | (tmp << 7);
        }

        result |= (tmp & 0x7f) << 7;
        if ((tmp = readInt8()) >= 0) {
            return result | (tmp << 14);
        }

        result |= (tmp & 0x7f) << 14;
        if ((tmp = readInt8()) >= 0) {
            return result | (tmp << 21);
        }

        result |= (tmp & 0x7f) << 21;
        result |= (tmp = readInt8()) << 28;
        while (tmp < 0) tmp = readInt8();
        return result;
    }

    public BinaryBuffer remaining() {
        var remaining = fromBytes(readBytes(buffer.remaining()));
        remaining.buffer.position(0);
        return remaining;
    }

    public byte[] readAllBytes() {
        return buffer.array();
    }

    public byte[] readWrittenBytes() {
        return readBytes(0, buffer.position(), false);
    }

    public byte[] readBytes(long size) {
        if (size <= 0 || size > Integer.MAX_VALUE)
            throw new IllegalArgumentException("Cannot read {" + size + "} bytes");
        return readBytes(buffer.position(), (int) (buffer.position() + size), true);
    }

    public byte[] readBytes(int start, int end, boolean shift) {
        if (start < 0)
            throw new IllegalArgumentException("Expected unsigned int for start, got: {" + start + "}");
        if (end < 0)
            throw new IllegalArgumentException("Expected unsigned int for end, got: {" + end + "}");
        if (end < start)
            throw new IllegalArgumentException("Expected end to be bigger than start, got: {" + start + "} - {" + end + "}");

        var bytes = new byte[end - start];
        buffer.get(start, bytes, 0, bytes.length);
        if (shift) {
            buffer.position(buffer.position() + bytes.length);
        }
        return bytes;
    }

    public String readString(long size) {
        return new String(readBytes(size), StandardCharsets.UTF_8);
    }

    public BinaryBuffer writeInt8(byte in) {
        return write(temp -> temp.put(in), 1);
    }

    public BinaryBuffer writeUInt8(int in) {
        return writeInt8(checkUnsigned(in).byteValue());
    }

    public BinaryBuffer writeUInt8(BinaryConstants.WA.Tags in) {
        return writeUInt8(in.getNumVal());
    }

    public BinaryBuffer writeUInt16(int in) {
        return write(temp -> temp.putShort(checkUnsigned(in).shortValue()), 2);
    }

    public BinaryBuffer writeInt32(int in) {
        return write(temp -> temp.putInt(in), 4);
    }

    public BinaryBuffer writeUInt32(long in) {
        return writeInt32(checkUnsigned(in).intValue());
    }

    public BinaryBuffer writeInt64(long in) {
        return write(temp -> temp.putLong(in), 8);
    }

    public BinaryBuffer writeUInt64(BigInteger in) {
        return write(temp -> temp.put(in.toByteArray()), 8);
    }

    public BinaryBuffer writeFloat32(float in) {
        return write(temp -> temp.putFloat(in), 4);
    }

    public BinaryBuffer writeFloat64(double in) {
        return write(temp -> temp.putDouble(in), 8);
    }

    private BinaryBuffer write(Consumer<ByteBuffer> consumer, int size) {
        var temp = ByteBuffer.allocate(size);
        if (buffer.position() + size + 1 >= buffer.limit()) {
            reserve(buffer.limit() * 2);
        }

        consumer.accept(temp);
        buffer.put(temp.rewind());
        return this;
    }

    public BinaryBuffer writeVarInt(int in) {
        while (true) {
            var bits = in & 0x7f;
            in >>>= 7;
            if (in == 0) {
                buffer.put((byte) bits);
                return this;
            }

            buffer.put((byte) (bits | 0x80));
        }
    }

    public BinaryBuffer writeBytes(byte... in) {
        for (var entry : in) writeInt8(entry);
        return this;
    }

    public BinaryBuffer writeString(String in) {
        return writeBytes(in.getBytes(StandardCharsets.UTF_8));
    }

    private BinaryBuffer reserve(int size) {
        var resized = ByteBuffer.allocate(Math.max(size, 128));
        for (var entry : readWrittenBytes()) resized.put(entry);
        this.buffer = resized;
        return this;
    }

    private <N extends Number> N checkUnsigned(N number) {
        if ((Double.doubleToLongBits(number.doubleValue()) & Long.MIN_VALUE) != Long.MIN_VALUE) {
            return number;
        }

        throw new IllegalArgumentException("Expected unsigned number, got %s".formatted(number));
    }
}
