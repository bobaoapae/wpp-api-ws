package br.com.zapia.wpp.api.ws.binary;

import br.com.zapia.wpp.api.ws.binary.protos.WebMessageInfo;
import br.com.zapia.wpp.api.ws.utils.Util;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.util.JsonFormat;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class WABinaryDecoder {

    private final byte[] data;
    private int index;

    public WABinaryDecoder(byte[] data) {
        this.data = data;
        index = 0;
    }

    private void checkEOS(int length) {
        if (index + length > data.length) {
            throw new IllegalStateException("End of Stream");
        }
    }

    private byte next() {
        return data[index++];
    }

    private short readByte() {
        checkEOS(1);
        var result = next() & 0xFF;
        return (short) result;
    }

    private String readStringFromChars(int length) {
        return new String(readBytes(length), StandardCharsets.UTF_8);
    }

    private byte[] readBytes(int length) {
        checkEOS(length);
        var bytesRead = Arrays.copyOfRange(data, index, index + length);
        index += length;
        return bytesRead;
    }

    private int readInt(int length) {
        return readInt(length, false);
    }

    private int readInt(int length, boolean littleEndian) {
        checkEOS(length);
        var val = 0;
        for (var i = 0; i < length; i++) {
            var shift = littleEndian ? i : length - 1 - i;
            val |= readByte() << (shift * 8);
        }
        return val;
    }

    private int readInt20() {
        checkEOS(3);
        return ((15 & readByte()) << 16) + (readByte() << 8) + readByte();
    }

    private String unpackHex(int value) {
        if (value >= 0 && value < 16) {
            return Integer.toHexString(value);
        }
        throw new IllegalArgumentException("invalid hex: " + value);
    }

    private String unpackNibble(int value) {
        if (value >= 0 && value <= 9) {
            return String.valueOf(value);
        }
        return switch (value) {
            case 10 -> "-";
            case 11 -> ".";
            case 15 -> "";
            default -> throw new IllegalArgumentException("invalid nibble: " + value);
        };
    }

    private String unpackByte(int tag, int value) {
        if (tag == BinaryConstants.WA.Tags.NIBBLE_8.getNumVal()) {
            return this.unpackNibble(value);
        } else if (tag == BinaryConstants.WA.Tags.HEX_8.getNumVal()) {
            return this.unpackHex(value);
        } else {
            throw new IllegalArgumentException("unknown tag: " + tag);
        }
    }

    private String readPacked8(int tag) {
        var startByte = readByte();
        var value = "";

        for (int i = 0; i < (startByte & 127); i++) {
            var curByte = readByte();
            value += unpackByte(tag, (curByte & 240) >> 4);
            value += unpackByte(tag, (curByte & 15));
        }

        if (startByte >> 7 != 0) {
            value = value.substring(0, value.length() - 1);
        }

        return value;
    }

    private boolean isListTag(int tag) {
        return tag == BinaryConstants.WA.Tags.LIST_EMPTY.getNumVal() || tag == BinaryConstants.WA.Tags.LIST_8.getNumVal() || tag == BinaryConstants.WA.Tags.LIST_16.getNumVal();
    }

    private int readListSize(int tag) {
        if (tag == BinaryConstants.WA.Tags.LIST_EMPTY.getNumVal()) {
            return 0;
        } else if (tag == BinaryConstants.WA.Tags.LIST_8.getNumVal()) {
            return readByte();
        } else if (tag == BinaryConstants.WA.Tags.LIST_16.getNumVal()) {
            return readInt(2);
        }

        throw new IllegalArgumentException("invalid tag for list size: " + tag);
    }

    private String readString(int tag) {
        if (tag >= 3 && tag <= 235) {
            return getToken(tag);
        }

        if (tag == BinaryConstants.WA.Tags.DICTIONARY_0.getNumVal() || tag == BinaryConstants.WA.Tags.DICTIONARY_1.getNumVal() || tag == BinaryConstants.WA.Tags.DICTIONARY_2.getNumVal() || tag == BinaryConstants.WA.Tags.DICTIONARY_3.getNumVal()) {
            return getTokenDouble(tag - BinaryConstants.WA.Tags.DICTIONARY_0.getNumVal(), readByte());
        } else if (tag == BinaryConstants.WA.Tags.LIST_EMPTY.getNumVal()) {
            return null;
        } else if (tag == BinaryConstants.WA.Tags.BINARY_8.getNumVal()) {
            return readStringFromChars(readByte());
        } else if (tag == BinaryConstants.WA.Tags.BINARY_20.getNumVal()) {
            return readStringFromChars(readInt20());
        } else if (tag == BinaryConstants.WA.Tags.BINARY_32.getNumVal()) {
            return readStringFromChars(readInt(4));
        } else if (tag == BinaryConstants.WA.Tags.JID_PAIR.getNumVal()) {
            var i = readString(readByte());
            var j = readString(readByte());

            return i + "@" + j;
        } else if (tag == BinaryConstants.WA.Tags.HEX_8.getNumVal() || tag == BinaryConstants.WA.Tags.NIBBLE_8.getNumVal()) {
            return readPacked8(tag);
        }

        throw new IllegalArgumentException("invalid string with tag: " + tag);
    }

    private Map<String, String> readAttributes(int number) {
        var map = new HashMap<String, String>();
        if (number != 0) {
            for (int i = 0; i < number; i++) {
                var key = readString(readByte());
                var value = readString(readByte());
                map.put(key, value);
            }
        }

        return map;
    }

    private JsonArray readList(int tag) throws InvalidProtocolBufferException {
        var jsonArray = new JsonArray();

        var size = readListSize(tag);
        for (int i = 0; i < size; i++) {
            jsonArray.add(readNode());
        }

        return jsonArray;
    }

    private String getToken(int index) {
        if (index < 3 || index > BinaryConstants.WA.SingleByteTokens.length) {
            throw new IllegalArgumentException("Invalid token index: " + index);
        }

        return BinaryConstants.WA.SingleByteTokens[index];
    }

    private String getTokenDouble(int index, int index2) {
        var n = 256 * index + index2;

        if (n < 3 || n > BinaryConstants.WA.SingleByteTokens.length) {
            throw new IllegalArgumentException("Invalid token index: " + index);
        }

        return BinaryConstants.WA.DoubleByteTokens[n];
    }

    private JsonArray readNode() throws InvalidProtocolBufferException {
        var listSize = readListSize(readByte());
        var descrTag = readByte();
        if (descrTag == BinaryConstants.WA.Tags.STREAM_END.getNumVal()) {
            throw new IllegalStateException("Unexpected stream end");
        }

        var descr = readString(descrTag);
        if (listSize == 0 || descr == null || descr.isEmpty()) {
            throw new IllegalStateException("Invalid Node");
        }

        var attrs = readAttributes((listSize - 1) >> 1);

        JsonElement jsonElement = null;

        if (listSize % 2 == 0) {
            var tag = readByte();
            if (isListTag(tag)) {
                jsonElement = readList(tag);
            } else {
                byte[] decoded;
                var isString = false;
                if (tag == BinaryConstants.WA.Tags.BINARY_8.getNumVal()) {
                    decoded = readBytes(readByte());
                } else if (tag == BinaryConstants.WA.Tags.BINARY_20.getNumVal()) {
                    decoded = readBytes(readInt20());
                } else if (tag == BinaryConstants.WA.Tags.BINARY_32.getNumVal()) {
                    decoded = readBytes(readInt(4));
                } else {
                    decoded = readString(tag).getBytes(StandardCharsets.UTF_8);
                    isString = true;
                }

                if (descr.equals("message") && !isString) {
                    try {
                        var message = WebMessageInfo.parseFrom(decoded);
                        var json = JsonFormat.printer().print(message);
                        jsonElement = JsonParser.parseString(json);
                    } catch (Exception e) {
                        throw e;
                    }
                } else {
                    var stringData = new String(decoded, StandardCharsets.UTF_8);
                    try {
                        jsonElement = JsonParser.parseString(stringData);
                    } catch (Exception ignore) {
                        jsonElement = new JsonPrimitive(stringData);
                    }
                }
            }
        }

        var jsonArray = new JsonArray();
        jsonArray.add(descr);
        jsonArray.add(JsonParser.parseString(Util.GSON.toJson(attrs)));
        jsonArray.add(jsonElement);

        return jsonArray;
    }

    public JsonArray read() throws InvalidProtocolBufferException {
        return readNode();
    }
}
