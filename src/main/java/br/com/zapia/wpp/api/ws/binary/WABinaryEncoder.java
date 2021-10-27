package br.com.zapia.wpp.api.ws.binary;

import br.com.zapia.wpp.api.ws.utils.Util;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class WABinaryEncoder {

    private final ByteArrayOutputStream buffer;

    public WABinaryEncoder() {
        buffer = new ByteArrayOutputStream();
    }

    private void pushByte(short value) {
        buffer.write(value & 0xff);
    }

    private void pushBytes(byte[] bytes) {
        for (byte aByte : bytes) {
            pushByte(aByte);
        }
    }

    private void pushInt(int value, int length, boolean littleEndian) {
        for (var i = 0; i < length; i++) {
            var curShift = littleEndian ? i : length - 1 - i;
            buffer.write((value >> (curShift * 8)) & 0xFF);
        }
    }

    private void pushInt20(int value) {
        var a = (value >> 16) & 0x0F;
        var b = (value >> 8) & 0xFF;
        var c = value & 0xFF;
        pushBytes(new byte[]{(byte) a, (byte) b, (byte) c});
    }

    private void writeByteLength(long length) {
        if (length >= 4294967296L) {
            throw new IllegalArgumentException("String too large to encode: " + length);
        }

        if (length >= 1 << 20) {
            pushByte((short) BinaryConstants.WA.Tags.BINARY_32.getNumVal());
            pushInt((int) length, 4, false);
        } else if (length >= 256) {
            pushByte((short) BinaryConstants.WA.Tags.BINARY_20.getNumVal());
            pushInt20((int) length);
        } else {
            pushByte((short) BinaryConstants.WA.Tags.BINARY_8.getNumVal());
            pushByte((short) length);
        }
    }

    private void writeStringRaw(String string) {
        var bytes = string.getBytes(StandardCharsets.UTF_8);
        writeByteLength(bytes.length);
        pushBytes(bytes);
    }


    private void writeJid(String left, String right) {
        pushByte((short) BinaryConstants.WA.Tags.JID_PAIR.getNumVal());
        if (left != null && !left.isEmpty()) {
            writeString(left, false);
        } else {
            writeToken((short) BinaryConstants.WA.Tags.LIST_EMPTY.getNumVal());
        }
        writeString(right, false);
    }

    private void writeToken(short token) {
        if (token < 245) {
            pushByte(token);
        } else if (token <= 500) {
            throw new IllegalArgumentException("Invalid Token: " + token);
        }
    }

    private void writeString(String token, boolean i) {
        if (token == null) {
            token = "";
        }
        if (token.equals("c.us")) token = "s.whatsapp.net";

        var tokenIndex = Arrays.stream(BinaryConstants.WA.SingleByteTokens).toList().indexOf(token);
        if (!i && token.equals("s.whatsapp.net")) {
            writeToken((short) tokenIndex);
        } else if (tokenIndex >= 0) {
            if (tokenIndex < BinaryConstants.WA.Tags.SINGLE_BYTE_MAX.getNumVal()) {
                writeToken((short) tokenIndex);
            } else {
                var overflow = tokenIndex - BinaryConstants.WA.Tags.SINGLE_BYTE_MAX.getNumVal();
                var dictionaryIndex = overflow >> 8;
                if (dictionaryIndex < 0 || dictionaryIndex > 3) {
                    throw new IllegalArgumentException("double byte dict token out of range: " + token + ", " + tokenIndex);
                }
                writeToken((short) (BinaryConstants.WA.Tags.DICTIONARY_0.getNumVal() + dictionaryIndex));
                writeToken((short) (overflow % 256));
            }
        } else if (!token.isEmpty()) {
            var jidSepIndex = token.indexOf('@');
            if (jidSepIndex <= 0) {
                this.writeStringRaw(token);
            } else {
                this.writeJid(token.substring(0, jidSepIndex), token.substring(jidSepIndex + 1));
            }
        }
    }

    private void writeAttributes(JsonObject jsonObject) {
        for (var entrySet : jsonObject.entrySet()) {
            writeString(entrySet.getKey(), false);
            writeString(entrySet.getValue().getAsString(), false);
        }
    }

    private void writeListStart(int listSize) {
        if (listSize == 0) {
            pushByte((short) BinaryConstants.WA.Tags.LIST_EMPTY.getNumVal());
        } else if (listSize < 256) {
            pushBytes(new byte[]{(byte) BinaryConstants.WA.Tags.LIST_8.getNumVal(), (byte) listSize});
        } else {
            pushBytes(new byte[]{(byte) BinaryConstants.WA.Tags.LIST_16.getNumVal(), (byte) listSize});
        }
    }

    private void writeChildren(JsonElement jsonElement) {
        if (jsonElement == null) return;

        if (jsonElement.isJsonPrimitive() && jsonElement.getAsJsonPrimitive().isString()) {
            writeString(jsonElement.getAsString(), true);
        } else if (jsonElement.isJsonArray()) {
            var jsonArray = jsonElement.getAsJsonArray();
            if (jsonArray.size() > 0) {
                var firstElement = jsonArray.get(0);
                if (firstElement.isJsonPrimitive() && Util.isJsonArrayByteArray(jsonArray)) {
                    var byteArray = Util.GSON.fromJson(jsonArray, byte[].class);
                    writeByteLength(byteArray.length);
                    pushBytes(byteArray);
                } else if (firstElement.isJsonArray()) {
                    writeListStart(jsonArray.size());
                    for (int i = 0; i < jsonArray.size(); i++) {
                        writeNode(jsonArray.get(i).getAsJsonArray());
                    }
                }
            }
        }
    }

    private JsonObject getValidKeys(JsonObject attrs) {
        var result = new JsonObject();
        for (var entrySet : attrs.entrySet()) {
            if (entrySet.getValue() != null && !entrySet.getValue().isJsonNull()) {
                result.add(entrySet.getKey(), entrySet.getValue());
            }
        }

        return result;
    }

    private void writeNode(JsonArray jsonArray) {
        if (jsonArray.size() != 3) {
            throw new IllegalArgumentException("Invalid node give: " + Util.GSON.toJson(jsonArray));
        }

        var validAttributes = getValidKeys(jsonArray.get(1) == null || jsonArray.get(1).isJsonNull() ? new JsonObject() : jsonArray.get(1).getAsJsonObject());

        var optional = 0;
        if (jsonArray.get(2) != null & !jsonArray.get(2).isJsonNull()) {
            optional = 1;
        }
        writeListStart(2 * validAttributes.size() + 1 + optional);
        writeString(jsonArray.get(0).getAsString(), false);
        writeAttributes(validAttributes);
        writeChildren(jsonArray.get(2));
    }

    public byte[] write(JsonArray jsonArray) {
        writeNode(jsonArray);

        return buffer.toByteArray();
    }
}
