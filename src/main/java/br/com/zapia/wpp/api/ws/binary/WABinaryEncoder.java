package br.com.zapia.wpp.api.ws.binary;

import br.com.zapia.wpp.api.ws.utils.Util;
import com.google.common.base.Strings;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class WABinaryEncoder {

    private final ByteArrayOutputStream buffer;
    private final boolean isMd;

    public WABinaryEncoder(boolean isMd) {
        buffer = new ByteArrayOutputStream();
        this.isMd = isMd;
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

        if (length < 256) {
            pushByte((short) BinaryConstants.WA.Tags.BINARY_8.getNumVal());
            pushByte((short) length);
        } else if (length < 1048576) {
            pushByte((short) BinaryConstants.WA.Tags.BINARY_20.getNumVal());
            pushInt20((int) length);
        } else {
            pushByte((short) BinaryConstants.WA.Tags.BINARY_32.getNumVal());
            pushInt((int) length, 4, false);
        }
    }

    private void writeStringRaw(String string) {
        var bytes = string.getBytes(StandardCharsets.UTF_8);
        writeByteLength(bytes.length);
        pushBytes(bytes);
    }


    private void writeJid(String left, String right) {
        pushByte((short) BinaryConstants.WA.Tags.JID_PAIR.getNumVal());
        if (left != null) {
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
        if (Strings.isNullOrEmpty(token)) {
            pushByte((short) BinaryConstants.WA.Tags.BINARY_8.getNumVal());
            pushByte((short) BinaryConstants.WA.Tags.LIST_EMPTY.getNumVal());
            return;
        }


        if (!i && token.equals("c.us")) {
            token = "s.whatsapp.net";
        }

        var tokenIndex = Arrays.stream(isMd ? BinaryConstants.WA.SingleByteTokensMD : BinaryConstants.WA.SingleByteTokens).toList().indexOf(token);

        if (tokenIndex != -1) {
            tokenIndex++;
            writeToken((short) tokenIndex);
            return;
        }

        var jidSepIndex = token.indexOf('@');
        if (jidSepIndex >= 0) {
            this.writeJid(token.substring(0, jidSepIndex), token.substring(jidSepIndex + 1));
            return;
        }

        var doubleTokens = Arrays.asList(BinaryConstants.WA.DoubleByteTokens);

        if (doubleTokens.contains(token)) {
            var index = doubleTokens.indexOf(token);
            var dictIndex = index / doubleTokens.size() / 4;
            var dict = switch (dictIndex) {
                case 0 -> BinaryConstants.WA.Tags.DICTIONARY_0;
                case 1 -> BinaryConstants.WA.Tags.DICTIONARY_1;
                case 2 -> BinaryConstants.WA.Tags.DICTIONARY_2;
                case 3 -> BinaryConstants.WA.Tags.DICTIONARY_3;
                default -> throw new IllegalArgumentException("Cannot find tag for quadrant %s".formatted(index));
            };
            pushByte((short) dict.getNumVal());
            pushByte((short) (index % (doubleTokens.size() / 4)));
            return;
        }

        var length = token.getBytes(StandardCharsets.UTF_8).length;

        if (length < 128 && token.matches("^[A-F\\d]*$")) {
            if (token.matches("\\d+")) {
                writeString(token, BinaryConstants.WA.Tags.NIBBLE_8);
            } else {
                writeString(token, BinaryConstants.WA.Tags.HEX_8);
            }
            return;
        }

        writeStringRaw(token);
    }

    private void writeString(String input, BinaryConstants.WA.Tags token) {
        pushByte((short) token.getNumVal());
        writeStringLength(input);

        for (int charCode = 0, index = 0; index < input.length(); index++) {
            var stringCodePoint = Character.codePointAt(input, index);
            var binaryCodePoint = getStringCodePoint(token, stringCodePoint);

            if (index % 2 != 0) {
                pushByte((short) (charCode |= binaryCodePoint));
                continue;
            }

            charCode = binaryCodePoint << 4;
            if (index != input.length() - 1) {
                continue;
            }

            pushByte((short) (charCode |= 15));
        }
    }

    private void writeStringLength(String input) {
        var roundedLength = (int) Math.ceil(input.length() / 2F);
        if (input.length() % 2 == 1) {
            pushByte((short) (roundedLength | 128));
            return;
        }

        pushByte((short) roundedLength);
    }

    private int getStringCodePoint(BinaryConstants.WA.Tags token, int codePoint) {
        if (codePoint >= 48 && codePoint <= 57) {
            return codePoint - 48;
        }

        if (token == BinaryConstants.WA.Tags.NIBBLE_8 && codePoint == 45) {
            return 10;
        }

        if (token == BinaryConstants.WA.Tags.NIBBLE_8 && codePoint == 46) {
            return 11;
        }

        if (token == BinaryConstants.WA.Tags.HEX_8 && codePoint >= 65 && codePoint <= 70) {
            return codePoint - 55;
        }

        throw new IllegalArgumentException("Cannot parse codepoint %s with token %s".formatted(codePoint, token));
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
        if (jsonArray.get(2) != null && !jsonArray.get(2).isJsonNull() && (!jsonArray.get(2).isJsonPrimitive() || (jsonArray.get(2).getAsJsonPrimitive().isString() && !jsonArray.get(2).getAsJsonPrimitive().getAsString().equals("[]")))) {
            optional = 1;
        }
        writeListStart(2 * validAttributes.size() + 1 + optional);
        writeString(jsonArray.get(0).getAsString(), false);
        writeAttributes(validAttributes);
        if (optional > 0)
            writeChildren(jsonArray.get(2));
    }

    public byte[] write(JsonArray jsonArray) {
        pushByte((short) 0);
        writeNode(jsonArray);

        return buffer.toByteArray();
    }
}
