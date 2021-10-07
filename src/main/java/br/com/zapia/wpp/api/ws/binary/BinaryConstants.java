package br.com.zapia.wpp.api.ws.binary;

import java.util.Arrays;

public class BinaryConstants {

    public class WA {

        public static final String[] DoubleByteTokens = new String[0];
        public static final String[] SingleByteTokens = new String[]{
                null,
                null,
                null,
                "200",
                "400",
                "404",
                "500",
                "501",
                "502",
                "action",
                "add",
                "after",
                "archive",
                "author",
                "available",
                "battery",
                "before",
                "body",
                "broadcast",
                "chat",
                "clear",
                "code",
                "composing",
                "contacts",
                "count",
                "create",
                "debug",
                "delete",
                "demote",
                "duplicate",
                "encoding",
                "error",
                "false",
                "filehash",
                "from",
                "g.us",
                "group",
                "groups_v2",
                "height",
                "id",
                "image",
                "in",
                "index",
                "invis",
                "item",
                "jid",
                "kind",
                "last",
                "leave",
                "live",
                "log",
                "media",
                "message",
                "mimetype",
                "missing",
                "modify",
                "name",
                "notification",
                "notify",
                "out",
                "owner",
                "participant",
                "paused",
                "picture",
                "played",
                "presence",
                "preview",
                "promote",
                "query",
                "raw",
                "read",
                "receipt",
                "received",
                "recipient",
                "recording",
                "relay",
                "remove",
                "response",
                "resume",
                "retry",
                "s.whatsapp.net",
                "seconds",
                "set",
                "size",
                "status",
                "subject",
                "subscribe",
                "t",
                "text",
                "to",
                "true",
                "type",
                "unarchive",
                "unavailable",
                "url",
                "user",
                "value",
                "web",
                "width",
                "mute",
                "read_only",
                "admin",
                "creator",
                "short",
                "update",
                "powersave",
                "checksum",
                "epoch",
                "block",
                "previous",
                "409",
                "replaced",
                "reason",
                "spam",
                "modify_tag",
                "message_info",
                "delivery",
                "emoji",
                "title",
                "description",
                "canonical-url",
                "matched-text",
                "star",
                "unstar",
                "media_key",
                "filename",
                "identity",
                "unread",
                "page",
                "page_count",
                "search",
                "media_message",
                "security",
                "call_log",
                "profile",
                "ciphertext",
                "invite",
                "gif",
                "vcard",
                "frequent",
                "privacy",
                "blacklist",
                "whitelist",
                "verify",
                "location",
                "document",
                "elapsed",
                "revoke_invite",
                "expiration",
                "unsubscribe",
                "disable",
                "vname",
                "old_jid",
                "new_jid",
                "announcement",
                "locked",
                "prop",
                "label",
                "color",
                "call",
                "offer",
                "call-id",
                "quick_reply",
                "sticker",
                "pay_t",
                "accept",
                "reject",
                "sticker_pack",
                "invalid",
                "canceled",
                "missed",
                "connected",
                "result",
                "audio",
                "video",
                "recent"};

        public enum Tags {
            LIST_EMPTY(0),
            STREAM_END(2),
            DICTIONARY_0(236),
            DICTIONARY_1(237),
            DICTIONARY_2(238),
            DICTIONARY_3(239),
            LIST_8(248),
            LIST_16(249),
            JID_PAIR(250),
            HEX_8(251),
            BINARY_8(252),
            BINARY_20(253),
            BINARY_32(254),
            NIBBLE_8(255),
            SINGLE_BYTE_MAX(256),
            PACKED_MAX(254);

            private final int numVal;

            Tags(int numVal) {
                this.numVal = numVal;
            }

            public int getNumVal() {
                return numVal;
            }

            public static Tags Convert(int numVal) {
                var tag = Arrays.stream(Tags.values()).filter(tags -> tags.numVal == numVal).findFirst();
                return tag.orElseThrow();
            }
        }

        public static class WATags {
            private final WAMetric waMetric;
            private final WAFlag waFlag;

            public WATags(WAMetric waMetric, WAFlag waFlag) {
                this.waMetric = waMetric;
                this.waFlag = waFlag;
            }

            public byte[] toByteArray() {
                return new byte[]{(byte) waMetric.getNumVal(), (byte) waFlag.getNumVal()};
            }
        }

        public enum WAMetric {
            debugLog(1),
            queryResume(2),
            liveLocation(3),
            queryMedia(4),
            queryChat(5),
            queryContact(6),
            queryMessages(7),
            presence(8),
            presenceSubscribe(9),
            group(10),
            read(11),
            chat(12),
            received(13),
            picture(14),
            status(15),
            message(16),
            queryActions(17),
            block(18),
            queryGroup(19),
            queryPreview(20),
            queryEmoji(21),
            queryRead(22),
            queryVCard(29),
            queryStatus(30),
            queryStatusUpdate(31),
            queryLiveLocation(33),
            queryLabel(36),
            queryQuickReply(39);
            private final int numVal;

            WAMetric(int numVal) {
                this.numVal = numVal;
            }

            public int getNumVal() {
                return numVal;
            }

            public static WAMetric Convert(int numVal) {
                var tag = Arrays.stream(WAMetric.values()).filter(tags -> tags.numVal == numVal).findFirst();
                return tag.orElseThrow();
            }
        }

        public enum WAFlag {
            available(160),
            other(136),
            ignore(1 << 7),
            acknowledge(1 << 6),
            unavailable(1 << 3),
            composing(1 << 2),
            recording(1 << 2),
            paused(1 << 2);

            private final int numVal;

            WAFlag(int numVal) {
                this.numVal = numVal;
            }

            public int getNumVal() {
                return numVal;
            }
        }

    }

}
