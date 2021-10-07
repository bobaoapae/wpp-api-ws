package br.com.zapia.wpp.api.ws.model;

import br.com.zapia.wpp.api.ws.binary.BinaryConstants;

public enum CollectionType {
    CONTACTS(BinaryConstants.WA.WAMetric.queryContact),
    CHAT(BinaryConstants.WA.WAMetric.queryChat),
    MESSAGE(BinaryConstants.WA.WAMetric.queryMessages),
    QUICK_REPLY(BinaryConstants.WA.WAMetric.queryQuickReply),
    STATUS(BinaryConstants.WA.WAMetric.queryStatus),
    ;

    private final BinaryConstants.WA.WAMetric waMetric;

    CollectionType(BinaryConstants.WA.WAMetric waMetric) {
        this.waMetric = waMetric;
    }

    public BinaryConstants.WA.WAMetric getWaMetric() {
        return waMetric;
    }
}
