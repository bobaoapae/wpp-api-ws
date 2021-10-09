package br.com.zapia.wpp.api.ws.model.communication;

public class LoadMessagesRequest extends BaseQuery {

    private final String jid;
    private final String kind;
    private final int count;
    private final String index;
    private final String owner;

    public LoadMessagesRequest(String epoch, String jid, String kind, int count, String index, String owner) {
        super("message", epoch, null);
        this.jid = jid;
        this.kind = kind;
        this.count = count;
        this.index = index;
        this.owner = owner;
    }

}
