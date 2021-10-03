package br.com.zapia.wpp.api.ws.binary;

public class NodeData {

    private final String content;
    private final Node[] childNodes;

    public NodeData(String content) {
        this(content, null);
    }

    public NodeData(Node[] childNodes) {
        this(null, childNodes);
    }

    public NodeData(String content, Node[] childNodes) {
        this.content = content;
        this.childNodes = childNodes;
    }

    public String getContent() {
        return content;
    }

    public Node[] getChildNodes() {
        return childNodes;
    }
}
