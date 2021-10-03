package br.com.zapia.wpp.api.ws.binary;

import java.util.Map;

public class Node {

    private final String descr;
    private final Map<String, String> attributes;
    private final NodeData nodeData;

    public Node(String descr, Map<String, String> attributes, NodeData nodeData) {
        this.descr = descr;
        this.attributes = attributes;
        this.nodeData = nodeData;
    }

    public String getDescr() {
        return descr;
    }

    public Map<String, String> getAttributes() {
        return attributes;
    }

    public NodeData getNodeData() {
        return nodeData;
    }
}
