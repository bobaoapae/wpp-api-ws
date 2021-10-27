package br.com.zapia.wpp.api.ws.model;

public enum DriverState {
    UNLOADED,
    CONNECTING,
    INITIALIZING,
    INIT_NEW_SESSION,
    RESTORING_OLD_SESSION,
    WAITING_SYNC,
    CONNECTED
}
