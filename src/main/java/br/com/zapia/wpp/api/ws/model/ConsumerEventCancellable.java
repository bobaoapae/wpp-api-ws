package br.com.zapia.wpp.api.ws.model;

import java.util.function.Consumer;

public abstract class ConsumerEventCancellable<T> implements Consumer<T> {

    private boolean isCanceled;

    public ConsumerEventCancellable() {
        isCanceled = false;
    }

    public void setCanceled() {
        isCanceled = true;
    }

    public boolean isCanceled() {
        return isCanceled;
    }
}
