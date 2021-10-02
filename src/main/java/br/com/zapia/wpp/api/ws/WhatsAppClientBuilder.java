package br.com.zapia.wpp.api.ws;

import java.awt.image.BufferedImage;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.logging.Level;
import java.util.logging.Logger;

public class WhatsAppClientBuilder {

    private ExecutorService executorService;
    private ScheduledExecutorService scheduledExecutorService;
    private Function<Runnable, Runnable> runnableFactory;
    private Function<Callable, Callable> callableFactory;
    private Function<Runnable, Thread> threadFactory;
    private Consumer<String> onQrCode;
    private String clientId;

    public WhatsAppClientBuilder() {
        this.runnableFactory = runnable -> () -> runnable.run();
        this.callableFactory = callable -> () -> callable.call();
        this.threadFactory = runnable -> new Thread(runnable);
        this.executorService = Executors.newCachedThreadPool(r -> threadFactory.apply(r));
        this.scheduledExecutorService = Executors.newScheduledThreadPool(20, r -> threadFactory.apply(r));
    }

    public WhatsAppClientBuilder runnableFactory(Function<Runnable, Runnable> runnableFactory) {
        this.runnableFactory = runnableFactory;
        return this;
    }

    public WhatsAppClientBuilder callableFactory(Function<Callable, Callable> callableFactory) {
        this.callableFactory = callableFactory;
        return this;
    }

    public WhatsAppClientBuilder threadFactory(Function<Runnable, Thread> threadFactory) {
        this.threadFactory = threadFactory;
        return this;
    }

    public WhatsAppClientBuilder executorService(ExecutorService executorService) {
        this.executorService = executorService;
        return this;
    }

    public WhatsAppClientBuilder scheduledExecutorService(ScheduledExecutorService scheduledExecutorService) {
        this.scheduledExecutorService = scheduledExecutorService;
        return this;
    }

    public WhatsAppClientBuilder clientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    public WhatsAppClientBuilder onQrCode(Consumer<String> onQrCode) {
        this.onQrCode = onQrCode;
        return this;
    }

    public WhatsAppClient builder() {
        return new WhatsAppClient(clientId, onQrCode, runnableFactory, callableFactory, threadFactory, executorService, scheduledExecutorService);
    }
}
