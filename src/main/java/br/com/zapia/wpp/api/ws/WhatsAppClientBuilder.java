package br.com.zapia.wpp.api.ws;

import br.com.zapia.wpp.api.ws.model.AuthInfo;
import br.com.zapia.wpp.api.ws.model.DriverState;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.function.Consumer;
import java.util.function.Function;

public class WhatsAppClientBuilder {

    private ExecutorService executorService;
    private ScheduledExecutorService scheduledExecutorService;
    private Function<Runnable, Runnable> runnableFactory;
    private Function<Callable, Callable> callableFactory;
    private Function<Runnable, Thread> threadFactory;
    private Consumer<String> onQrCode;
    private Consumer<AuthInfo> onAuthInfo;
    private Consumer<DriverState> onChangeDriverState;
    private Runnable onConnect;
    private AuthInfo authInfo;

    public WhatsAppClientBuilder() {
        this.runnableFactory = runnable -> () -> runnable.run();
        this.callableFactory = callable -> () -> callable.call();
        this.threadFactory = runnable -> new Thread(runnable);
        this.executorService = Executors.newCachedThreadPool(r -> threadFactory.apply(r));
        this.scheduledExecutorService = Executors.newScheduledThreadPool(20, r -> threadFactory.apply(r));
    }

    public WhatsAppClientBuilder withRunnableFactory(Function<Runnable, Runnable> runnableFactory) {
        this.runnableFactory = runnableFactory;
        return this;
    }

    public WhatsAppClientBuilder withCallableFactory(Function<Callable, Callable> callableFactory) {
        this.callableFactory = callableFactory;
        return this;
    }

    public WhatsAppClientBuilder withThreadFactory(Function<Runnable, Thread> threadFactory) {
        this.threadFactory = threadFactory;
        return this;
    }

    public WhatsAppClientBuilder withExecutorService(ExecutorService executorService) {
        this.executorService = executorService;
        return this;
    }

    public WhatsAppClientBuilder withScheduledExecutorService(ScheduledExecutorService scheduledExecutorService) {
        this.scheduledExecutorService = scheduledExecutorService;
        return this;
    }

    public WhatsAppClientBuilder withAuthInfo(AuthInfo authInfo) {
        this.authInfo = authInfo;
        return this;
    }

    public WhatsAppClientBuilder withOnQrCode(Consumer<String> onQrCode) {
        this.onQrCode = onQrCode;
        return this;
    }

    public WhatsAppClientBuilder withOnAuthInfo(Consumer<AuthInfo> onAuthInfo) {
        this.onAuthInfo = onAuthInfo;
        return this;
    }

    public WhatsAppClientBuilder withOnConnect(Runnable onConnect) {
        this.onConnect = onConnect;
        return this;
    }

    public WhatsAppClientBuilder withOnChangeDriverState(Consumer<DriverState> onChangeDriverState) {
        this.onChangeDriverState = onChangeDriverState;
        return this;
    }

    public WhatsAppClient builder() {
        return new WhatsAppClient(authInfo, onQrCode, onConnect, onAuthInfo, onChangeDriverState, runnableFactory, callableFactory, threadFactory, executorService, scheduledExecutorService);
    }
}
