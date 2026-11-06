package icu.yunzhan.panel;

import java.util.concurrent.Semaphore;

/** A cancelled provider/peer retains its lease until its actual worker exits. */
final class NativeTransferBudget {
    private static final Semaphore ACTIVE = new Semaphore(1);
    private NativeTransferBudget() { }
    static boolean acquire() { return ACTIVE.tryAcquire(); }
    static void release() { ACTIVE.release(); }
}
