package icu.yunzhan.panel;

import java.util.UUID;

/** Main-thread state only. No platform, credential, storage or network access. */
final class SessionCallbacks<T> {
    static final class Ticket {
        final UUID session, nonce;
        final int requestCode;
        Ticket(UUID session, int requestCode) { this.session = session; this.nonce = UUID.randomUUID(); this.requestCode = requestCode; }
    }
    static final class Selection<T> {
        final T value;
        Selection(T value) { this.value = value; }
    }
    private UUID session = UUID.randomUUID();
    private Ticket auth, picker, view, prompt;
    private T selected;
    private boolean active, foreground, locked, selectionReady;
    // Android activity result codes are never reused in this Activity instance.
    private int nextRequestCode = 1024;

    void start() { end(); active = true; view = new Ticket(session, -1); locked = !foreground; }
    void end() {
        session = UUID.randomUUID(); active = false; locked = false;
        auth = null; view = null; prompt = null; cancelSelection();
    }
    void foreground(boolean value) {
        foreground = value;
        if (!value && active) { locked = true; auth = null; prompt = null; }
    }
    boolean locked() { return locked; }
    boolean interactive() { return active && foreground && !locked; }
    Ticket viewTicket() { return active ? view : null; }
    boolean ownsView(Ticket ticket) { return active && ticket != null && ticket == view && session.equals(ticket.session); }
    Ticket beginPrompt(Ticket owner) {
        if (!ownsView(owner) || !interactive() || prompt != null) return null;
        prompt = new Ticket(session, -2); return prompt;
    }
    boolean finishPrompt(Ticket ticket) {
        if (ticket == null || ticket != prompt || !session.equals(ticket.session)) return false;
        prompt = null; return interactive();
    }
    void cancelPrompt() { prompt = null; }
    Ticket beginAuthentication() {
        if (!active || !foreground || !locked || auth != null) return null;
        auth = new Ticket(session, 0); return auth;
    }
    boolean finishAuthentication(Ticket ticket, boolean success) {
        if (ticket == null || ticket != auth || !session.equals(ticket.session)) return false;
        auth = null;
        if (!success || !active || !foreground || !locked) return false;
        locked = false; return true;
    }
    Ticket beginSelection() {
        if (!interactive() || picker != null || nextRequestCode > 65535) return null;
        picker = new Ticket(session, nextRequestCode++); return picker;
    }
    boolean receiveSelection(int code, T value) {
        if (!awaitingSelection(code)) return false;
        selected = value; selectionReady = true; return true;
    }
    boolean awaitingSelection(int code) {
        return active && picker != null && session.equals(picker.session) && picker.requestCode == code && !selectionReady;
    }
    Selection<T> takeSelection() {
        if (!interactive() || !selectionReady) return null;
        Selection<T> result = new Selection<>(selected); cancelSelection(); return result;
    }
    void cancelSelection() { picker = null; selected = null; selectionReady = false; }
}
