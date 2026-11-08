package icu.yunzhan.panel;

import org.junit.Test;
import static org.junit.Assert.*;

public class SessionCallbacksTest {
    private SessionCallbacks<String> connected() {
        SessionCallbacks<String> s = new SessionCallbacks<>(); s.foreground(true); s.start(); return s;
    }
    @Test public void pickerReturnsBeforeResumeButCannotUploadBeforeAuthentication() {
        SessionCallbacks<String> s = connected(); SessionCallbacks.Ticket pick = s.beginSelection();
        s.foreground(false); assertTrue(s.locked()); assertTrue(s.receiveSelection(pick.requestCode, "private-file")); assertNull(s.takeSelection());
        s.foreground(true); assertNull(s.takeSelection()); SessionCallbacks.Ticket auth = s.beginAuthentication();
        assertTrue(s.finishAuthentication(auth, true)); assertEquals("private-file", s.takeSelection().value); assertNull(s.takeSelection());
        assertFalse(s.receiveSelection(pick.requestCode, "duplicate")); assertFalse(s.finishAuthentication(auth, true));
    }
    @Test public void cancelledAuthenticationRetainsFilesOnlyInSameLockedSession() {
        SessionCallbacks<String> s = connected(); SessionCallbacks.Ticket pick = s.beginSelection(); s.foreground(false); s.receiveSelection(pick.requestCode, "a"); s.foreground(true);
        assertFalse(s.finishAuthentication(s.beginAuthentication(), false)); assertTrue(s.locked()); assertNull(s.takeSelection());
        s.end(); s.start(); assertNull(s.takeSelection()); assertFalse(s.receiveSelection(pick.requestCode, "old"));
    }
    @Test public void staleSuccessCannotUnlockNewSessionOrReplaceCurrentAuthentication() {
        SessionCallbacks<String> s = connected(); s.foreground(false); s.foreground(true); SessionCallbacks.Ticket old = s.beginAuthentication();
        s.end(); s.start(); s.foreground(false); s.foreground(true); SessionCallbacks.Ticket current = s.beginAuthentication();
        assertFalse(s.finishAuthentication(old, true)); assertTrue(s.locked()); assertTrue(s.finishAuthentication(current, true));
    }
    @Test public void backgroundRevokesAuthenticationAndCannotStartPicker() {
        SessionCallbacks<String> s = connected(); s.foreground(false); assertNull(s.beginAuthentication()); assertNull(s.beginSelection());
        s.foreground(true); SessionCallbacks.Ticket auth = s.beginAuthentication(); s.foreground(false); assertFalse(s.finishAuthentication(auth, true));
        s.foreground(true); assertTrue(s.locked()); assertTrue(s.finishAuthentication(s.beginAuthentication(), true));
    }
    @Test public void oldPickerCodeCannotDeliverIntoNewConnectionEvenAtSameOrigin() {
        SessionCallbacks<String> s = connected(); SessionCallbacks.Ticket old = s.beginSelection(); s.end(); s.start(); SessionCallbacks.Ticket current = s.beginSelection();
        assertNotEquals(old.requestCode, current.requestCode); assertFalse(s.receiveSelection(old.requestCode, "stale")); assertTrue(s.receiveSelection(current.requestCode, null));
        assertNotNull(s.takeSelection()); assertNull(s.takeSelection());
    }
    @Test public void concurrentDuplicateAndExhaustedSelectionAreFailClosed() {
        SessionCallbacks<String> s = connected(); SessionCallbacks.Ticket first = s.beginSelection(); assertNull(s.beginSelection());
        assertTrue(s.receiveSelection(first.requestCode, "first")); assertFalse(s.receiveSelection(first.requestCode, "second")); assertEquals("first", s.takeSelection().value);
        int count = 1; SessionCallbacks.Ticket ticket;
        while ((ticket = s.beginSelection()) != null) { count++; assertTrue(s.receiveSelection(ticket.requestCode, "a")); assertNotNull(s.takeSelection()); }
        assertEquals(65535 - 1024 + 1, count); s.end(); s.start(); assertNull(s.beginSelection());
    }
    @Test public void asynchronousConnectCompletingInBackgroundStartsLocked() {
        SessionCallbacks<String> s = new SessionCallbacks<>(); s.foreground(false); s.start();
        assertTrue(s.locked()); assertFalse(s.interactive()); assertNull(s.beginSelection()); s.foreground(true);
        assertTrue(s.locked()); assertTrue(s.finishAuthentication(s.beginAuthentication(), true)); assertTrue(s.interactive());
    }
    @Test public void oldViewCallbacksCannotEnterNewConnectionEvenAtSameOrigin() {
        SessionCallbacks<String> s = connected(); SessionCallbacks.Ticket old = s.viewTicket();
        assertTrue(s.ownsView(old)); s.end(); assertFalse(s.ownsView(old)); assertNull(s.viewTicket());
        s.start(); SessionCallbacks.Ticket current = s.viewTicket();
        assertNotSame(old, current); assertFalse(s.ownsView(old)); assertTrue(s.ownsView(current));
        assertFalse(s.ownsView(new SessionCallbacks.Ticket(current.session, -1)));
    }
    @Test public void backgroundKeepsOnlyCurrentViewButCannotAuthorizeDialogs() {
        SessionCallbacks<String> s = connected(); SessionCallbacks.Ticket view = s.viewTicket();
        s.foreground(false); assertTrue(s.ownsView(view)); assertFalse(s.interactive());
        s.foreground(true); assertTrue(s.ownsView(view)); assertFalse(s.interactive());
        assertTrue(s.finishAuthentication(s.beginAuthentication(), true));
        assertTrue(s.ownsView(view)); assertTrue(s.interactive());
    }
    @Test public void endingConnectionRevokesViewAndPendingSelectionTogether() {
        SessionCallbacks<String> s = connected(); SessionCallbacks.Ticket view = s.viewTicket(), pick = s.beginSelection();
        assertTrue(s.receiveSelection(pick.requestCode, "private-file")); s.end();
        assertFalse(s.ownsView(view)); assertNull(s.viewTicket()); assertNull(s.takeSelection());
        s.start(); assertFalse(s.receiveSelection(pick.requestCode, "old-file")); assertFalse(s.ownsView(view));
    }
    @Test public void oldPromptCannotConfirmInNewConnectionOrConsumeItsPrompt() {
        SessionCallbacks<String> s = connected(); SessionCallbacks.Ticket old = s.beginPrompt(s.viewTicket());
        s.end(); s.start(); SessionCallbacks.Ticket current = s.beginPrompt(s.viewTicket());
        assertFalse(s.finishPrompt(old)); assertTrue(s.finishPrompt(current)); assertFalse(s.finishPrompt(current));
    }
    @Test public void backgroundRevokesPromptAndUnlockCannotReviveOldConfirmation() {
        SessionCallbacks<String> s = connected(); SessionCallbacks.Ticket view = s.viewTicket(), prompt = s.beginPrompt(view);
        s.foreground(false); assertFalse(s.finishPrompt(prompt)); assertNull(s.beginPrompt(view)); s.foreground(true);
        assertTrue(s.finishAuthentication(s.beginAuthentication(), true)); assertFalse(s.finishPrompt(prompt));
        assertTrue(s.finishPrompt(s.beginPrompt(view)));
    }
    @Test public void duplicateCancelledAndForgedPromptsAreNeverConfirmationAuthority() {
        SessionCallbacks<String> s = connected(); SessionCallbacks.Ticket view = s.viewTicket(), first = s.beginPrompt(view);
        assertNull(s.beginPrompt(view)); assertFalse(s.finishPrompt(new SessionCallbacks.Ticket(first.session, -2)));
        s.cancelPrompt(); assertFalse(s.finishPrompt(first)); assertTrue(s.finishPrompt(s.beginPrompt(view)));
        s.end(); assertNull(s.beginPrompt(view));
    }
}
