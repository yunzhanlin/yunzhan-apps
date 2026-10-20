import Foundation

struct SessionCallbackTicket: Equatable {
    fileprivate let session: UUID
    fileprivate let nonce = UUID()
}

/// Value-only main-actor-owned state, with no WebKit, credentials or storage.
struct SessionCallbacks<Value> {
    struct Selection { let value: Value? }
    private var session = UUID()
    private var active = false
    private var foreground = true
    private(set) var locked = false
    private var auth: SessionCallbackTicket?
    private var authenticatedWhileInactive = false
    private var picker: SessionCallbackTicket?
    private var selected: Value?
    private var ready = false
    var interactive: Bool { active && foreground && !locked }
    mutating func start() { end(); active = true }
    mutating func end() {
        session = UUID(); active = false; locked = false; auth = nil
        authenticatedWhileInactive = false; cancelSelection()
    }
    mutating func cover(background: Bool) {
        foreground = false
        if background && active { locked = true; auth = nil; authenticatedWhileInactive = false }
    }
    mutating func activate() {
        foreground = true
        if active && authenticatedWhileInactive { locked = false }
        authenticatedWhileInactive = false
    }
    mutating func beginAuthentication() -> SessionCallbackTicket? {
        guard active, foreground, locked, auth == nil, !authenticatedWhileInactive else { return nil }
        let next = SessionCallbackTicket(session: session); auth = next; return next
    }
    mutating func finishAuthentication(_ ticket: SessionCallbackTicket, success: Bool) -> Bool {
        guard active, auth == ticket, ticket.session == session else { return false }
        auth = nil
        guard success, locked else { return false }
        if foreground { locked = false } else { authenticatedWhileInactive = true }
        return true
    }
    mutating func beginSelection() -> SessionCallbackTicket? {
        guard interactive, picker == nil else { return nil }
        let next = SessionCallbackTicket(session: session); picker = next; return next
    }
    mutating func receiveSelection(_ ticket: SessionCallbackTicket, value: Value?) -> Bool {
        guard active, picker == ticket, ticket.session == session, !ready else { return false }
        selected = value; ready = true; return true
    }
    mutating func takeSelection() -> Selection? {
        guard interactive, ready else { return nil }
        let result = Selection(value: selected); cancelSelection(); return result
    }
    mutating func cancelSelection() { picker = nil; selected = nil; ready = false }
}
