import SwiftUI

/// A separate owned CI fixture exposing only its own Documents folder through
/// Apple's ordinary local file provider. No product code or network handling.
@main struct C68Receiver: App {
    init() {
        let documents=FileManager.default.urls(for:.documentDirectory,in:.userDomainMask)[0]
        let marker=documents.appendingPathComponent("C68-original-receiver-marker.txt")
        if !FileManager.default.fileExists(atPath:marker.path) { try? Data("C68 owned provider original marker\n".utf8).write(to:marker,options:.withoutOverwriting) }
    }
    var body: some Scene { WindowGroup { Text("C68 owned local document receiver") } }
}
