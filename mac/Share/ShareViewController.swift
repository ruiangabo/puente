import AppKit

/// Extensión «Compartir → Puente»: toma los archivos y se los pasa a Puente.app, que los manda al celular.
/// No tiene ventana: entrega los archivos y se cierra.
final class ShareViewController: NSViewController {
    override func loadView() { view = NSView(frame: NSRect(x: 0, y: 0, width: 1, height: 1)) }

    override func beginRequest(with context: NSExtensionContext) {
        super.beginRequest(with: context)
        let providers = (context.inputItems as? [NSExtensionItem] ?? []).flatMap { $0.attachments ?? [] }
        let group = DispatchGroup()
        let lock = NSLock()
        var urls: [URL] = []
        for p in providers where p.hasItemConformingToTypeIdentifier("public.file-url") {
            group.enter()
            p.loadItem(forTypeIdentifier: "public.file-url", options: nil) { item, _ in
                var u = item as? URL
                if u == nil, let d = item as? Data { u = URL(dataRepresentation: d, relativeTo: nil) }
                if let u, u.isFileURL { lock.lock(); urls.append(u); lock.unlock() }
                group.leave()
            }
        }
        group.notify(queue: .main) {
            // …/Puente.app/Contents/PlugIns/PuenteShare.appex → …/Puente.app
            let app = Bundle.main.bundleURL.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            guard !urls.isEmpty else { context.cancelRequest(withError: NSError(domain: "Puente", code: 1)); return }
            let cfg = NSWorkspace.OpenConfiguration()
            cfg.activates = false
            NSWorkspace.shared.open(urls, withApplicationAt: app, configuration: cfg) { _, _ in
                DispatchQueue.main.async { context.completeRequest(returningItems: nil) }
            }
        }
    }
}
