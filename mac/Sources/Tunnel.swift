import CoreBluetooth
import Darwin
import Foundation

/// Enlace por Bluetooth cuando la red no llega al celular (p. ej. el "kill switch" de un VPN bloquea la red local).
/// Escucha en 127.0.0.1 (lo local no lo bloquea el VPN) y cada conexión se vuelve un canal L2CAP con el celular,
/// que la reenvía a su enlace cifrado. NetChannel cifra igual que por Wi‑Fi: el Bluetooth solo transporta bytes.
final class BluetoothTunnel {
    private let proximity: Proximity
    private var listenFD: Int32 = -1
    private(set) var port: UInt16 = 0
    private let lock = NSLock()

    init(proximity: Proximity) { self.proximity = proximity }

    /// Puerto local del túnel, o nil si no se puede (sin Bluetooth o sin el celular a la vista).
    func localPort() -> UInt16? {
        guard DispatchQueue.main.sync(execute: { proximity.status.seen && proximity.status.bluetoothOn }) else { return nil }
        lock.lock(); defer { lock.unlock() }
        if listenFD >= 0 { return port }
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        var a = sockaddr_in()
        a.sin_family = sa_family_t(AF_INET)
        a.sin_addr.s_addr = inet_addr("127.0.0.1")
        a.sin_port = 0
        let ok = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) == 0 } }
        guard ok, listen(fd, 4) == 0 else { close(fd); return nil }
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        listenFD = fd
        port = UInt16(bigEndian: a.sin_port)
        Thread.detachNewThread { [weak self] in
            while true {
                let c = accept(fd, nil, nil)
                if c < 0 { continue }
                self?.serve(c)
            }
        }
        return port
    }

    private func serve(_ c: Int32) {
        var one: Int32 = 1
        setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        let got = DispatchSemaphore(value: 0)
        var channel: CBL2CAPChannel?
        DispatchQueue.main.async {
            self.proximity.openChannel { ch in channel = ch; got.signal() }
        }
        guard got.wait(timeout: .now() + 14) == .success, let ch = channel else { close(c); return }
        L2Pump(channel: ch, fd: c) { [weak self] in
            DispatchQueue.main.async { self?.proximity.channelClosed(ch) }
        }.start()
    }
}

/// Copia bytes entre un socket local y un canal L2CAP, en un hilo con su propio run loop.
private final class L2Pump: NSObject, StreamDelegate {
    private let ch: CBL2CAPChannel
    private let fd: Int32
    private let onClose: () -> Void
    private var out = Data()
    private var thread: Thread!
    private var closed = false
    private var retainSelf: L2Pump?

    init(channel: CBL2CAPChannel, fd: Int32, onClose: @escaping () -> Void) {
        ch = channel; self.fd = fd; self.onClose = onClose
    }

    func start() {
        retainSelf = self
        thread = Thread { [self] in
            for s in [ch.inputStream as Stream, ch.outputStream as Stream] {
                s.delegate = self
                s.schedule(in: .current, forMode: .default)
                s.open()
            }
            Thread.detachNewThread { self.readSocket() }
            while !closed { RunLoop.current.run(mode: .default, before: Date().addingTimeInterval(0.5)) }
            for s in [ch.inputStream as Stream, ch.outputStream as Stream] {
                s.close(); s.remove(from: .current, forMode: .default); s.delegate = nil
            }
            Darwin.shutdown(fd, SHUT_RDWR)
            Darwin.close(fd)
            onClose()
            retainSelf = nil
        }
        thread.start()
    }

    /// Socket local → Bluetooth
    private func readSocket() {
        var buf = [UInt8](repeating: 0, count: 16384)
        while true {
            let n = Darwin.read(fd, &buf, buf.count)
            if n <= 0 { perform(#selector(stop), on: thread, with: nil, waitUntilDone: false); return }
            perform(#selector(enqueue(_:)), on: thread, with: Data(buf[0..<n]) as NSData, waitUntilDone: false)
        }
    }

    @objc private func enqueue(_ d: NSData) { out.append(d as Data); flush() }

    @objc private func stop() { closed = true }

    private func flush() {
        while !out.isEmpty, ch.outputStream.hasSpaceAvailable {
            let n = out.withUnsafeBytes { ch.outputStream.write($0.bindMemory(to: UInt8.self).baseAddress!, maxLength: out.count) }
            if n <= 0 { break }
            out.removeFirst(n)
        }
    }

    func stream(_ s: Stream, handle e: Stream.Event) {
        switch e {
        case .hasBytesAvailable:
            var buf = [UInt8](repeating: 0, count: 16384)
            while ch.inputStream.hasBytesAvailable {
                let n = ch.inputStream.read(&buf, maxLength: buf.count)
                if n <= 0 { break }
                var off = 0
                while off < n { // Bluetooth → socket local
                    let w = buf.withUnsafeBytes { Darwin.write(fd, $0.baseAddress! + off, n - off) }
                    if w <= 0 { closed = true; return }
                    off += w
                }
            }
        case .hasSpaceAvailable: flush()
        case .errorOccurred, .endEncountered: closed = true
        default: break
        }
    }
}
