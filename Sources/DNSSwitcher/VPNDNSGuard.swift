import Foundation
import SystemConfiguration
import Darwin
import notify

/// Event-driven SCDynamicStore guard inside the privileged root bridge daemon.
/// Ensures active corporate VPN services (e.g. Palo Alto GlobalProtect `gpd.pan`) route DNS queries
/// through `127.0.0.1` when DoH is enabled, while preserving original VPN DNS addresses for Split-DNS
/// and restoring them cleanly when disabled or when the daemon stops.
public final class VPNDNSGuard: @unchecked Sendable {
    public static let shared = VPNDNSGuard()

    public static let origServersKey = "DNSSwitcherOrigServerAddresses"
    public static let configNotificationName = "com.dnsswitcher.vpnGuardConfigChanged"

    private static let proxyBundleKeywords = [
        "v2ray", "v2box", "happ", "outline", "sing-box", "singbox",
        "clash", "mihomo", "shadowrocket", "nekoray", "hiddify",
        "xray", "amnezia", "nekobox"
    ]

    private let queue = DispatchQueue(label: "com.dnsswitcher.bridge.vpnguard", qos: .utility)
    private var store: SCDynamicStore?
    private var debounceWorkItem: DispatchWorkItem?
    private var notifyToken: Int32 = 0
    private var sigTermSource: DispatchSourceSignal?
    private var sigIntSource: DispatchSourceSignal?
    private var writeTimestamps: [String: [Date]] = [:]
    private var isStarted = false

    private init() {}

    // MARK: - Pure Decision & Transformation Helpers

    /// Returns true for known FakeIP / virtual proxy DNS addresses used by proxy tunnels (e.g. 198.18.0.0/15, 172.19.0.2).
    public static func isFakeIPAddress(_ ip: String) -> Bool {
        let trimmed = ip.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed == "172.19.0.2" {
            return true
        }
        guard SystemDNSManager.isValidNonLoopbackIPv4(trimmed) else { return false }
        return trimmed.hasPrefix("198.18.") || trimmed.hasPrefix("198.19.")
    }

    /// Returns true if the VPN NetworkExtension bundle ID matches a known proxy / FakeIP tunnel client.
    public static func isKnownProxyBundleID(_ bundleID: String) -> Bool {
        let lower = bundleID.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !lower.isEmpty else { return false }
        return proxyBundleKeywords.contains { lower.contains($0) }
    }

    /// Returns true when a DNS dictionary only applies to explicit supplemental domains (domain-scoped split-DNS)
    /// rather than capturing all queries (`""`, `"*"`, or `"."`).
    public static func isDomainScopedOnly(dnsDict: [String: Any]) -> Bool {
        guard let domains = dnsDict["SupplementalMatchDomains"] as? [String], !domains.isEmpty else {
            return false
        }
        return !domains.contains { domain in
            let trimmed = domain.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed.isEmpty || trimmed == "*" || trimmed == "."
        }
    }

    /// Parses the persisted toggle configuration content; defaults to enabled when absent or unrecognized.
    public static func isGuardConfigEnabled(from content: String?) -> Bool {
        guard let raw = content?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(), !raw.isEmpty else {
            return true
        }
        return !(raw == "disabled" || raw == "false" || raw == "0")
    }

    /// Determines whether a non-physical dynamic store DNS service should be intercepted to route through `127.0.0.1`.
    public static func shouldInterceptVPNService(
        serviceID: String,
        isPhysicalEthernet: Bool,
        dnsDict: [String: Any],
        vpnBundleID: String?
    ) -> Bool {
        guard !isPhysicalEthernet, !serviceID.isEmpty else { return false }
        if isDomainScopedOnly(dnsDict: dnsDict) {
            return false
        }
        if let bundleID = vpnBundleID, isKnownProxyBundleID(bundleID) {
            return false
        }

        let currentAddrs = dnsDict["ServerAddresses"] as? [String] ?? []
        let origAddrs = dnsDict[origServersKey] as? [String] ?? []
        let allIPs = currentAddrs + origAddrs

        if allIPs.contains(where: { isFakeIPAddress($0) }) {
            return false
        }
        if !origAddrs.isEmpty {
            return true
        }
        return currentAddrs.contains { SystemDNSManager.isValidNonLoopbackIPv4($0) }
    }

    /// Returns an updated DNS dictionary routing `ServerAddresses` to `["127.0.0.1"]` and backing up the originals
    /// in `DNSSwitcherOrigServerAddresses`, or `nil` if already patched or no non-loopback servers exist.
    public static func makePatchedDNSDict(from current: [String: Any]) -> [String: Any]? {
        let currentServers = current["ServerAddresses"] as? [String] ?? []
        if currentServers == ["127.0.0.1"] {
            return nil
        }

        let existingOrig = current[origServersKey] as? [String] ?? []
        let originalServers: [String]
        if !existingOrig.isEmpty && currentServers.contains("127.0.0.1") {
            originalServers = existingOrig
        } else {
            originalServers = currentServers.filter { $0 != "127.0.0.1" }
        }
        guard !originalServers.isEmpty else { return nil }

        var updated = current
        updated[origServersKey] = originalServers
        updated["ServerAddresses"] = ["127.0.0.1"]
        return updated
    }

    /// Restores original `ServerAddresses` from `DNSSwitcherOrigServerAddresses` and removes the backup key,
    /// or returns `nil` if no backup is present.
    public static func makeRestoredDNSDict(from current: [String: Any]) -> [String: Any]? {
        guard let orig = current[origServersKey] as? [String], !orig.isEmpty else {
            return nil
        }
        var restored = current
        restored["ServerAddresses"] = orig
        restored.removeValue(forKey: origServersKey)
        return restored
    }

    // MARK: - Daemon Lifecycle

    /// Starts event-driven SCDynamicStore watching, Darwin notification listening, and clean shutdown handlers.
    public func start() {
        queue.async { [weak self] in
            guard let self = self, !self.isStarted else { return }
            self.isStarted = true
            self.setupStore()
            self.setupConfigNotification()
            self.setupSignalHandlers()
            self.reconcile()
        }
    }

    private func setupStore() {
        var context = SCDynamicStoreContext(
            version: 0,
            info: Unmanaged.passUnretained(self).toOpaque(),
            retain: nil,
            release: nil,
            copyDescription: nil
        )

        let callback: SCDynamicStoreCallBack = { _, _, info in
            guard let info = info else { return }
            let guardObj = Unmanaged<VPNDNSGuard>.fromOpaque(info).takeUnretainedValue()
            guardObj.scheduleReconcile(delay: 0.15)
        }

        guard let store = SCDynamicStoreCreate(nil, "com.dnsswitcher.bridge.vpnguard" as CFString, callback, &context) else {
            fputs("[VPNDNSGuard] Failed to create SCDynamicStore\n", stderr)
            return
        }
        self.store = store

        let patterns = [
            "State:/Network/Service/.*/DNS",
            "Setup:/Network/Service/.*/DNS",
            "State:/Network/Global/DNS",
            "State:/Network/Global/IPv4"
        ] as CFArray

        SCDynamicStoreSetNotificationKeys(store, nil, patterns)
        SCDynamicStoreSetDispatchQueue(store, queue)
    }

    private func setupConfigNotification() {
        var token: Int32 = 0
        let status = notify_register_dispatch(Self.configNotificationName, &token, queue) { [weak self] _ in
            self?.scheduleReconcile(delay: 0.05)
        }
        if status == NOTIFY_STATUS_OK {
            self.notifyToken = token
        } else {
            fputs("[VPNDNSGuard] notify_register_dispatch failed status=\(status)\n", stderr)
        }
    }

    private func setupSignalHandlers() {
        signal(SIGTERM, SIG_IGN)
        signal(SIGINT, SIG_IGN)

        let termSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: queue)
        termSource.setEventHandler { [weak self] in
            if let store = self?.store {
                self?.restoreAllPatchedServices(store: store)
            }
            _exit(0)
        }
        termSource.resume()
        self.sigTermSource = termSource

        let intSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: queue)
        intSource.setEventHandler { [weak self] in
            if let store = self?.store {
                self?.restoreAllPatchedServices(store: store)
            }
            _exit(0)
        }
        intSource.resume()
        self.sigIntSource = intSource
    }

    private func scheduleReconcile(delay: TimeInterval) {
        queue.async { [weak self] in
            guard let self = self else { return }
            self.debounceWorkItem?.cancel()
            let work = DispatchWorkItem { [weak self] in
                self?.reconcile()
            }
            self.debounceWorkItem = work
            self.queue.asyncAfter(deadline: .now() + delay, execute: work)
        }
    }

    private func reconcile() {
        guard let store = self.store else { return }

        let configContent = try? String(contentsOfFile: SystemDNSManager.vpnGuardConfigPath, encoding: .utf8)
        let enabled = Self.isGuardConfigEnabled(from: configContent)
        let dohActive = isPhysicalDoHConfigured(store: store)

        if !enabled || !dohActive {
            restoreAllPatchedServices(store: store)
            return
        }

        guard let keys = SCDynamicStoreCopyKeyList(store, "State:/Network/Service/.*/DNS" as CFString) as? [String] else {
            return
        }

        let now = Date()
        var didModify = false

        for key in keys {
            let parts = key.split(separator: "/")
            guard parts.count >= 4 else { continue }
            let serviceID = String(parts[3])

            if SystemDNSManager.isPhysicalEthernetService(store: store, serviceID: serviceID) {
                continue
            }

            guard let dnsDict = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any] else {
                continue
            }

            let hasIPv4 = SCDynamicStoreCopyValue(store, "State:/Network/Service/\(serviceID)/IPv4" as CFString) != nil
            let hasIPv6 = SCDynamicStoreCopyValue(store, "State:/Network/Service/\(serviceID)/IPv6" as CFString) != nil
            let hasCatchAllSupplemental: Bool = {
                guard let domains = dnsDict["SupplementalMatchDomains"] as? [String] else { return false }
                return domains.contains { domain in
                    let trimmed = domain.trimmingCharacters(in: .whitespacesAndNewlines)
                    return trimmed.isEmpty || trimmed == "*" || trimmed == "."
                }
            }()
            guard hasIPv4 || hasIPv6 || hasCatchAllSupplemental else {
                continue
            }

            let vpnDict = SCDynamicStoreCopyValue(store, "Setup:/Network/Service/\(serviceID)/VPN" as CFString) as? [String: Any]
            let vpnBundleID = vpnDict?["NEProviderBundleIdentifier"] as? String

            if Self.shouldInterceptVPNService(
                serviceID: serviceID,
                isPhysicalEthernet: false,
                dnsDict: dnsDict,
                vpnBundleID: vpnBundleID
            ) {
                var history = (writeTimestamps[serviceID] ?? []).filter { now.timeIntervalSince($0) < 10.0 }
                if history.count >= 6 {
                    fputs("[VPNDNSGuard] Rate-limited writes for \(serviceID)\n", stderr)
                    writeTimestamps[serviceID] = history
                    continue
                }
                if let patched = Self.makePatchedDNSDict(from: dnsDict) {
                    if SCDynamicStoreSetValue(store, key as CFString, patched as CFDictionary) {
                        fputs("[VPNDNSGuard] Routed VPN service \(serviceID) DNS -> 127.0.0.1\n", stderr)
                        history.append(now)
                        writeTimestamps[serviceID] = history
                        didModify = true
                    } else {
                        fputs("[VPNDNSGuard] Failed to update \(key)\n", stderr)
                    }
                }
            } else if let restored = Self.makeRestoredDNSDict(from: dnsDict) {
                if SCDynamicStoreSetValue(store, key as CFString, restored as CFDictionary) {
                    fputs("[VPNDNSGuard] Restored excluded VPN service \(serviceID) DNS\n", stderr)
                    didModify = true
                }
            }
        }

        if didModify {
            flushSystemDNS()
        }
    }

    private func isPhysicalDoHConfigured(store: SCDynamicStore) -> Bool {
        guard let keys = SCDynamicStoreCopyKeyList(store, "Setup:/Network/Service/.*/DNS" as CFString) as? [String] else {
            return false
        }
        for key in keys {
            let parts = key.split(separator: "/")
            guard parts.count >= 4 else { continue }
            let serviceID = String(parts[3])
            guard SystemDNSManager.isPhysicalEthernetService(store: store, serviceID: serviceID),
                  let setupDNS = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any] else {
                continue
            }
            if let servers = setupDNS["ServerAddresses"] as? [String], servers.contains("127.0.0.1") {
                return true
            }
            if let orig = setupDNS["OpenVPNConnectOrigServerAddresses"] as? [String], orig.contains("127.0.0.1") {
                return true
            }
        }
        return false
    }

    private func restoreAllPatchedServices(store: SCDynamicStore) {
        guard let keys = SCDynamicStoreCopyKeyList(store, "State:/Network/Service/.*/DNS" as CFString) as? [String] else {
            return
        }
        var didModify = false
        for key in keys {
            let parts = key.split(separator: "/")
            let serviceID = parts.count >= 4 ? String(parts[3]) : key
            guard let dnsDict = SCDynamicStoreCopyValue(store, key as CFString) as? [String: Any],
                  let restored = Self.makeRestoredDNSDict(from: dnsDict) else {
                continue
            }
            if SCDynamicStoreSetValue(store, key as CFString, restored as CFDictionary) {
                fputs("[VPNDNSGuard] Restored VPN service \(serviceID) DNS\n", stderr)
                didModify = true
            }
        }
        if didModify {
            flushSystemDNS()
        }
    }

    private func flushSystemDNS() {
        _ = SystemDNSManager.runCommand("/usr/bin/dscacheutil", ["-flushcache"])
        _ = SystemDNSManager.runCommand("/usr/bin/killall", ["-HUP", "mDNSResponder"])
    }
}
