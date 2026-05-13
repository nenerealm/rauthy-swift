import SwiftUI
import AuthenticationServices
import Rauthy

/// Security tab — exercises all auth-hardening APIs. Demonstrates:
///
///   - `PasskeyAPI.list()`, `register(named:anchor:)`, `delete(_:)`
///   - `AccountAPI.devices()`, `revokeDevice(_:)`, `renameDevice(_:to:)`
///   - `AccountAPI.updateProfile(passwordCurrent:passwordNew:mfaCode:)`
///   - `AccountAPI.convertToPasskeyOnly()`
struct SecurityTabView: View {
    @EnvironmentObject var auth: RauthyAuthState
    let user: User

    @State private var passkeys: [Passkey] = []
    @State private var devices: [Device] = []
    @State private var loading = false
    @State private var errorMessage: String?

    @State private var newPasskeyName: String = ""
    @State private var newPasskeySheet = false

    @State private var renameDevice: Device?
    @State private var changePasswordSheet = false
    @State private var convertToPasskeyConfirm = false

    var body: some View {
        NavigationStack {
            List {
                passkeySection
                deviceSection
                passwordSection
                convertSection

                if let err = errorMessage {
                    Section {
                        Text(err).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Security")
            .refreshable { await loadAll() }
            .task { await loadAll() }
            .sheet(isPresented: $newPasskeySheet) {
                RegisterPasskeySheet { name in
                    await registerPasskey(named: name)
                }
            }
            .sheet(item: $renameDevice) { device in
                RenameDeviceSheet(device: device) { newName in
                    await renameDevice(device, to: newName)
                }
            }
            .sheet(isPresented: $changePasswordSheet) {
                ChangePasswordSheet()
            }
            .confirmationDialog(
                "Convert to passkey-only?",
                isPresented: $convertToPasskeyConfirm,
                titleVisibility: .visible
            ) {
                Button("Convert", role: .destructive) {
                    Task { await convertToPasskeyOnly() }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text(
                    "After this, you can no longer sign in with your password — only with a registered passkey. Make sure at least one passkey is registered first. This is a one-way operation from the SDK's perspective."
                )
            }
        }
    }

    // MARK: - Passkeys

    private var passkeySection: some View {
        Section {
            if passkeys.isEmpty {
                Text("No passkeys registered.")
                    .foregroundStyle(.secondary)
            } else {
                ForEach(passkeys) { passkey in
                    PasskeyRow(passkey: passkey) {
                        await deletePasskey(passkey)
                    }
                }
            }

            Button {
                newPasskeySheet = true
            } label: {
                Label("Register passkey on this device", systemImage: "key.horizontal")
            }
            .disabled(loading)
        } header: {
            Text("Passkeys")
        } footer: {
            Text("WebAuthn registration uses Face ID / Touch ID. Real-device only — Simulator can't enroll biometric credentials.")
        }
    }

    // MARK: - Devices

    private var deviceSection: some View {
        Section("Active devices") {
            if devices.isEmpty {
                Text("No devices found.").foregroundStyle(.secondary)
            } else {
                ForEach(devices) { device in
                    DeviceRow(
                        device: device,
                        onRename: { renameDevice = device },
                        onRevoke: { Task { await revokeDevice(device) } }
                    )
                }
            }
        }
    }

    // MARK: - Password

    private var passwordSection: some View {
        Section("Password") {
            Button {
                changePasswordSheet = true
            } label: {
                Label("Change password", systemImage: "key.fill")
            }
        }
    }

    // MARK: - Passkey-only conversion

    private var convertSection: some View {
        Section {
            Button(role: .destructive) {
                convertToPasskeyConfirm = true
            } label: {
                Label("Convert to passkey-only login", systemImage: "key.viewfinder")
            }
            .disabled(passkeys.isEmpty)
        } footer: {
            if passkeys.isEmpty {
                Text("Register at least one passkey before converting.")
            } else {
                Text("Removes password sign-in. You'll need to use a registered passkey for every future login.")
            }
        }
    }

    // MARK: - Actions

    private func loadAll() async {
        loading = true
        defer { loading = false }
        errorMessage = nil
        async let pk: () = loadPasskeys()
        async let dev: () = loadDevices()
        _ = await (pk, dev)
    }

    private func loadPasskeys() async {
        do {
            passkeys = try await auth.client.passkeys.list()
        } catch {
            errorMessage = "Passkeys: \(error.localizedDescription)"
        }
    }

    private func loadDevices() async {
        do {
            devices = try await auth.client.account.devices()
        } catch {
            errorMessage = "Devices: \(error.localizedDescription)"
        }
    }

    @MainActor
    private func registerPasskey(named name: String) async {
        loading = true
        defer { loading = false }
        do {
            let trimmed = name.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty else { return }
            guard let anchor = auth.presentationAnchor else {
                errorMessage = "No presentation context — did .rauthyPresentationContext() run?"
                return
            }
            try await auth.client.passkeys.register(named: trimmed, anchor: anchor)
            await loadPasskeys()
        } catch RauthyError.userCancelled {
            // User dismissed Face ID prompt — silent
        } catch {
            errorMessage = "Register passkey: \(error.localizedDescription)"
        }
    }

    private func deletePasskey(_ passkey: Passkey) async {
        do {
            try await auth.client.passkeys.delete(passkey)
            await loadPasskeys()
        } catch {
            errorMessage = "Delete passkey: \(error.localizedDescription)"
        }
    }

    private func renameDevice(_ device: Device, to newName: String) async {
        do {
            try await auth.client.account.renameDevice(device, to: newName)
            await loadDevices()
        } catch {
            errorMessage = "Rename device: \(error.localizedDescription)"
        }
    }

    private func revokeDevice(_ device: Device) async {
        do {
            try await auth.client.account.revokeDevice(device)
            await loadDevices()
        } catch {
            errorMessage = "Revoke device: \(error.localizedDescription)"
        }
    }

    private func convertToPasskeyOnly() async {
        do {
            try await auth.client.account.convertToPasskeyOnly()
            await auth.refreshUser()
        } catch {
            errorMessage = "Convert to passkey-only: \(error.localizedDescription)"
        }
    }
}

// MARK: - Passkey row

struct PasskeyRow: View {
    let passkey: Passkey
    let onDelete: () async -> Void

    @State private var confirmDelete = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(passkey.name).font(.headline)
            HStack(spacing: 12) {
                Label(formatted(passkey.registered), systemImage: "calendar")
                Label(formatted(passkey.lastUsed), systemImage: "clock")
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        .swipeActions {
            Button(role: .destructive) {
                confirmDelete = true
            } label: {
                Label("Delete", systemImage: "trash")
            }
        }
        .confirmationDialog(
            "Delete passkey \"\(passkey.name)\"?",
            isPresented: $confirmDelete,
            titleVisibility: .visible
        ) {
            Button("Delete", role: .destructive) {
                Task { await onDelete() }
            }
            Button("Cancel", role: .cancel) {}
        }
    }

    private func formatted(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateStyle = .medium
        formatter.timeStyle = .none
        return formatter.string(from: date)
    }
}

// MARK: - Device row

struct DeviceRow: View {
    let device: Device
    let onRename: () -> Void
    let onRevoke: () -> Void

    @State private var confirmRevoke = false

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(device.name).font(.headline)
            HStack {
                Label(device.peerIP, systemImage: "network")
                Spacer()
                Text(device.id.prefix(8) + "…").font(.caption.monospaced())
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        .swipeActions(edge: .trailing) {
            Button(role: .destructive) {
                confirmRevoke = true
            } label: {
                Label("Revoke", systemImage: "xmark.circle")
            }

            Button {
                onRename()
            } label: {
                Label("Rename", systemImage: "pencil")
            }
            .tint(.blue)
        }
        .confirmationDialog(
            "Revoke device \"\(device.name)\"?",
            isPresented: $confirmRevoke,
            titleVisibility: .visible
        ) {
            Button("Revoke", role: .destructive) { onRevoke() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("This signs the device out of its Rauthy session. The user will need to sign in again on that device.")
        }
    }
}

// MARK: - Sheets

struct RegisterPasskeySheet: View {
    @Environment(\.dismiss) private var dismiss
    @State private var name: String = ""
    let onRegister: (String) async -> Void

    @State private var busy = false

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Passkey name", text: $name)
                        .textInputAutocapitalization(.words)
                } footer: {
                    Text(
                        "Give this passkey a name (e.g. \"iPhone\", \"Work laptop\"). 2–128 chars."
                    )
                }
            }
            .navigationTitle("Register passkey")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Register") {
                        busy = true
                        Task {
                            await onRegister(name)
                            busy = false
                            dismiss()
                        }
                    }
                    .disabled(busy || name.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
            .interactiveDismissDisabled(busy)
        }
    }
}

struct RenameDeviceSheet: View {
    @Environment(\.dismiss) private var dismiss
    let device: Device
    let onRename: (String) async -> Void

    @State private var newName: String
    @State private var busy = false

    init(device: Device, onRename: @escaping (String) async -> Void) {
        self.device = device
        self.onRename = onRename
        _newName = State(initialValue: device.name)
    }

    var body: some View {
        NavigationStack {
            Form {
                TextField("Device name", text: $newName)
                    .textInputAutocapitalization(.words)
            }
            .navigationTitle("Rename device")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        busy = true
                        Task {
                            await onRename(newName)
                            busy = false
                            dismiss()
                        }
                    }
                    .disabled(busy || newName == device.name || newName.count < 2)
                }
            }
        }
    }
}

struct ChangePasswordSheet: View {
    @EnvironmentObject var auth: RauthyAuthState
    @Environment(\.dismiss) private var dismiss

    @State private var current = ""
    @State private var new = ""
    @State private var confirm = ""
    @State private var mfaCode = ""
    @State private var busy = false
    @State private var errorMessage: String?

    var body: some View {
        NavigationStack {
            Form {
                Section("Current password") {
                    SecureField("Required", text: $current)
                }
                Section("New password") {
                    SecureField("New password", text: $new)
                    SecureField("Confirm new password", text: $confirm)
                }
                Section("MFA code (if enabled)") {
                    TextField("123456", text: $mfaCode)
                        .keyboardType(.numberPad)
                }

                if let err = errorMessage {
                    Section {
                        Text(err).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Change password")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { Task { await save() } }
                        .disabled(!canSave)
                }
            }
            .interactiveDismissDisabled(busy)
        }
    }

    private var canSave: Bool {
        !busy && !current.isEmpty && new.count >= 8 && new == confirm
    }

    private func save() async {
        busy = true
        defer { busy = false }
        errorMessage = nil
        do {
            try await auth.client.account.updateProfile(
                passwordCurrent: current,
                passwordNew: new,
                mfaCode: mfaCode.isEmpty ? nil : mfaCode
            )
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
