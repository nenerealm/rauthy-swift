import SwiftUI
import PhotosUI
import Rauthy

/// Profile tab — read-only display of user info + entry points to edit
/// profile / username / avatar. Demonstrates:
///
///   - reading the `User` snapshot from `@RauthyUser` / RauthyAuthState
///   - `AccountAPI.updateProfile(...)`
///   - `AccountAPI.updatePreferredUsername(_:)`
///   - `AccountAPI.uploadAvatar(_:mimeType:)` + `deleteAvatar(pictureID:)`
///   - `AccountAPI.pictureURL(userID:pictureID:)` for display
struct ProfileTabView: View {
    @EnvironmentObject var auth: RauthyAuthState
    let user: User

    @State private var editProfileSheet = false
    @State private var editUsernameSheet = false
    @State private var avatarPickerItem: PhotosPickerItem?
    @State private var avatarBusy = false
    @State private var avatarError: String?

    var body: some View {
        NavigationStack {
            List {
                Section {
                    VStack(spacing: 16) {
                        AvatarView(user: user, size: 100)
                        VStack(spacing: 4) {
                            Text(displayName).font(.title2.bold())
                            if let email = user.email {
                                Text(email).font(.subheadline).foregroundStyle(.secondary)
                            }
                        }
                        PhotosPicker(
                            selection: $avatarPickerItem,
                            matching: .images,
                            photoLibrary: .shared()
                        ) {
                            Label(
                                user.pictureURL == nil ? "Upload avatar" : "Change avatar",
                                systemImage: "photo.on.rectangle.angled"
                            )
                        }
                        .disabled(avatarBusy)

                        if user.pictureURL != nil {
                            Button(role: .destructive) {
                                Task { await deleteAvatar() }
                            } label: {
                                Label("Remove avatar", systemImage: "trash")
                            }
                            .disabled(avatarBusy)
                        }
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 8)
                } footer: {
                    if let err = avatarError {
                        Text(err).foregroundStyle(.red)
                    } else {
                        Text("Avatar PNG/JPEG up to a few MB. Rauthy auto-resizes server-side.")
                    }
                }

                Section("Profile") {
                    InfoRow(label: "Username", value: user.preferredUsername ?? "—")
                    InfoRow(label: "Given name", value: user.givenName ?? "—")
                    InfoRow(label: "Family name", value: user.familyName ?? "—")
                    InfoRow(
                        label: "Email verified",
                        value: user.emailVerified == true ? "Yes" : "No"
                    )
                    InfoRow(label: "Language", value: user.locale ?? "default")
                }

                if !user.roles.isEmpty {
                    Section("Roles") {
                        ForEach(user.roles, id: \.self) { role in
                            Label(role, systemImage: "person.badge.shield.checkmark")
                        }
                    }
                }

                if !user.groups.isEmpty {
                    Section("Groups") {
                        ForEach(user.groups, id: \.self) { group in
                            Label(group, systemImage: "person.3")
                        }
                    }
                }

                Section {
                    Button {
                        editProfileSheet = true
                    } label: {
                        Label("Edit profile", systemImage: "pencil")
                    }

                    Button {
                        editUsernameSheet = true
                    } label: {
                        Label("Change username", systemImage: "at")
                    }
                }

                Section {
                    Button {
                        Task { await auth.refreshUser() }
                    } label: {
                        Label("Refresh from server", systemImage: "arrow.clockwise")
                    }
                    .disabled(auth.isBusy)
                }
            }
            .navigationTitle("Profile")
            .sheet(isPresented: $editProfileSheet) {
                EditProfileSheet(user: user)
            }
            .sheet(isPresented: $editUsernameSheet) {
                EditUsernameSheet(user: user)
            }
            .onChange(of: avatarPickerItem) { _, newItem in
                guard let item = newItem else { return }
                Task { await uploadAvatar(item: item) }
            }
        }
    }

    private var displayName: String {
        if let n = user.preferredUsername, !n.isEmpty { return n }
        if let g = user.givenName, let f = user.familyName { return "\(g) \(f)" }
        return user.email ?? "Unknown"
    }

    // MARK: - Avatar actions

    private func uploadAvatar(item: PhotosPickerItem) async {
        avatarError = nil
        avatarBusy = true
        defer {
            avatarBusy = false
            avatarPickerItem = nil
        }
        do {
            guard let data = try await item.loadTransferable(type: Data.self) else {
                avatarError = "Could not load image data."
                return
            }
            let mime = detectMimeType(data: data) ?? "image/jpeg"
            _ = try await auth.client.account.uploadAvatar(data, mimeType: mime)
            await auth.refreshUser()
        } catch {
            avatarError = error.localizedDescription
        }
    }

    private func deleteAvatar() async {
        guard let pictureURL = user.pictureURL else { return }
        // pictureURL ends in `.../picture/<picture_id>` — extract the last path component
        let pictureID = pictureURL.lastPathComponent
        avatarBusy = true
        defer { avatarBusy = false }
        do {
            try await auth.client.account.deleteAvatar(pictureID: pictureID)
            await auth.refreshUser()
        } catch {
            avatarError = error.localizedDescription
        }
    }

    /// Detect MIME type from leading magic bytes. Covers JPEG / PNG / GIF /
    /// WebP. Falls back to nil → caller picks a default.
    private func detectMimeType(data: Data) -> String? {
        guard data.count >= 12 else { return nil }
        let bytes = Array(data.prefix(12))
        // JPEG: FF D8 FF
        if bytes[0] == 0xFF, bytes[1] == 0xD8, bytes[2] == 0xFF { return "image/jpeg" }
        // PNG:  89 50 4E 47 0D 0A 1A 0A
        if bytes.prefix(8) == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
            return "image/png"
        }
        // GIF: "GIF8"
        if bytes.prefix(4) == [0x47, 0x49, 0x46, 0x38] { return "image/gif" }
        // WebP: "RIFF" .... "WEBP"
        if bytes.prefix(4) == [0x52, 0x49, 0x46, 0x46], bytes[8...11] == [0x57, 0x45, 0x42, 0x50] {
            return "image/webp"
        }
        return nil
    }
}

// MARK: - Avatar view

struct AvatarView: View {
    let user: User
    let size: CGFloat

    var body: some View {
        Group {
            if let url = user.pictureURL {
                AsyncImage(url: url) { phase in
                    switch phase {
                    case .empty:
                        ProgressView()
                    case .success(let image):
                        image.resizable().scaledToFill()
                    case .failure:
                        fallback
                    @unknown default:
                        fallback
                    }
                }
            } else {
                fallback
            }
        }
        .frame(width: size, height: size)
        .clipShape(Circle())
        .overlay(Circle().stroke(.tertiary, lineWidth: 1))
    }

    private var fallback: some View {
        ZStack {
            Circle().fill(.tint.opacity(0.2))
            Text(initials).font(.title.bold()).foregroundStyle(.tint)
        }
    }

    private var initials: String {
        if let n = user.preferredUsername?.first { return String(n).uppercased() }
        if let g = user.givenName?.first { return String(g).uppercased() }
        return "?"
    }
}

// MARK: - Reusable info row

struct InfoRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label).foregroundStyle(.secondary)
            Spacer()
            Text(value).multilineTextAlignment(.trailing)
        }
    }
}

// MARK: - Edit Profile sheet

struct EditProfileSheet: View {
    @EnvironmentObject var auth: RauthyAuthState
    @Environment(\.dismiss) private var dismiss

    let user: User

    @State private var email: String
    @State private var givenName: String
    @State private var familyName: String
    @State private var language: String
    @State private var saving = false
    @State private var errorMessage: String?

    init(user: User) {
        self.user = user
        _email = State(initialValue: user.email ?? "")
        _givenName = State(initialValue: user.givenName ?? "")
        _familyName = State(initialValue: user.familyName ?? "")
        _language = State(initialValue: user.locale ?? "")
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Identity") {
                    TextField("Email", text: $email)
                        .keyboardType(.emailAddress)
                        .textInputAutocapitalization(.never)
                    TextField("Given name", text: $givenName)
                    TextField("Family name", text: $familyName)
                }

                Section("Preferences") {
                    Picker("Preferred language", selection: $language) {
                        Text("Default").tag("")
                        Text("English (en)").tag("en")
                        Text("简体中文 (zh-Hans)").tag("zh-Hans")
                        Text("日本語 (ja)").tag("ja")
                        Text("Deutsch (de)").tag("de")
                    }
                }

                if let err = errorMessage {
                    Section {
                        Text(err).foregroundStyle(.red)
                    }
                }

                Section {
                    Text(
                        "Email changes trigger a verification email — the new "
                            + "address isn't active until you click the link."
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
            }
            .navigationTitle("Edit profile")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { Task { await save() } }
                        .disabled(saving || !hasChanges)
                }
            }
            .interactiveDismissDisabled(saving)
        }
    }

    private var hasChanges: Bool {
        email != (user.email ?? "")
            || givenName != (user.givenName ?? "")
            || familyName != (user.familyName ?? "")
            || language != (user.locale ?? "")
    }

    private func save() async {
        saving = true
        defer { saving = false }
        errorMessage = nil
        do {
            try await auth.client.account.updateProfile(
                email: email != (user.email ?? "") ? email : nil,
                givenName: givenName != (user.givenName ?? "") ? givenName : nil,
                familyName: familyName != (user.familyName ?? "") ? familyName : nil,
                language: language != (user.locale ?? "") ? (language.isEmpty ? nil : language) : nil
            )
            await auth.refreshUser()
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}

// MARK: - Edit Username sheet

struct EditUsernameSheet: View {
    @EnvironmentObject var auth: RauthyAuthState
    @Environment(\.dismiss) private var dismiss

    let user: User

    @State private var newUsername: String
    @State private var saving = false
    @State private var errorMessage: String?

    init(user: User) {
        self.user = user
        _newUsername = State(initialValue: user.preferredUsername ?? "")
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Username", text: $newUsername)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                } footer: {
                    Text(
                        "Alphanumeric, 1–32 characters. Subject to Rauthy's "
                            + "username regex; some punctuation may be allowed."
                    )
                }

                if let err = errorMessage {
                    Section {
                        Text(err).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Change username")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { Task { await save() } }
                        .disabled(saving || newUsername.isEmpty || newUsername == user.preferredUsername)
                }
            }
            .interactiveDismissDisabled(saving)
        }
    }

    private func save() async {
        saving = true
        defer { saving = false }
        errorMessage = nil
        do {
            try await auth.client.account.updatePreferredUsername(newUsername)
            await auth.refreshUser()
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
