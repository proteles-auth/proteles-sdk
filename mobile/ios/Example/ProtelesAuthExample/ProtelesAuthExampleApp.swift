// A minimal SwiftUI app using ProtelesAuth: sign in, call an API with a valid
// access token, sign out. See Example/README.md for making it an Xcode project.

import ProtelesAuth
import SwiftUI
import UIKit

@main
struct ProtelesAuthExampleApp: App {
    @StateObject private var auth = AuthModel()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(auth)
                .task { await auth.load() }
        }
    }
}

/// Replace these with your tenant's issuer and the client your administrator
/// registered for this app (public, with the authorization_code and
/// refresh_token grants, and exactly this redirect URI), on a domain
/// associated with the app under `webcredentials`.
enum ExampleSettings {
    static let issuer = "https://acme.proteles.example"
    static let clientId = "com.example.proteles-demo"
    static let redirectURI = "https://app.example.com/oauth/callback"
    static let postLogoutRedirectURI = "https://app.example.com/oauth/signed-out"
    static let apiURL = URL(string: "https://api.example.com/me")!
}

@MainActor
final class AuthModel: ObservableObject {
    @Published private(set) var user: UserClaims?
    @Published private(set) var message: String?
    @Published private(set) var busy = false

    private let client: ProtelesClient?

    init() {
        do {
            let configuration = try ProtelesConfiguration(
                issuer: ExampleSettings.issuer,
                clientId: ExampleSettings.clientId,
                redirectURI: ExampleSettings.redirectURI,
                postLogoutRedirectURI: ExampleSettings.postLogoutRedirectURI
            )
            client = try ProtelesClient(configuration: configuration)
        } catch {
            // A configuration error is a bug in the app, found on first launch.
            client = nil
            message = error.localizedDescription
        }
    }

    func load() async {
        guard let client else { return }
        do {
            user = try await client.currentUser()
        } catch {
            message = error.localizedDescription
        }
    }

    func signIn() async {
        guard let client, let window = Self.keyWindow() else { return }
        await run {
            self.user = try await client.signIn(presentationAnchor: window)
            self.message = nil
        }
    }

    func callAPI() async {
        guard let client else { return }
        await run {
            // Ask for the token before every request; never cache it.
            let token = try await client.validAccessToken()
            var request = URLRequest(url: ExampleSettings.apiURL)
            request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            let (_, response) = try await URLSession.shared.data(for: request)
            self.message = "API answered HTTP \((response as? HTTPURLResponse)?.statusCode ?? 0)"
        }
    }

    /// `endBrowserSession` must come from a user gesture: it opens the
    /// browser so the next sign-in asks for credentials again.
    func signOut(endBrowserSession: Bool) async {
        guard let client else { return }
        await run {
            let result: SignOutResult
            if endBrowserSession, let window = Self.keyWindow() {
                result = try await client.signOut(endSessionPresentingFrom: window)
            } else {
                result = try await client.signOut()
            }
            self.user = nil
            if case .failed(let error) = result.revocation {
                // Signed out on this device either way; the server-side
                // refresh token outlives this if revocation failed.
                self.message = "Signed out locally; revocation failed: \(error.localizedDescription)"
            } else {
                self.message = "Signed out"
            }
        }
    }

    private func run(_ body: @escaping () async throws -> Void) async {
        busy = true
        defer { busy = false }
        do {
            try await body()
        } catch ProtelesAuthError.cancelled {
            message = nil // the user closed the browser; nothing to report
        } catch ProtelesAuthError.alreadyInProgress {
            // A sign-in is already showing the browser; let it finish.
        } catch ProtelesAuthError.signInRequired {
            user = nil
            message = "Please sign in again."
        } catch ProtelesAuthError.rateLimited(let retryAfter) {
            // The SDK caps its own values at an hour; `Int(_:)` traps on
            // anything past Int.max, so clamp before converting.
            let seconds = min(max(retryAfter ?? 60, 0), 3600)
            message = "Too many requests; try again in \(Int(seconds.rounded(.up))) s."
        } catch {
            message = error.localizedDescription
        }
    }

    private static func keyWindow() -> UIWindow? {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
            .first(where: \.isKeyWindow)
    }
}

struct ContentView: View {
    @EnvironmentObject private var auth: AuthModel

    var body: some View {
        VStack(spacing: 16) {
            if let user = auth.user {
                Text("Signed in as \(user.email ?? user.preferredUsername ?? user.subject)")
                Button("Call the API") { Task { await auth.callAPI() } }
                Button("Sign out") { Task { await auth.signOut(endBrowserSession: false) } }
                Button("Sign out everywhere in this browser") { Task { await auth.signOut(endBrowserSession: true) } }
            } else {
                Button("Sign in") { Task { await auth.signIn() } }
            }
            if let message = auth.message {
                Text(message).font(.footnote).foregroundColor(.secondary)
            }
        }
        .disabled(auth.busy)
        .padding()
    }
}
