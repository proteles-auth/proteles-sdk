# ProtelesAuth example app

One SwiftUI file: sign in, call an API with `validAccessToken()`, sign out
(with or without ending the browser session).

It is source only — there is no `.xcodeproj` checked in. To run it:

1. In Xcode, *File › New › Project… › iOS App* (SwiftUI, Swift), deployment
   target iOS 17.4 or later.
2. Delete the generated `…App.swift` and `ContentView.swift`, and add
   `ProtelesAuthExample/ProtelesAuthExampleApp.swift`.
3. *File › Add Package Dependencies…*: the package by URL, as the package's
   README shows, or *Add Local…* and a checkout of it. Add the **ProtelesAuth**
   library to the app target.
4. Set `ExampleSettings` to your tenant's issuer and the `client_id` of the
   client your administrator registered: public, with the `authorization_code`
   and `refresh_token` grants, redirect URI `https://app.example.com/oauth/callback`
   and post-logout redirect URI `https://app.example.com/oauth/signed-out`, on
   a domain of yours in place of `app.example.com`.
5. Associate that domain with the app under `webcredentials`
   (*Signing & Capabilities › Associated Domains*,
   `webcredentials:app.example.com`) and serve its
   `apple-app-site-association` file, as the package's README describes under
   "Redirect URIs". `ASWebAuthenticationSession` hands the redirect back only
   for a host associated that way.

In the Proteles repository, `scripts/ios-build-check.sh` type-checks this file
against the iOS SDK, so it stays in step with the library.
