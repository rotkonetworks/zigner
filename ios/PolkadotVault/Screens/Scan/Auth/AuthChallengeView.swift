//
//  AuthChallengeView.swift
//  Zigner
//
//  QR-based ed25519 auth: scan challenge, review domain, sign, display response.

import SwiftUI

struct AuthChallengeView: View {
    @StateObject var viewModel: ViewModel

    var body: some View {
        VStack(spacing: 0) {
            NavigationBarView(
                viewModel: .init(
                    title: .title("Sign In"),
                    leftButtons: [.init(type: .xmark, action: viewModel.onDismiss)],
                    rightButtons: [.init(type: .empty)],
                    backgroundColor: .backgroundPrimary
                )
            )
            switch viewModel.state {
            case .review:
                reviewView
            case .signing:
                progressView
            case let .displayResponse(json):
                responseView(json: json)
            case let .error(message):
                errorView(message: message)
            }
        }
        .background(.backgroundPrimary)
    }

    private var reviewView: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(spacing: Spacing.medium) {
                    // Domain — big and prominent
                    VStack(spacing: Spacing.small) {
                        Text("Authenticate to")
                            .font(PrimaryFont.labelM.font)
                            .foregroundColor(.textAndIconsTertiary)
                        Text(viewModel.domain)
                            .font(PrimaryFont.titleL.font)
                            .foregroundColor(.textAndIconsPrimary)
                            .multilineTextAlignment(.center)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(Spacing.large)
                    .containerBackground()

                    // Identity
                    if let pubkey = viewModel.pubkeyHex {
                        VStack(alignment: .leading, spacing: Spacing.extraSmall) {
                            Text("Identity #\(viewModel.index)")
                                .font(PrimaryFont.labelM.font)
                                .foregroundColor(.textAndIconsTertiary)
                            Text("zid\(String(pubkey.prefix(16)))")
                                .font(PrimaryFont.captionM.font)
                                .foregroundColor(.textAndIconsSecondary)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(Spacing.small)
                        .containerBackground()
                    }

                    // Stale warning
                    if viewModel.isStale {
                        HStack(alignment: .top, spacing: Spacing.extraSmall) {
                            Image(systemName: "exclamationmark.triangle.fill")
                                .foregroundColor(.accentRed300)
                                .font(.system(size: 14))
                            Text("Challenge is \(viewModel.ageMinutes) minutes old. It may have expired.")
                                .font(PrimaryFont.captionM.font)
                                .foregroundColor(.textAndIconsPrimary)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(Spacing.small)
                        .background(Color.accentRed300.opacity(0.12))
                        .cornerRadius(CornerRadius.medium)
                    }
                }
                .padding(.horizontal, Spacing.medium)
                .padding(.top, Spacing.medium)
            }

            Divider()
            VStack(spacing: Spacing.small) {
                ActionButton(action: viewModel.onApprove, text: "Approve", style: .primary())
                ActionButton(action: viewModel.onDismiss, text: "Decline", style: .emptyPrimary())
            }
            .padding(.horizontal, Spacing.large)
            .padding(.vertical, Spacing.medium)
        }
    }

    private var progressView: some View {
        VStack { Spacer(); ProgressView(); Text("Signing...").font(PrimaryFont.titleS.font).foregroundColor(.textAndIconsPrimary).padding(.top, Spacing.medium); Spacer() }
    }

    private func responseView(json: String) -> some View {
        VStack(spacing: 0) {
            Text("Show this to \(viewModel.domain)")
                .font(PrimaryFont.labelM.font)
                .foregroundColor(.textAndIconsTertiary)
                .padding(.top, Spacing.medium)
            Spacer()
            if let qrImage = viewModel.encodeQR(json) {
                AnimatedQRCodeView(
                    viewModel: Binding<AnimatedQRCodeViewModel>.constant(.init(qrCodes: [qrImage]))
                )
                .padding(Spacing.medium)
                .containerBackground()
                .padding(.horizontal, Spacing.medium)
            }
            Spacer()
            Divider()
            VStack(spacing: Spacing.small) {
                ActionButton(action: viewModel.onDismiss, text: "Done", style: .primary())
            }
            .padding(.horizontal, Spacing.large)
            .padding(.vertical, Spacing.medium)
        }
    }

    private func errorView(message: String) -> some View {
        VStack { Spacer(); Text("Error").font(PrimaryFont.titleS.font).foregroundColor(.accentRed300); Text(message).font(PrimaryFont.bodyL.font).foregroundColor(.textAndIconsSecondary).multilineTextAlignment(.center).padding(.horizontal, Spacing.large); Spacer(); ActionButton(action: viewModel.onDismiss, text: "Dismiss", style: .secondary()).padding(.horizontal, Spacing.large).padding(.bottom, Spacing.large) }
    }
}

extension AuthChallengeView {
    enum State {
        case review
        case signing
        case displayResponse(String)
        case error(String)
    }

    final class ViewModel: ObservableObject {
        @Published var state: State = .review
        @Published var pubkeyHex: String?

        let domain: String
        let nonce: String
        let timestamp: UInt64
        let index: UInt32
        private let seedPhrase: String
        private let onCompletion: () -> Void

        var isStale: Bool {
            let now = UInt64(Date().timeIntervalSince1970)
            return now > timestamp && (now - timestamp) > 300
        }

        var ageMinutes: Int {
            let now = UInt64(Date().timeIntervalSince1970)
            guard now > timestamp else { return 0 }
            return Int((now - timestamp) / 60)
        }

        init(
            domain: String,
            nonce: String,
            timestamp: UInt64,
            seedPhrase: String,
            index: UInt32 = 0,
            onCompletion: @escaping () -> Void
        ) {
            self.domain = domain
            self.nonce = nonce
            self.timestamp = timestamp
            self.seedPhrase = seedPhrase
            self.index = index
            self.onCompletion = onCompletion
            deriveIdentity()
        }

        private func deriveIdentity() {
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { return }
                let pubkey = try? authDeriveIdentity(seedPhrase: self.seedPhrase, index: self.index)
                DispatchQueue.main.async { self.pubkeyHex = pubkey }
            }
        }

        func onApprove() {
            state = .signing
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { return }
                do {
                    let result = try authSignChallenge(
                        seedPhrase: self.seedPhrase,
                        index: self.index,
                        domain: self.domain,
                        nonce: self.nonce,
                        timestamp: self.timestamp
                    )
                    let responseDict: [String: Any] = [
                        "auth": "response",
                        "pubkey": result.pubkeyHex,
                        "sig": result.signatureHex,
                        "domain": result.domain,
                    ]
                    let jsonData = try JSONSerialization.data(withJSONObject: responseDict)
                    let json = String(data: jsonData, encoding: .utf8) ?? "{}"
                    DispatchQueue.main.async { self.state = .displayResponse(json) }
                } catch {
                    DispatchQueue.main.async { self.state = .error(error.localizedDescription) }
                }
            }
        }

        func encodeQR(_ text: String) -> [UInt8]? {
            let bytes = Array(text.utf8).map { UInt8($0) }
            return try? encodeToQr(payload: bytes, isDanger: false)
        }

        func onDismiss() { onCompletion() }
    }
}
