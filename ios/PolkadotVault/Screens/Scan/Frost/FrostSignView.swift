//
//  FrostSignView.swift
//  Zigner
//

import SwiftUI

struct FrostSignView: View {
    @StateObject var viewModel: ViewModel
    @Environment(\.presentationMode) var presentationMode

    var body: some View {
        VStack(spacing: 0) {
            NavigationBarView(
                viewModel: .init(
                    title: .title("FROST Sign"),
                    leftButtons: [.init(type: .xmark, action: viewModel.onDismiss)],
                    rightButtons: [.init(type: .empty)],
                    backgroundColor: .backgroundPrimary
                )
            )
            switch viewModel.state {
            case .loading:
                progressView(message: "Loading wallet...")
            case .generatingCommitments:
                progressView(message: "Generating commitments...")
            case let .displayCommitments(qrData):
                qrDisplayView(
                    title: "Show commitment to coordinator",
                    subtitle: "After coordinator collects all commitments, scan the sign request QR",
                    qrData: qrData
                )
            case .signing:
                progressView(message: "Signing...")
            case let .displayShares(qrData):
                qrDisplayView(
                    title: "Show signature share to coordinator",
                    subtitle: "Coordinator will aggregate all shares to complete the transaction",
                    qrData: qrData
                )
            case let .error(message):
                errorView(message: message)
            }
        }
        .background(.backgroundPrimary)
    }

    private func progressView(message: String) -> some View {
        VStack {
            Spacer()
            ProgressView()
            Text(message)
                .font(PrimaryFont.titleS.font)
                .foregroundColor(.textAndIconsPrimary)
                .padding(.top, Spacing.medium)
            Spacer()
        }
    }

    private func qrDisplayView(title: String, subtitle: String, qrData: String) -> some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(spacing: Spacing.medium) {
                    Text(title)
                        .font(PrimaryFont.labelM.font)
                        .foregroundColor(.textAndIconsTertiary)
                    if let qrImage = viewModel.encodeQR(qrData) {
                        AnimatedQRCodeView(
                            viewModel: Binding<AnimatedQRCodeViewModel>.constant(
                                .init(qrCodes: [qrImage])
                            )
                        )
                        .padding(Spacing.stroke)
                        .containerBackground()
                    }
                    Text(subtitle)
                        .font(PrimaryFont.captionM.font)
                        .foregroundColor(.textAndIconsTertiary)
                        .multilineTextAlignment(.center)
                }
                .padding(.horizontal, Spacing.medium)
                .padding(.top, Spacing.medium)
            }
            Divider()
            VStack(spacing: Spacing.small) {
                ActionButton(
                    action: viewModel.onDismiss,
                    text: "Done",
                    style: .primary()
                )
            }
            .padding(.horizontal, Spacing.large)
            .padding(.vertical, Spacing.medium)
        }
    }

    private func errorView(message: String) -> some View {
        VStack {
            Spacer()
            Text("Signing Failed")
                .font(PrimaryFont.titleS.font)
                .foregroundColor(.accentRed300)
            Text(message)
                .font(PrimaryFont.bodyL.font)
                .foregroundColor(.textAndIconsSecondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, Spacing.large)
            Spacer()
            ActionButton(
                action: viewModel.onDismiss,
                text: "Dismiss",
                style: .secondary()
            )
            .padding(.horizontal, Spacing.large)
            .padding(.bottom, Spacing.large)
        }
    }
}

extension FrostSignView {
    enum State {
        case loading
        case generatingCommitments
        case displayCommitments(String)
        case signing
        case displayShares(String)
        case error(String)
    }

    final class ViewModel: ObservableObject {
        @Published var state: State = .loading
        let walletId: String
        private let onCompletion: () -> Void

        // Held in memory between round 1 and round 2
        private var noncesHex: String = ""
        private var keyPackageHex: String = ""

        /// Round 1: generate commitments
        init(
            walletId: String,
            onCompletion: @escaping () -> Void
        ) {
            self.walletId = walletId
            self.onCompletion = onCompletion
            generateCommitments()
        }

        private func generateCommitments() {
            state = .loading
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { return }
                do {
                    let walletJson = try frostLoadWallet(walletId: self.walletId)
                    let wallet = try JSONSerialization.jsonObject(with: Data(walletJson.utf8)) as? [String: Any]
                    let keyPackage = wallet?["key_package"] as? String ?? ""
                    let ephemeralSeed = wallet?["ephemeral_seed"] as? String ?? ""

                    DispatchQueue.main.async { self.state = .generatingCommitments }

                    let result = try frostSignRound1(
                        ephemeralSeedHex: ephemeralSeed,
                        keyPackageHex: keyPackage
                    )
                    let json = try JSONSerialization.jsonObject(with: Data(result.utf8)) as? [String: Any]
                    let nonces = json?["nonces"] as? String ?? ""
                    let commitments = json?["commitments"] as? String ?? ""

                    DispatchQueue.main.async {
                        self.noncesHex = nonces
                        self.keyPackageHex = keyPackage
                        self.state = .displayCommitments(commitments)
                    }
                } catch {
                    DispatchQueue.main.async {
                        self.state = .error(error.localizedDescription)
                    }
                }
            }
        }

        /// Round 2: sign with sighash + alphas + all commitments
        func sign(sighashHex: String, alphasJson: String, commitmentsJson: String) {
            state = .signing
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { return }
                do {
                    let result = try frostSpendSignActions(
                        keyPackageHex: self.keyPackageHex,
                        noncesHex: self.noncesHex,
                        sighashHex: sighashHex,
                        alphasJson: alphasJson,
                        commitmentsJson: commitmentsJson
                    )
                    DispatchQueue.main.async {
                        self.noncesHex = "" // clear after use
                        self.state = .displayShares(result)
                    }
                } catch {
                    DispatchQueue.main.async {
                        self.state = .error(error.localizedDescription)
                    }
                }
            }
        }

        func encodeQR(_ text: String) -> [UInt8]? {
            let bytes = Array(text.utf8).map { UInt8($0) }
            return try? encodeToQr(payload: bytes, isDanger: false)
        }

        func onDismiss() {
            noncesHex = ""
            keyPackageHex = ""
            onCompletion()
        }
    }
}
