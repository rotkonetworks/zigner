//
//  FrostDkgView.swift
//  Zigner
//

import SwiftUI

struct FrostDkgView: View {
    @StateObject var viewModel: ViewModel
    @Environment(\.presentationMode) var presentationMode

    var body: some View {
        VStack(spacing: 0) {
            NavigationBarView(
                viewModel: .init(
                    title: .title("FROST DKG"),
                    leftButtons: [.init(type: .xmark, action: viewModel.onDismiss)],
                    rightButtons: [.init(type: .empty)],
                    backgroundColor: .backgroundPrimary
                )
            )
            switch viewModel.state {
            case .computing(let round):
                computingView(round: round)
            case .displayBroadcast(let qrData):
                displayQrView(
                    title: "Round 1: Show to coordinator",
                    subtitle: "After coordinator collects all broadcasts, scan the round 2 QR",
                    qrData: qrData
                )
            case .displayPeerPackages(let qrData):
                displayQrView(
                    title: "Round 2: Show to coordinator",
                    subtitle: "After coordinator collects all packages, scan the round 3 QR",
                    qrData: qrData
                )
            case let .complete(walletId):
                completeView(walletId: walletId)
            case let .error(message):
                errorView(message: message)
            }
        }
        .background(.backgroundPrimary)
    }

    private func computingView(round: Int) -> some View {
        VStack {
            Spacer()
            ProgressView()
            Text("Computing round \(round)...")
                .font(PrimaryFont.titleS.font)
                .foregroundColor(.textAndIconsPrimary)
                .padding(.top, Spacing.medium)
            Spacer()
        }
    }

    private func displayQrView(title: String, subtitle: String, qrData: String) -> some View {
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

    private func completeView(walletId: String) -> some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: Spacing.small) {
                    VStack(alignment: .leading, spacing: Spacing.small) {
                        Text("DKG Complete")
                            .font(PrimaryFont.titleS.font)
                            .foregroundColor(.textAndIconsPrimary)
                        Text("Key share stored securely")
                            .font(PrimaryFont.bodyL.font)
                            .foregroundColor(.textAndIconsSecondary)
                        Text("Wallet: \(walletId)")
                            .font(PrimaryFont.captionM.font)
                            .foregroundColor(.textAndIconsTertiary)
                        Text("\(viewModel.minSigners)-of-\(viewModel.maxSigners) \(viewModel.mainnet ? "Mainnet" : "Testnet")")
                            .font(PrimaryFont.captionM.font)
                            .foregroundColor(.textAndIconsTertiary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(Spacing.medium)
                    .containerBackground()
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
            Text("DKG Failed")
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

extension FrostDkgView {
    enum State {
        case computing(Int)
        case displayBroadcast(String)
        case displayPeerPackages(String)
        case complete(String) // wallet_id
        case error(String)
    }

    final class ViewModel: ObservableObject {
        @Published var state: State = .computing(1)
        let minSigners: UInt16
        let maxSigners: UInt16
        let mainnet: Bool
        let label: String
        private let onCompletion: () -> Void

        // DKG state (held in memory only)
        private var round1Secret: String = ""
        private var round2Secret: String = ""

        init(
            maxSigners: UInt16,
            minSigners: UInt16,
            label: String = "",
            mainnet: Bool = true,
            onCompletion: @escaping () -> Void
        ) {
            self.maxSigners = maxSigners
            self.minSigners = minSigners
            self.label = label
            self.mainnet = mainnet
            self.onCompletion = onCompletion
            startRound1()
        }

        private func startRound1() {
            state = .computing(1)
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { return }
                do {
                    let result = try frostDkgPart1(
                        maxSigners: self.maxSigners,
                        minSigners: self.minSigners
                    )
                    let json = try JSONSerialization.jsonObject(with: Data(result.utf8)) as? [String: Any]
                    let secret = json?["secret"] as? String ?? ""
                    let broadcast = json?["broadcast"] as? String ?? ""
                    DispatchQueue.main.async {
                        self.round1Secret = secret
                        self.state = .displayBroadcast(broadcast)
                    }
                } catch {
                    DispatchQueue.main.async {
                        self.state = .error(error.localizedDescription)
                    }
                }
            }
        }

        /// Called when coordinator's round 2 QR is scanned
        func processRound2(broadcastsJson: String) {
            state = .computing(2)
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { return }
                do {
                    let result = try frostDkgPart2(
                        secretHex: self.round1Secret,
                        peerBroadcastsJson: broadcastsJson
                    )
                    let json = try JSONSerialization.jsonObject(with: Data(result.utf8)) as? [String: Any]
                    let secret = json?["secret"] as? String ?? ""
                    let peerPackages = json?["peer_packages"] as? [String] ?? []
                    let packagesJson = String(data: try JSONSerialization.data(withJSONObject: peerPackages), encoding: .utf8) ?? "[]"
                    DispatchQueue.main.async {
                        self.round1Secret = "" // clear round 1 secret
                        self.round2Secret = secret
                        self.state = .displayPeerPackages(packagesJson)
                    }
                } catch {
                    DispatchQueue.main.async {
                        self.state = .error(error.localizedDescription)
                    }
                }
            }
        }

        /// Called when coordinator's round 3 QR is scanned
        func processRound3(round1BroadcastsJson: String, round2PackagesJson: String) {
            state = .computing(3)
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { return }
                do {
                    let result = try frostDkgPart3(
                        secretHex: self.round2Secret,
                        round1BroadcastsJson: round1BroadcastsJson,
                        round2PackagesJson: round2PackagesJson
                    )
                    let json = try JSONSerialization.jsonObject(with: Data(result.utf8)) as? [String: Any]
                    let keyPackage = json?["key_package"] as? String ?? ""
                    let publicKeyPackage = json?["public_key_package"] as? String ?? ""
                    let ephemeralSeed = json?["ephemeral_seed"] as? String ?? ""

                    // Store wallet
                    let walletId = try frostStoreWallet(
                        keyPackageHex: keyPackage,
                        publicKeyPackageHex: publicKeyPackage,
                        ephemeralSeedHex: ephemeralSeed,
                        label: self.label,
                        minSigners: self.minSigners,
                        maxSigners: self.maxSigners,
                        mainnet: self.mainnet
                    )
                    DispatchQueue.main.async {
                        self.round2Secret = "" // clear
                        self.state = .complete(walletId)
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
            round1Secret = ""
            round2Secret = ""
            onCompletion()
        }
    }
}
