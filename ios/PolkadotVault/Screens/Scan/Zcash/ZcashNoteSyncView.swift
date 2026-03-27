//
//  ZcashNoteSyncView.swift
//  Zigner
//

import SwiftUI

struct ZcashNoteSyncView: View {
    @StateObject var viewModel: ViewModel
    @Environment(\.presentationMode) var presentationMode

    var body: some View {
        VStack(spacing: 0) {
            NavigationBarView(
                viewModel: .init(
                    title: .title("Zcash Note Sync"),
                    leftButtons: [.init(type: .xmark, action: viewModel.onDismiss)],
                    rightButtons: [.init(type: .empty)],
                    backgroundColor: .backgroundPrimary
                )
            )
            switch viewModel.state {
            case .scanning:
                scanningView
            case .verifying:
                verifyingView
            case let .result(syncResult):
                resultView(result: syncResult)
            case let .error(message):
                errorView(message: message)
            }
        }
        .background(.backgroundPrimary)
    }

    private var scanningView: some View {
        VStack {
            Spacer()
            Text("Scan zcash-notes QR from zcli")
                .font(PrimaryFont.bodyL.font)
                .foregroundColor(.textAndIconsSecondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, Spacing.large)
            Spacer()
        }
    }

    private var verifyingView: some View {
        VStack {
            Spacer()
            ProgressView()
            Text("Verifying merkle paths...")
                .font(PrimaryFont.titleS.font)
                .foregroundColor(.textAndIconsPrimary)
                .padding(.top, Spacing.medium)
            Spacer()
        }
    }

    private func resultView(result: ZcashNoteSyncResult) -> some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: Spacing.small) {
                    // Verified count
                    VStack(alignment: .leading, spacing: Spacing.small) {
                        Text("Verified")
                            .font(PrimaryFont.labelM.font)
                            .foregroundColor(.textAndIconsTertiary)
                        Text("\(result.notesVerified) note\(result.notesVerified == 1 ? "" : "s") verified")
                            .font(PrimaryFont.titleS.font)
                            .foregroundColor(.textAndIconsPrimary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(Spacing.medium)
                    .containerBackground()

                    // Balance
                    VStack(alignment: .leading, spacing: Spacing.small) {
                        Text("Verified Balance")
                            .font(PrimaryFont.labelM.font)
                            .foregroundColor(.textAndIconsTertiary)
                        Text(formatZec(zatoshis: result.totalBalance))
                            .font(PrimaryFont.titleL.font)
                            .foregroundColor(.textAndIconsPrimary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(Spacing.medium)
                    .containerBackground()

                    // Network & anchor
                    VStack(alignment: .leading, spacing: Spacing.extraSmall) {
                        Text(result.mainnet ? "Mainnet" : "Testnet")
                            .font(PrimaryFont.labelM.font)
                            .foregroundColor(.textAndIconsTertiary)
                        Text("Anchor height: \(result.anchorHeight)")
                            .font(PrimaryFont.captionM.font)
                            .foregroundColor(.textAndIconsSecondary)
                        Text("Anchor: \(String(result.anchorHex.prefix(16)))...")
                            .font(PrimaryFont.captionM.font)
                            .foregroundColor(.textAndIconsSecondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(Spacing.small)
                    .containerBackground()

                    // Anchor attestation status
                    VStack(alignment: .leading, spacing: Spacing.extraSmall) {
                        Text(result.anchorVerified
                            ? "Anchor: Attested by threshold group"
                            : "Anchor: From zcli (single-signer)")
                            .font(PrimaryFont.labelM.font)
                            .foregroundColor(result.anchorVerified
                                ? .textAndIconsPrimary
                                : .textAndIconsTertiary)
                        if !result.anchorVerified {
                            Text("No FROST wallet \u{2014} anchor trust relies on zcli. Set up a threshold wallet for independent verification.")
                                .font(PrimaryFont.captionM.font)
                                .foregroundColor(.textAndIconsTertiary)
                        }
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(Spacing.small)
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
            Text("Note Sync Failed")
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

    private func formatZec(zatoshis: UInt64) -> String {
        let zec = Double(zatoshis) / 100_000_000.0
        return String(format: "%.8f ZEC", zec)
    }
}

extension ZcashNoteSyncView {
    enum State {
        case scanning
        case verifying
        case result(ZcashNoteSyncResult)
        case error(String)
    }

    final class ViewModel: ObservableObject {
        @Published var state: State = .scanning
        private let onCompletion: () -> Void

        init(
            urFrames: [String],
            onCompletion: @escaping () -> Void
        ) {
            self.onCompletion = onCompletion
            verifyNotes(urFrames: urFrames)
        }

        private func verifyNotes(urFrames: [String]) {
            state = .verifying
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                do {
                    let result = try decodeAndVerifyZcashNotes(urParts: urFrames)
                    DispatchQueue.main.async {
                        self?.state = .result(result)
                    }
                } catch {
                    DispatchQueue.main.async {
                        self?.state = .error(error.localizedDescription)
                    }
                }
            }
        }

        func onDismiss() {
            onCompletion()
        }
    }
}
