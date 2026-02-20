//
//  ZcashTransactionView.swift
//  Zigner
//

import SwiftUI

struct ZcashTransactionView: View {
    @StateObject var viewModel: ViewModel
    @Environment(\.presentationMode) var presentationMode

    var body: some View {
        VStack(spacing: 0) {
            NavigationBarView(
                viewModel: .init(
                    title: .title("Zcash Transaction"),
                    leftButtons: [.init(type: .xmark, action: viewModel.onDecline)],
                    rightButtons: [.init(type: .empty)],
                    backgroundColor: .backgroundPrimary
                )
            )
            switch viewModel.state {
            case .review:
                reviewView
            case .signing:
                signingView
            case let .signature(bytes):
                ZcashSignatureQrView(
                    signatureBytes: bytes,
                    onDone: viewModel.onDone
                )
            case let .error(message):
                errorView(message: message)
            }
        }
        .background(.backgroundPrimary)
    }

    private var reviewView: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: Spacing.small) {
                    // Summary card
                    if let request = viewModel.request {
                        summaryCard(request: request)

                        // Action cards
                        ForEach(Array(request.alphas.enumerated()), id: \.offset) { index, _ in
                            actionCard(index: index)
                        }

                        // Wallet summary text
                        if !request.summary.isEmpty {
                            VStack(alignment: .leading, spacing: Spacing.small) {
                                Text("Transaction Summary")
                                    .font(PrimaryFont.titleS.font)
                                    .foregroundColor(.textAndIconsPrimary)
                                Text(request.summary)
                                    .font(PrimaryFont.bodyL.font)
                                    .foregroundColor(.textAndIconsSecondary)
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(Spacing.medium)
                            .containerBackground()
                        }

                        // Account info
                        VStack(alignment: .leading, spacing: Spacing.extraSmall) {
                            Text("Account #\(request.accountIndex)")
                                .font(PrimaryFont.labelM.font)
                                .foregroundColor(.textAndIconsTertiary)
                            Text("\(request.alphas.count) signature\(request.alphas.count == 1 ? "" : "s") required")
                                .font(PrimaryFont.captionM.font)
                                .foregroundColor(.textAndIconsSecondary)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(Spacing.small)
                        .containerBackground()
                    }
                }
                .padding(.horizontal, Spacing.medium)
                .padding(.top, Spacing.medium)
            }

            Divider()
            VStack(spacing: Spacing.small) {
                ActionButton(
                    action: viewModel.onApprove,
                    text: "Approve",
                    style: .primary()
                )
                ActionButton(
                    action: viewModel.onDecline,
                    text: "Decline",
                    style: .emptyPrimary()
                )
            }
            .padding(.horizontal, Spacing.large)
            .padding(.vertical, Spacing.medium)
        }
    }

    private func summaryCard(request: ZcashSignRequest) -> some View {
        VStack(alignment: .leading, spacing: Spacing.small) {
            HStack(spacing: Spacing.small) {
                Text("Zcash Transaction")
                    .font(PrimaryFont.titleS.font)
                    .foregroundColor(.textAndIconsPrimary)
                Text(request.mainnet ? "Mainnet" : "Testnet")
                    .font(PrimaryFont.labelM.font)
                    .foregroundColor(request.mainnet ? .accentGreen300 : .accentRed300)
                    .padding(.horizontal, Spacing.extraSmall)
                    .padding(.vertical, 2)
                    .containerBackground()
            }

            HStack(spacing: Spacing.small) {
                Text("Actions:")
                    .font(PrimaryFont.bodyL.font)
                    .foregroundColor(.textAndIconsTertiary)
                Text("\(request.alphas.count) Orchard action\(request.alphas.count == 1 ? "" : "s")")
                    .font(PrimaryFont.bodyL.font)
                    .foregroundColor(.textAndIconsPrimary)
            }

            VStack(alignment: .leading, spacing: Spacing.extraSmall) {
                Text("Sighash:")
                    .font(PrimaryFont.bodyL.font)
                    .foregroundColor(.textAndIconsTertiary)
                Text(String(request.sighash.prefix(32)) + "...")
                    .font(PrimaryFont.captionM.font)
                    .foregroundColor(.textAndIconsSecondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(Spacing.medium)
        .containerBackground()
    }

    private func actionCard(index: Int) -> some View {
        VStack(alignment: .leading, spacing: Spacing.extraSmall) {
            Text("Orchard Action")
                .font(PrimaryFont.labelM.font)
                .foregroundColor(.accentPink300)
            Text("Action #\(index + 1)")
                .font(PrimaryFont.bodyL.font)
                .foregroundColor(.textAndIconsPrimary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(Spacing.small)
        .containerBackground()
    }

    private var signingView: some View {
        VStack {
            Spacer()
            ProgressView()
            Text("Signing transaction...")
                .font(PrimaryFont.titleS.font)
                .foregroundColor(.textAndIconsPrimary)
                .padding(.top, Spacing.medium)
            Spacer()
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
                action: viewModel.onDecline,
                text: "Dismiss",
                style: .secondary()
            )
            .padding(.horizontal, Spacing.large)
            .padding(.bottom, Spacing.large)
        }
    }
}

extension ZcashTransactionView {
    enum State {
        case review
        case signing
        case signature([UInt8])
        case error(String)
    }

    final class ViewModel: ObservableObject {
        @Published var state: State = .review
        var request: ZcashSignRequest?
        private let seedsMediator: SeedsMediating
        private let onCompletion: () -> Void

        init(
            qrHex: String,
            seedsMediator: SeedsMediating = ServiceLocator.seedsMediator,
            onCompletion: @escaping () -> Void
        ) {
            self.seedsMediator = seedsMediator
            self.onCompletion = onCompletion
            do {
                self.request = try parseZcashSignRequest(qrHex: qrHex)
            } catch {
                self.state = .error(error.localizedDescription)
            }
        }

        func onApprove() {
            guard let request else { return }
            state = .signing
            let seeds = seedsMediator.getAllSeeds()
            guard let seedPhrase = seeds.values.first, !seedPhrase.isEmpty else {
                state = .error("No seed phrase available")
                return
            }
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                do {
                    let response = try signZcashTransaction(
                        seedPhrase: seedPhrase,
                        request: request
                    )
                    let signatureQr = try encodeZcashSignatureQr(response: response)
                    DispatchQueue.main.async {
                        self?.state = .signature(signatureQr)
                    }
                } catch {
                    DispatchQueue.main.async {
                        self?.state = .error(error.localizedDescription)
                    }
                }
            }
        }

        func onDecline() {
            onCompletion()
        }

        func onDone() {
            onCompletion()
        }
    }
}
