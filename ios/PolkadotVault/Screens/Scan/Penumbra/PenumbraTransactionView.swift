//
//  PenumbraTransactionView.swift
//  Zigner
//

import SwiftUI

struct PenumbraTransactionView: View {
    @StateObject var viewModel: ViewModel
    @Environment(\.presentationMode) var presentationMode

    var body: some View {
        VStack(spacing: 0) {
            NavigationBarView(
                viewModel: .init(
                    title: .title("Penumbra Transaction"),
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
                PenumbraSignatureQrView(
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
                    // Chain ID
                    infoCard(label: "Chain", value: viewModel.request?.chainId ?? "Unknown")

                    // Effect hash
                    infoCard(
                        label: "Effect Hash",
                        value: {
                            let hash = viewModel.request?.effectHashHex ?? ""
                            if hash.count > 16 {
                                return String(hash.prefix(8)) + "..." + String(hash.suffix(8))
                            }
                            return hash.isEmpty ? "N/A" : hash
                        }()
                    )

                    // Actions summary
                    actionsCard
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

    private var actionsCard: some View {
        VStack(alignment: .leading, spacing: Spacing.small) {
            Text("Actions")
                .font(PrimaryFont.titleS.font)
                .foregroundColor(.textAndIconsPrimary)

            if let request = viewModel.request {
                if request.spendCount > 0 {
                    Text("\(request.spendCount) Spend\(request.spendCount > 1 ? "s" : "")")
                        .font(PrimaryFont.bodyL.font)
                        .foregroundColor(.textAndIconsSecondary)
                }
                if request.voteCount > 0 {
                    Text("\(request.voteCount) Delegator Vote\(request.voteCount > 1 ? "s" : "")")
                        .font(PrimaryFont.bodyL.font)
                        .foregroundColor(.textAndIconsSecondary)
                }
                if request.lqtVoteCount > 0 {
                    Text("\(request.lqtVoteCount) LQT Vote\(request.lqtVoteCount > 1 ? "s" : "")")
                        .font(PrimaryFont.bodyL.font)
                        .foregroundColor(.textAndIconsSecondary)
                }
                let total = request.spendCount + request.voteCount + request.lqtVoteCount
                Text("\(total) signature\(total > 1 ? "s" : "") required")
                    .font(PrimaryFont.captionM.font)
                    .foregroundColor(.textAndIconsTertiary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(Spacing.medium)
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

    private func infoCard(label: String, value: String) -> some View {
        VStack(alignment: .leading, spacing: Spacing.extraSmall) {
            Text(label)
                .font(PrimaryFont.labelM.font)
                .foregroundColor(.textAndIconsTertiary)
            Text(value)
                .font(PrimaryFont.bodyL.font)
                .foregroundColor(.textAndIconsPrimary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(Spacing.small)
        .containerBackground()
    }
}

extension PenumbraTransactionView {
    enum State {
        case review
        case signing
        case signature([UInt8])
        case error(String)
    }

    final class ViewModel: ObservableObject {
        @Published var state: State = .review
        var request: PenumbraSignRequest?
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
                self.request = try parsePenumbraSignRequest(qrHex: qrHex)
            } catch {
                self.state = .error(error.localizedDescription)
            }
        }

        func onApprove() {
            guard let request else { return }
            state = .signing
            // Get seed phrase (uses first available seed - account 0)
            let seeds = seedsMediator.getAllSeeds()
            guard let seedPhrase = seeds.values.first, !seedPhrase.isEmpty else {
                state = .error("No seed phrase available")
                return
            }
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                do {
                    let signatureBytes = try signPenumbraTransaction(
                        seedPhrase: seedPhrase,
                        request: request
                    )
                    DispatchQueue.main.async {
                        self?.state = .signature(signatureBytes)
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
