//
//  ZcashPcztView.swift
//  Zigner
//
//  PCZT signing with full transaction inspection.
//  Shows spend/output breakdown, anchor verification, known spend status.

import SwiftUI

struct ZcashPcztView: View {
    @StateObject var viewModel: ViewModel
    @Environment(\.presentationMode) var presentationMode

    var body: some View {
        VStack(spacing: 0) {
            NavigationBarView(
                viewModel: .init(
                    title: .title("Zcash Transaction (PCZT)"),
                    leftButtons: [.init(type: .xmark, action: viewModel.onDismiss)],
                    rightButtons: [.init(type: .empty)],
                    backgroundColor: .backgroundPrimary
                )
            )
            switch viewModel.state {
            case .inspecting:
                progressView(message: "Inspecting transaction...")
            case let .review(inspection):
                reviewView(inspection: inspection)
            case .signing:
                progressView(message: "Signing...")
            case let .displaySignature(partCount):
                signatureView(partCount: partCount)
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

    private func reviewView(inspection: ZcashPcztInspection) -> some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: Spacing.small) {
                    // Anchor status
                    verificationCard(inspection: inspection)

                    // Spends
                    if !inspection.spends.isEmpty {
                        sectionCard(title: "Spending") {
                            ForEach(Array(inspection.spends.enumerated()), id: \.offset) { _, spend in
                                HStack {
                                    if spend.value > 0 {
                                        let zec = Double(spend.value) / 100_000_000.0
                                        Text(String(format: "%.8f ZEC", zec))
                                            .font(PrimaryFont.bodyL.font)
                                            .foregroundColor(.textAndIconsPrimary)
                                    } else {
                                        Text("redacted")
                                            .font(PrimaryFont.bodyL.font)
                                            .foregroundColor(.textAndIconsTertiary)
                                    }
                                    Spacer()
                                    Text(spend.known ? "verified" : "UNKNOWN")
                                        .font(PrimaryFont.labelM.font)
                                        .foregroundColor(spend.known ? .textAndIconsPrimary : .accentRed300)
                                }
                            }
                        }
                    }

                    // Outputs
                    if !inspection.outputs.isEmpty {
                        sectionCard(title: "Outputs") {
                            ForEach(Array(inspection.outputs.enumerated()), id: \.offset) { _, output in
                                VStack(alignment: .leading, spacing: 2) {
                                    let zec = Double(output.value) / 100_000_000.0
                                    Text(String(format: "%.8f ZEC", zec))
                                        .font(PrimaryFont.bodyL.font)
                                        .foregroundColor(.textAndIconsPrimary)
                                    if !output.recipient.isEmpty {
                                        Text(String(output.recipient.prefix(20)) + "..." + String(output.recipient.suffix(8)))
                                            .font(PrimaryFont.captionM.font)
                                            .foregroundColor(.textAndIconsTertiary)
                                    }
                                }
                            }
                        }
                    }

                    // Fee
                    sectionCard(title: "Fee") {
                        let feeZec = Double(inspection.feeZat) / 100_000_000.0
                        Text(String(format: "%.8f ZEC", feeZec))
                            .font(PrimaryFont.bodyL.font)
                            .foregroundColor(.textAndIconsPrimary)
                    }

                    // Warnings
                    if inspection.knownSpends < inspection.actionCount {
                        warningCard("\(inspection.actionCount - inspection.knownSpends) spend(s) not in verified notes.")
                    }
                    if inspection.verifiedBalance == 0 {
                        warningCard("No verified balance. Sync notes first (zcli export-notes).")
                    }
                }
                .padding(.horizontal, Spacing.medium)
                .padding(.top, Spacing.medium)
            }

            Divider()
            VStack(spacing: Spacing.small) {
                ActionButton(
                    action: viewModel.onApprove,
                    text: "Approve & Sign",
                    style: .primary()
                )
                ActionButton(
                    action: viewModel.onDismiss,
                    text: "Decline",
                    style: .emptyPrimary()
                )
            }
            .padding(.horizontal, Spacing.large)
            .padding(.vertical, Spacing.medium)
        }
    }

    private func signatureView(partCount: Int) -> some View {
        VStack(spacing: 0) {
            Spacer()
            Text("Signed")
                .font(PrimaryFont.titleS.font)
                .foregroundColor(.textAndIconsPrimary)
            Text("\(partCount) UR part(s) ready for coordinator")
                .font(PrimaryFont.bodyL.font)
                .foregroundColor(.textAndIconsSecondary)
                .padding(.top, Spacing.small)
            Spacer()
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
            Text("Error")
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

    // MARK: - Card Components

    private func verificationCard(inspection: ZcashPcztInspection) -> some View {
        VStack(alignment: .leading, spacing: Spacing.extraSmall) {
            Text("\(inspection.knownSpends)/\(inspection.actionCount) spends verified")
                .font(PrimaryFont.captionM.font)
                .foregroundColor(inspection.knownSpends == inspection.actionCount ? .textAndIconsSecondary : .accentRed300)
            let balZec = Double(inspection.verifiedBalance) / 100_000_000.0
            Text(String(format: "Verified balance: %.8f ZEC", balZec))
                .font(PrimaryFont.captionM.font)
                .foregroundColor(.textAndIconsSecondary)
}
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(Spacing.medium)
        .containerBackground()
    }

    private func sectionCard<Content: View>(title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: Spacing.small) {
            Text(title)
                .font(PrimaryFont.labelM.font)
                .foregroundColor(.textAndIconsTertiary)
            content()
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(Spacing.medium)
        .containerBackground()
    }

    private func warningCard(_ message: String) -> some View {
        HStack(alignment: .top, spacing: Spacing.extraSmall) {
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundColor(.accentRed300)
                .font(.system(size: 14))
            Text(message)
                .font(PrimaryFont.captionM.font)
                .foregroundColor(.textAndIconsPrimary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(Spacing.small)
        .background(Color.accentRed300.opacity(0.12))
        .cornerRadius(CornerRadius.medium)
    }
}

// MARK: - ViewModel

extension ZcashPcztView {
    enum State {
        case inspecting
        case review(ZcashPcztInspection)
        case signing
        case displaySignature(Int)
        case error(String)
    }

    final class ViewModel: ObservableObject {
        @Published var state: State = .inspecting
        private let urParts: [String]
        private let seedsMediator: SeedsMediating
        private let onCompletion: () -> Void
        private var pcztBytes: [UInt8] = []

        init(
            urParts: [String],
            seedsMediator: SeedsMediating = ServiceLocator.seedsMediator,
            onCompletion: @escaping () -> Void
        ) {
            self.urParts = urParts
            self.seedsMediator = seedsMediator
            self.onCompletion = onCompletion
            inspect()
        }

        private func inspect() {
            state = .inspecting
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { return }
                do {
                    let bytes = try decodeUrZcashPczt(urParts: self.urParts)
                    let inspection = try inspectZcashPczt(pcztBytes: bytes)
                    DispatchQueue.main.async {
                        self.pcztBytes = bytes
                        self.state = .review(inspection)
                    }
                } catch {
                    DispatchQueue.main.async {
                        self.state = .error(error.localizedDescription)
                    }
                }
            }
        }

        func onApprove() {
            guard let seedName = seedsMediator.seedNames.first else {
                state = .error("No seed phrase available")
                return
            }
            let seedPhrase = seedsMediator.getSeed(seedName: seedName)
            guard !seedPhrase.isEmpty else {
                state = .error("Failed to retrieve seed phrase")
                return
            }

            state = .signing
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { return }
                do {
                    let signedParts = try signZcashPcztUr(
                        seedPhrase: seedPhrase,
                        accountIndex: 0,
                        urParts: self.urParts,
                        maxFragmentLen: 200
                    )
                    DispatchQueue.main.async {
                        self.state = .displaySignature(signedParts.count)
                    }
                } catch {
                    DispatchQueue.main.async {
                        self.state = .error(error.localizedDescription)
                    }
                }
            }
        }

        func onDismiss() {
            onCompletion()
        }
    }
}
