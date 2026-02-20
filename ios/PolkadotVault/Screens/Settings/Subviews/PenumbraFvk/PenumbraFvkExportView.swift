//
//  PenumbraFvkExportView.swift
//  Zigner
//

import SwiftUI

struct PenumbraFvkExportView: View {
    @StateObject var viewModel: ViewModel
    @Environment(\.presentationMode) var presentationMode

    var body: some View {
        VStack(spacing: 0) {
            NavigationBarView(
                viewModel: .init(
                    title: .title("Export Penumbra FVK"),
                    leftButtons: [.init(type: .xmark, action: { presentationMode.wrappedValue.dismiss() })],
                    rightButtons: [.init(type: .empty)],
                    backgroundColor: .backgroundPrimary
                )
            )
            switch viewModel.state {
            case .seedSelection:
                seedSelectionView
            case .loading:
                loadingView
            case let .result(fvkBech32m, walletId, qrData):
                resultView(fvkBech32m: fvkBech32m, walletId: walletId, qrData: qrData)
            case let .error(message):
                errorView(message: message)
            }
        }
        .background(.backgroundPrimary)
    }

    private var seedSelectionView: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Select a wallet to export its Full Viewing Key for Prax:")
                .font(PrimaryFont.bodyL.font)
                .foregroundColor(.textAndIconsSecondary)
                .padding(.horizontal, Spacing.large)
                .padding(.vertical, Spacing.medium)
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(viewModel.seedNames, id: \.self) { seedName in
                        Button(action: { viewModel.exportFvk(seedName: seedName) }) {
                            HStack {
                                Text(seedName)
                                    .font(PrimaryFont.titleS.font)
                                    .foregroundColor(.textAndIconsPrimary)
                                Spacer()
                                Image(.chevronRight)
                                    .foregroundColor(.textAndIconsTertiary)
                            }
                            .padding(.horizontal, Spacing.large)
                            .padding(.vertical, Spacing.medium)
                        }
                    }
                }
            }
            Text("The FVK allows viewing your transaction history without spending ability. Safe to share with watch-only wallets.")
                .font(PrimaryFont.captionM.font)
                .foregroundColor(.textAndIconsTertiary)
                .padding(.horizontal, Spacing.large)
                .padding(.vertical, Spacing.medium)
        }
    }

    private var loadingView: some View {
        VStack {
            Spacer()
            ProgressView()
            Text("Exporting Full Viewing Key...")
                .font(PrimaryFont.titleS.font)
                .foregroundColor(.textAndIconsPrimary)
                .padding(.top, Spacing.medium)
            Spacer()
        }
    }

    private func resultView(fvkBech32m: String, walletId: String, qrData: [UInt8]) -> some View {
        ScrollView {
            VStack(alignment: .center, spacing: Spacing.medium) {
                AnimatedQRCodeView(
                    viewModel: .constant(.init(qrCodes: [qrData]))
                )

                Text("Scan with Prax to import")
                    .font(PrimaryFont.titleS.font)
                    .foregroundColor(.textAndIconsPrimary)

                VStack(alignment: .leading, spacing: Spacing.extraSmall) {
                    Text("Wallet ID")
                        .font(PrimaryFont.labelM.font)
                        .foregroundColor(.textAndIconsTertiary)
                    Text(String(walletId.prefix(24)) + "...")
                        .font(PrimaryFont.captionM.font)
                        .foregroundColor(.textAndIconsSecondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(Spacing.small)
                .containerBackground()

                VStack(alignment: .leading, spacing: Spacing.extraSmall) {
                    Text("Full Viewing Key")
                        .font(PrimaryFont.labelM.font)
                        .foregroundColor(.textAndIconsTertiary)
                    Text(String(fvkBech32m.prefix(32)) + "...")
                        .font(PrimaryFont.captionM.font)
                        .foregroundColor(.textAndIconsSecondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(Spacing.small)
                .containerBackground()

                Text("This key allows viewing your Penumbra transactions and balances. It cannot be used to spend funds.")
                    .font(PrimaryFont.captionM.font)
                    .foregroundColor(.textAndIconsTertiary)
                    .padding(.horizontal, Spacing.small)
            }
            .padding(.horizontal, Spacing.medium)
        }
    }

    private func errorView(message: String) -> some View {
        VStack {
            Spacer()
            Text("Export Failed")
                .font(PrimaryFont.titleS.font)
                .foregroundColor(.accentRed300)
            Text(message)
                .font(PrimaryFont.bodyL.font)
                .foregroundColor(.textAndIconsSecondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, Spacing.large)
            Spacer()
            ActionButton(
                action: { viewModel.state = .seedSelection },
                text: "Try Again",
                style: .primary()
            )
            .padding(.horizontal, Spacing.large)
            .padding(.bottom, Spacing.large)
        }
    }
}

extension PenumbraFvkExportView {
    enum State {
        case seedSelection
        case loading
        case result(fvkBech32m: String, walletId: String, qrData: [UInt8])
        case error(String)
    }

    final class ViewModel: ObservableObject {
        @Published var state: State = .seedSelection
        @Published var seedNames: [String] = []

        private let seedsMediator: SeedsMediating

        init(seedsMediator: SeedsMediating = ServiceLocator.seedsMediator) {
            self.seedsMediator = seedsMediator
            self.seedNames = seedsMediator.seedNames
        }

        func exportFvk(seedName: String) {
            state = .loading
            let seedPhrase = seedsMediator.getSeed(seedName: seedName)
            guard !seedPhrase.isEmpty else {
                state = .error("Failed to retrieve seed phrase")
                return
            }
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                do {
                    let export = try exportPenumbraFvk(
                        seedPhrase: seedPhrase,
                        accountIndex: 0,
                        label: seedName
                    )
                    let urBytes = Array(export.urString.utf8)
                    let qrPng = try encodeToQr(payload: urBytes, isDanger: false)
                    DispatchQueue.main.async {
                        self?.state = .result(
                            fvkBech32m: export.fvkBech32m,
                            walletId: export.walletIdBech32m,
                            qrData: qrPng
                        )
                    }
                } catch {
                    DispatchQueue.main.async {
                        self?.state = .error(error.localizedDescription)
                    }
                }
            }
        }
    }
}
