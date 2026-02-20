//
//  ZcashFvkExportView.swift
//  Zigner
//

import SwiftUI

struct ZcashFvkExportView: View {
    @StateObject var viewModel: ViewModel
    @Environment(\.presentationMode) var presentationMode

    var body: some View {
        VStack(spacing: 0) {
            NavigationBarView(
                viewModel: .init(
                    title: .title("Export Zcash FVK"),
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
            case let .result(address, fvkHex, isMainnet, qrData):
                resultView(address: address, fvkHex: fvkHex, isMainnet: isMainnet, qrData: qrData)
            case let .error(message):
                errorView(message: message)
            }
        }
        .background(.backgroundPrimary)
    }

    private var seedSelectionView: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Select a wallet to export its Orchard Full Viewing Key:")
                .font(PrimaryFont.bodyL.font)
                .foregroundColor(.textAndIconsSecondary)
                .padding(.horizontal, Spacing.large)
                .padding(.vertical, Spacing.medium)

            // Network toggle
            HStack {
                Text("Network:")
                    .font(PrimaryFont.labelM.font)
                    .foregroundColor(.textAndIconsSecondary)
                Spacer()
                Text(viewModel.isMainnet ? "Mainnet" : "Testnet")
                    .font(PrimaryFont.labelM.font)
                    .foregroundColor(.textAndIconsPrimary)
                Toggle("", isOn: $viewModel.isMainnet)
                    .labelsHidden()
            }
            .padding(.horizontal, Spacing.large)
            .padding(.vertical, Spacing.small)

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
            Text("The FVK allows viewing your Zcash Orchard transaction history without spending ability. Safe to share with watch-only wallets.")
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
            Text("Exporting Zcash Viewing Key...")
                .font(PrimaryFont.titleS.font)
                .foregroundColor(.textAndIconsPrimary)
                .padding(.top, Spacing.medium)
            Spacer()
        }
    }

    private func resultView(address: String, fvkHex: String, isMainnet: Bool, qrData: [UInt8]) -> some View {
        ScrollView {
            VStack(alignment: .center, spacing: Spacing.medium) {
                // Network badge
                Text(isMainnet ? "Mainnet" : "Testnet")
                    .font(PrimaryFont.labelM.font)
                    .foregroundColor(isMainnet ? .accentGreen300 : .accentRed300)
                    .padding(.horizontal, Spacing.small)
                    .padding(.vertical, Spacing.extraSmall)
                    .containerBackground()

                AnimatedQRCodeView(
                    viewModel: .constant(.init(qrCodes: [qrData]))
                )

                Text("Scan with Zafu / Zashi / Keystone")
                    .font(PrimaryFont.titleS.font)
                    .foregroundColor(.textAndIconsPrimary)

                // Unified Address
                VStack(alignment: .leading, spacing: Spacing.extraSmall) {
                    Text("Unified Address")
                        .font(PrimaryFont.labelM.font)
                        .foregroundColor(.textAndIconsTertiary)
                    Text(String(address.prefix(24)) + "...")
                        .font(PrimaryFont.captionM.font)
                        .foregroundColor(.textAndIconsSecondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(Spacing.small)
                .containerBackground()

                // Orchard FVK
                VStack(alignment: .leading, spacing: Spacing.extraSmall) {
                    Text("Orchard FVK")
                        .font(PrimaryFont.labelM.font)
                        .foregroundColor(.textAndIconsTertiary)
                    Text(String(fvkHex.prefix(32)) + "...")
                        .font(PrimaryFont.captionM.font)
                        .foregroundColor(.textAndIconsSecondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(Spacing.small)
                .containerBackground()

                Text("This key allows viewing your Zcash Orchard transactions and balances. It cannot be used to spend funds.")
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

extension ZcashFvkExportView {
    enum State {
        case seedSelection
        case loading
        case result(address: String, fvkHex: String, isMainnet: Bool, qrData: [UInt8])
        case error(String)
    }

    final class ViewModel: ObservableObject {
        @Published var state: State = .seedSelection
        @Published var seedNames: [String] = []
        @Published var isMainnet: Bool = true

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
            let mainnet = isMainnet
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                do {
                    let export = try exportZcashFvk(
                        seedPhrase: seedPhrase,
                        accountIndex: 0,
                        label: seedName,
                        mainnet: mainnet
                    )
                    // Encode UR string as QR code data
                    let urBytes = Array(export.urString.utf8)
                    let qrPng = try encodeToQr(payload: urBytes, isDanger: false)
                    DispatchQueue.main.async {
                        self?.state = .result(
                            address: export.address,
                            fvkHex: export.fvkHex,
                            isMainnet: export.mainnet,
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
