//
//  CosmosAccountExportView.swift
//  Zigner
//

import SwiftUI

struct CosmosAccountExportView: View {
    @StateObject var viewModel: ViewModel
    @Environment(\.presentationMode) var presentationMode

    var body: some View {
        VStack(spacing: 0) {
            NavigationBarView(
                viewModel: .init(
                    title: .title("Export Cosmos Accounts"),
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
            case let .result(export):
                resultView(export: export)
            case let .error(message):
                errorView(message: message)
            }
        }
        .background(.backgroundPrimary)
    }

    private var seedSelectionView: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Select a wallet to export Cosmos chain addresses (Osmosis, Noble, Celestia):")
                .font(PrimaryFont.bodyL.font)
                .foregroundColor(.textAndIconsSecondary)
                .padding(.horizontal, Spacing.large)
                .padding(.vertical, Spacing.medium)
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(viewModel.seedNames, id: \.self) { seedName in
                        Button(action: { viewModel.exportAccounts(seedName: seedName) }) {
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
            Text("These addresses allow receiving funds on Cosmos chains. The same key is used for Osmosis, Noble, and Celestia.")
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
            Text("Generating addresses...")
                .font(PrimaryFont.titleS.font)
                .foregroundColor(.textAndIconsPrimary)
                .padding(.top, Spacing.medium)
            Spacer()
        }
    }

    private func resultView(export: CosmosExportResult) -> some View {
        ScrollView {
            VStack(alignment: .center, spacing: Spacing.medium) {
                AnimatedQRCodeView(
                    viewModel: .constant(.init(qrCodes: [export.qrData]))
                )

                Text("Scan with Zafu to import")
                    .font(PrimaryFont.titleS.font)
                    .foregroundColor(.textAndIconsPrimary)

                ForEach(export.addresses, id: \.chainId) { addr in
                    VStack(alignment: .leading, spacing: Spacing.extraSmall) {
                        Text(addr.chainId.capitalized)
                            .font(PrimaryFont.labelM.font)
                            .foregroundColor(.textAndIconsTertiary)
                        Text(addr.address)
                            .font(PrimaryFont.captionM.font)
                            .foregroundColor(.textAndIconsSecondary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(Spacing.small)
                    .containerBackground()
                }

                Text("These addresses share the same private key. Import into Zafu to manage Osmosis, Noble, and Celestia assets.")
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

struct CosmosAddressResult: Identifiable {
    var id: String { chainId }
    let chainId: String
    let address: String
    let prefix: String
}

struct CosmosExportResult {
    let publicKeyHex: String
    let addresses: [CosmosAddressResult]
    let qrData: [UInt8]
}

extension CosmosAccountExportView {
    enum State {
        case seedSelection
        case loading
        case result(CosmosExportResult)
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

        func exportAccounts(seedName: String) {
            state = .loading
            let seedPhrase = seedsMediator.getSeed(seedName: seedName)
            guard !seedPhrase.isEmpty else {
                state = .error("Failed to retrieve seed phrase")
                return
            }
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                do {
                    let export = try exportCosmosAccounts(
                        seedPhrase: seedPhrase,
                        accountIndex: 0,
                        label: seedName,
                        networkName: ""
                    )
                    let addresses = export.addresses.map { addr in
                        CosmosAddressResult(
                            chainId: addr.chainId,
                            address: addr.address,
                            prefix: addr.prefix
                        )
                    }
                    let result = CosmosExportResult(
                        publicKeyHex: export.publicKeyHex,
                        addresses: addresses,
                        qrData: export.qrData
                    )
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
    }
}
