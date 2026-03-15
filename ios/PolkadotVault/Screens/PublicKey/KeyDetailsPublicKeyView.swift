//
//  KeyDetailsPublicKeyView.swift
//  Polkadot Vault
//
//  Created by Krzysztof Rodak on 13/09/2022.
//

import Combine
import SwiftUI

struct KeyDetailsPublicKeyView: View {
    @StateObject var viewModel: ViewModel
    @Environment(\.presentationMode) var presentationMode

    var body: some View {
        GeometryReader { geo in
            VStack(spacing: 0) {
                // Navigation bar
                NavigationBarView(
                    viewModel: .init(
                        leftButtons: [.init(type: .arrow, action: { presentationMode.wrappedValue.dismiss() })],
                        rightButtons: [.init(type: .more, action: viewModel.onMoreButtonTap)]
                    )
                )
                ScrollView {
                    VStack(spacing: Spacing.medium) {
                        // Exposed key alert
                        if viewModel.renderable.isKeyExposed {
                            HStack(alignment: .center, spacing: 0) {
                                Localizable.KeyScreen.Label.hotkey.text
                                    .frame(maxWidth: .infinity, alignment: .leading)
                                    .font(PrimaryFont.labelXS.font)
                                    .foregroundColor(.textAndIconsPrimary)
                                Spacer().frame(maxWidth: Spacing.small)
                                Image(.exclamationRed)
                                    .foregroundColor(.accentRed300)
                            }
                            .padding(Spacing.medium)
                            .strokeContainerBackground(CornerRadius.small, state: .error)
                        }
                        // QR Code container
                        VStack(spacing: 0) {
                            if viewModel.isZcash && viewModel.isReceiveMode {
                                zcashReceiveQR()
                            } else {
                                AnimatedQRCodeView(
                                    viewModel: Binding<AnimatedQRCodeViewModel>.constant(
                                        .init(
                                            qrCodes: viewModel.renderable.qrCodes
                                        )
                                    )
                                )
                                .padding(Spacing.stroke)
                            }
                            if viewModel.isZcash && viewModel.isReceiveMode {
                                zcashReceiveFooter()
                            } else {
                                QRCodeAddressFooterView(
                                    viewModel: viewModel.renderable.footer,
                                    backgroundColor: .fill6Solid
                                )
                            }
                        }
                        .strokeContainerBackground()

                        // Zcash FVK/Receive toggle
                        if viewModel.isZcash {
                            zcashModeToggle()
                        }

                        // Zcash Receive controls
                        if viewModel.isZcash && viewModel.isReceiveMode {
                            zcashReceiveControls()
                        }

                        // Key data
                        keyDetails()
                            .padding(.bottom, Spacing.extraExtraLarge)
                    }
                    .padding(.horizontal, Spacing.large)
                    .padding(.top, Spacing.extraSmall)
                }
            }
            .frame(
                minWidth: geo.size.width,
                minHeight: geo.size.height
            )
            .background(.backgroundPrimary)
        }
        .onReceive(viewModel.dismissViewRequest) { _ in
            presentationMode.wrappedValue.dismiss()
        }
        // Action sheet
        .fullScreenModal(
            isPresented: $viewModel.isShowingActionSheet,
            onDismiss: {
                // iOS 15 handling of following .fullscreen presentation after dismissal, we need to dispatch this async
                DispatchQueue.main.async { viewModel.checkForActionsPresentation() }
            }
        ) {
            PublicKeyActionsModal(
                shouldPresentExportKeysWarningModal: $viewModel.shouldPresentExportKeysWarningModal,
                isShowingActionSheet: $viewModel.isShowingActionSheet,
                shouldPresentRemoveConfirmationModal: $viewModel.shouldPresentRemoveConfirmationModal,
                isExportKeyAvailable: viewModel.isExportKeyAvailable
            )
            .clearModalBackground()
        }
        // Export private key warning
        .fullScreenModal(
            isPresented: $viewModel.isPresentingExportKeysWarningModal,
            onDismiss: {
                // iOS 15 handling of following .fullscreen presentation after dismissal, we need to dispatch this async
                DispatchQueue.main.async { viewModel.onWarningDismissal() }
            }
        ) {
            ExportPrivateKeyWarningModal(
                isPresentingExportKeysWarningModal: $viewModel.isPresentingExportKeysWarningModal,
                shouldPresentExportKeysModal: $viewModel.shouldPresentExportKeysModal
            )
            .clearModalBackground()
        }
        // Export private key modal
        .fullScreenModal(
            isPresented: $viewModel.isPresentingExportKeysModal,
            onDismiss: viewModel.onExportKeysDismissal
        ) {
            ExportPrivateKeyModal(
                isPresentingExportKeysModal: $viewModel.isPresentingExportKeysModal,
                viewModel: viewModel.exportPrivateKeyViewModel
            )
            .clearModalBackground()
        }
        // Remove key modal
        .fullScreenModal(isPresented: $viewModel.isShowingRemoveConfirmation) {
            HorizontalActionsBottomModal(
                viewModel: .forgetSingleKey,
                mainAction: viewModel.onRemoveKeyTap(),
                isShowingBottomAlert: $viewModel.isShowingRemoveConfirmation
            )
            .clearModalBackground()
        }
        .fullScreenModal(
            isPresented: $viewModel.isPresentingError
        ) {
            ErrorBottomModal(
                viewModel: viewModel.presentableError,
                isShowingBottomAlert: $viewModel.isPresentingError
            )
            .clearModalBackground()
        }
    }
}

// MARK: - Zcash Receive Mode Views

private extension KeyDetailsPublicKeyView {
    @ViewBuilder
    func zcashReceiveQR() -> some View {
        if viewModel.showTransparent {
            if viewModel.zcashTransparentLoading {
                ProgressView()
                    .frame(height: 264)
            } else if let addr = viewModel.zcashTransparentAddress,
                      let qrData = viewModel.encodeAddressQR(addr) {
                AnimatedQRCodeView(
                    viewModel: Binding<AnimatedQRCodeViewModel>.constant(
                        .init(qrCodes: [qrData])
                    )
                )
                .padding(Spacing.stroke)
            }
        } else {
            if viewModel.zcashDiversifiedLoading {
                ProgressView()
                    .frame(height: 264)
            } else if let addr = viewModel.zcashDiversifiedAddress,
                      let qrData = viewModel.encodeAddressQR(addr) {
                AnimatedQRCodeView(
                    viewModel: Binding<AnimatedQRCodeViewModel>.constant(
                        .init(qrCodes: [qrData])
                    )
                )
                .padding(Spacing.stroke)
            } else {
                // Default address (index 0)
                AnimatedQRCodeView(
                    viewModel: Binding<AnimatedQRCodeViewModel>.constant(
                        .init(qrCodes: viewModel.renderable.qrCodes)
                    )
                )
                .padding(Spacing.stroke)
            }
        }
    }

    @ViewBuilder
    func zcashReceiveFooter() -> some View {
        HStack {
            if viewModel.showTransparent, let addr = viewModel.zcashTransparentAddress {
                Text(String(addr.prefix(12)) + "..." + String(addr.suffix(8)))
                    .foregroundColor(.textAndIconsTertiary)
                    .font(PrimaryFont.captionM.font)
                    .lineLimit(1)
            } else {
                Text("Address #\(viewModel.diversifierIndex)")
                    .foregroundColor(.textAndIconsTertiary)
                    .font(PrimaryFont.captionM.font)
            }
            Spacer()
            if let identicon = viewModel.keyDetails.address.identicon as Identicon? {
                IdenticonView(identicon: identicon, rowHeight: Heights.identiconSmall)
            }
        }
        .padding(Spacing.medium)
        .background(.fill6Solid)
    }

    @ViewBuilder
    func zcashModeToggle() -> some View {
        HStack(spacing: 0) {
            Button(action: { viewModel.isReceiveMode = false }) {
                Text("FVK")
                    .font(PrimaryFont.labelM.font)
                    .foregroundColor(viewModel.isReceiveMode ? .textAndIconsPrimary : .white)
                    .padding(.horizontal, Spacing.large)
                    .padding(.vertical, Spacing.small)
                    .background(viewModel.isReceiveMode ? Color.fill12 : Color.accentPink300)
                    .cornerRadius(CornerRadius.small, corners: [.topLeft, .bottomLeft])
            }
            Button(action: { viewModel.isReceiveMode = true }) {
                Text("Receive")
                    .font(PrimaryFont.labelM.font)
                    .foregroundColor(viewModel.isReceiveMode ? .white : .textAndIconsPrimary)
                    .padding(.horizontal, Spacing.large)
                    .padding(.vertical, Spacing.small)
                    .background(viewModel.isReceiveMode ? Color.accentPink300 : Color.fill12)
                    .cornerRadius(CornerRadius.small, corners: [.topRight, .bottomRight])
            }
        }
        Text(viewModel.isReceiveMode
             ? "Scan to send funds to this cold wallet"
             : "Scan with Zafu to import as watch-only wallet")
            .font(PrimaryFont.captionM.font)
            .foregroundColor(.textAndIconsTertiary)
            .multilineTextAlignment(.center)
    }

    @ViewBuilder
    func zcashReceiveControls() -> some View {
        // New Address button
        if !viewModel.showTransparent {
            Button(action: {
                viewModel.diversifierIndex += 1
                viewModel.requestDiversifiedAddress()
            }) {
                Text("New Address")
                    .font(PrimaryFont.labelM.font)
                    .foregroundColor(.white)
                    .padding(.horizontal, Spacing.large)
                    .padding(.vertical, Spacing.small)
                    .background(Color.accentPink300)
                    .cornerRadius(CornerRadius.small)
            }
        }

        // Transparent toggle
        HStack {
            Text("Transparent address")
                .font(PrimaryFont.bodyL.font)
                .foregroundColor(.textAndIconsPrimary)
            Spacer()
            Toggle("", isOn: Binding(
                get: { viewModel.showTransparent },
                set: { newValue in
                    viewModel.showTransparent = newValue
                    if newValue && viewModel.zcashTransparentAddress == nil {
                        viewModel.requestTransparentAddress()
                    }
                }
            ))
            .labelsHidden()
            .tint(.accentPink300)
        }
        .padding(.horizontal, Spacing.extraSmall)

        // Warning for transparent
        if viewModel.showTransparent {
            HStack(spacing: Spacing.extraSmall) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundColor(.accentRed300)
                    .font(.system(size: 14))
                Text("Transparent addresses offer no privacy. Use only for exchange compatibility.")
                    .font(PrimaryFont.captionM.font)
                    .foregroundColor(.textAndIconsPrimary)
            }
            .padding(Spacing.small)
            .background(Color.accentRed300.opacity(0.12))
            .cornerRadius(CornerRadius.small)
        }
    }
}

private extension KeyDetailsPublicKeyView {
    @ViewBuilder
    func keyDetails() -> some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 0) {
                Localizable.PublicKeyDetails.Label.network.text
                    .frame(height: Spacing.large, alignment: .center)
                    .padding(.vertical, Spacing.small)
                    .foregroundColor(.textAndIconsTertiary)
                Spacer()
                NetworkIconCapsuleView(
                    networkLogo: viewModel.renderable.networkLogo,
                    networkTitle: viewModel.renderable.networkTitle
                )
            }
            Divider()
            rowWrapper(
                Localizable.PublicKeyDetails.Label.derivation.string,
                viewModel.renderable.path.isEmpty && !viewModel.renderable.hasPassword ? Localizable.PublicKeyDetails
                    .Label.emptyPath.text : fullPath
            )
            rowWrapper(
                Localizable.PublicKeyDetails.Label.keySetName.string,
                Text(viewModel.renderable.keySetName),
                isLast: true
            )
        }
        .font(PrimaryFont.bodyL.font)
        .padding(.horizontal, Spacing.medium)
        .background(
            RoundedRectangle(cornerRadius: CornerRadius.medium)
                .stroke(.fill12, lineWidth: 1)
                .background(.fill6)
                .cornerRadius(CornerRadius.medium)
        )
    }

    @ViewBuilder
    func rowWrapper(
        _ key: String,
        _ value: some View,
        isLast: Bool = false
    ) -> some View {
        HStack(spacing: Spacing.medium) {
            Text(key)
                .foregroundColor(.textAndIconsTertiary)
                .frame(height: Spacing.large, alignment: .center)
            Spacer()
            value
                .frame(idealWidth: .infinity, alignment: .trailing)
                .multilineTextAlignment(.trailing)
                .foregroundColor(.textAndIconsPrimary)
        }
        .padding(.vertical, Spacing.small)
        if !isLast {
            Divider()
        }
    }

    /// String interpolation for SFSymbols is a bit unstable if creating `String` inline by using conditional logic or
    /// `appending` from `StringProtocol`. Hence less DRY approach and dedicated function to wrap that
    var fullPath: Text {
        viewModel.renderable.hasPassword ?
            Text(
                "\(viewModel.renderable.path)\(Localizable.Shared.Label.passwordedPathDelimeter.string)\(Image(.lock))"
            ) :
            Text(viewModel.renderable.path)
    }
}

extension KeyDetailsPublicKeyView {
    enum OnCompletionAction: Equatable {
        case derivedKeyDeleted
    }

    final class ViewModel: ObservableObject {
        let addressKey: String
        private let publicKeyDetailsService: PublicKeyDetailsServicing
        private let exportPrivateKeyService: ExportPrivateKeyServicing
        private let keyDetailsService: KeyDetailsActionServicing
        private let seedsMediator: SeedsMediating

        @Published var keyDetails: MKeyDetails
        @Published var exportPrivateKeyViewModel: ExportPrivateKeyViewModel!
        @Published var renderable: KeyDetailsPublicKeyViewRenderable
        @Published var isShowingRemoveConfirmation = false
        @Published var isShowingActionSheet = false
        @Published var isPresentingExportKeysWarningModal = false
        @Published var isPresentingExportKeysModal = false
        @Published var shouldPresentExportKeysWarningModal = false
        @Published var shouldPresentExportKeysModal = false
        @Published var shouldPresentRemoveConfirmationModal = false
        @Published var isPresentingError: Bool = false
        @Published var presentableError: ErrorBottomModalViewModel = .alertError(message: "")

        // Zcash receive mode state
        @Published var isReceiveMode: Bool = false
        @Published var diversifierIndex: Int = 0
        @Published var showTransparent: Bool = false
        @Published var zcashDiversifiedAddress: String?
        @Published var zcashDiversifiedLoading: Bool = false
        @Published var zcashTransparentAddress: String?
        @Published var zcashTransparentLoading: Bool = false

        var isZcash: Bool {
            keyDetails.networkInfo.networkLogo.lowercased().contains("zcash")
        }

        var isExportKeyAvailable: Bool {
            keyDetails.address.hasPwd == false
        }

        var dismissViewRequest: AnyPublisher<Void, Never> {
            dismissRequest.eraseToAnyPublisher()
        }

        private let dismissRequest = PassthroughSubject<Void, Never>()
        private let onCompletion: (OnCompletionAction) -> Void

        init(
            keyDetails: MKeyDetails,
            addressKey: String,
            publicKeyDetailsService: PublicKeyDetailsServicing = PublicKeyDetailsService(),
            exportPrivateKeyService: ExportPrivateKeyServicing = ExportPrivateKeyService(),
            keyDetailsService: KeyDetailsActionServicing = KeyDetailsActionService(),
            seedsMediator: SeedsMediating = ServiceLocator.seedsMediator,
            onCompletion: @escaping (OnCompletionAction) -> Void
        ) {
            _keyDetails = .init(initialValue: keyDetails)
            self.addressKey = addressKey
            self.publicKeyDetailsService = publicKeyDetailsService
            self.exportPrivateKeyService = exportPrivateKeyService
            self.keyDetailsService = keyDetailsService
            self.seedsMediator = seedsMediator
            self.onCompletion = onCompletion
            _renderable = .init(initialValue: KeyDetailsPublicKeyViewRenderable(keyDetails))
        }

        func onMoreButtonTap() {
            isShowingActionSheet = true
        }

        func checkForActionsPresentation() {
            if shouldPresentExportKeysWarningModal {
                shouldPresentExportKeysWarningModal = false
                exportPrivateKeyService.exportPrivateKey(keyDetails) { result in
                    switch result {
                    case let .success(model):
                        self.exportPrivateKeyViewModel = model
                        self.isPresentingExportKeysWarningModal = true
                    case let .failure(error):
                        self.presentableError = .alertError(message: error.message)
                        self.isPresentingError = true
                    }
                }
            }
            if shouldPresentRemoveConfirmationModal {
                shouldPresentRemoveConfirmationModal = false
                isShowingRemoveConfirmation = true
            }
        }

        func onWarningDismissal() {
            guard shouldPresentExportKeysModal else { return }
            shouldPresentExportKeysModal = false
            isPresentingExportKeysModal = true
        }

        func onExportKeysDismissal() {
            exportPrivateKeyViewModel = nil
            keyDetailsService.publicKey(
                addressKey: addressKey,
                networkSpecsKey: keyDetails.networkInfo.networkSpecsKey
            ) { result in
                switch result {
                case let .success(keyDetails):
                    self.keyDetails = keyDetails
                    self.renderable = KeyDetailsPublicKeyViewRenderable(keyDetails)
                case let .failure(error):
                    self.presentableError = .alertError(message: error.localizedDescription)
                    self.isPresentingError = true
                }
            }
        }

        func onRemoveKeyTap() {
            publicKeyDetailsService.forgetSingleKey(
                address: addressKey,
                networkSpecsKey: keyDetails.networkInfo.networkSpecsKey
            ) { result in
                switch result {
                case .success:
                    self.onCompletion(.derivedKeyDeleted)
                    self.dismissRequest.send()
                case let .failure(error):
                    self.presentableError = .alertError(message: error.localizedDescription)
                    self.isPresentingError = true
                }
            }
        }

        // MARK: - Zcash Address Generation

        func requestDiversifiedAddress() {
            let seedName = keyDetails.address.seedName
            let seedPhrase = seedsMediator.getSeed(seedName: seedName)
            guard !seedPhrase.isEmpty else { return }

            zcashDiversifiedLoading = true
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { return }
                do {
                    let address = try getZcashDiversifiedAddress(
                        seedPhrase: seedPhrase,
                        accountIndex: 0,
                        diversifierIndex: UInt32(self.diversifierIndex),
                        mainnet: true
                    )
                    DispatchQueue.main.async {
                        self.zcashDiversifiedAddress = address
                        self.zcashDiversifiedLoading = false
                    }
                } catch {
                    DispatchQueue.main.async {
                        self.zcashDiversifiedLoading = false
                    }
                }
            }
        }

        func requestTransparentAddress() {
            let seedName = keyDetails.address.seedName
            let seedPhrase = seedsMediator.getSeed(seedName: seedName)
            guard !seedPhrase.isEmpty else { return }

            zcashTransparentLoading = true
            DispatchQueue.global(qos: .userInitiated).async { [weak self] in
                guard let self else { return }
                do {
                    let address = try getZcashTransparentAddress(
                        seedPhrase: seedPhrase,
                        account: 0,
                        mainnet: true
                    )
                    DispatchQueue.main.async {
                        self.zcashTransparentAddress = address
                        self.zcashTransparentLoading = false
                    }
                } catch {
                    DispatchQueue.main.async {
                        self.zcashTransparentLoading = false
                    }
                }
            }
        }

        func encodeAddressQR(_ address: String) -> [UInt8]? {
            let bytes = Array(address.utf8).map { UInt8($0) }
            return try? encodeToQr(payload: bytes, isDanger: false)
        }
    }
}

#if DEBUG
    struct KeyDetailsPublicKeyView_Previews: PreviewProvider {
        static var previews: some View {
            Group {
                KeyDetailsPublicKeyView(
                    viewModel: .init(
                        keyDetails: .stub,
                        addressKey: "",
                        onCompletion: { _ in }
                    )
                )
            }
            .previewLayout(.sizeThatFits)
            .preferredColorScheme(.dark)
        }
    }
#endif
