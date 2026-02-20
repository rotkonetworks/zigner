//
//  PenumbraSignatureQrView.swift
//  Zigner
//

import SwiftUI

struct PenumbraSignatureQrView: View {
    let signatureBytes: [UInt8]
    let onDone: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            Text("Penumbra Signature")
                .font(PrimaryFont.titleL.font)
                .foregroundColor(.textAndIconsPrimary)
                .padding(.bottom, Spacing.small)

            Text("Scan this QR code with Prax to complete the transaction")
                .font(PrimaryFont.bodyL.font)
                .foregroundColor(.textAndIconsSecondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, Spacing.large)
                .padding(.bottom, Spacing.large)

            Spacer()

            AnimatedQRCodeView(
                viewModel: .constant(.init(qrCodes: [hexEncodedQrData]))
            )

            Spacer()

            Divider()
            ActionButton(
                action: onDone,
                text: "Done",
                style: .primary()
            )
            .padding(.horizontal, Spacing.large)
            .padding(.vertical, Spacing.medium)
        }
    }

    /// Hex-encode signature bytes for reliable QR scanning (ASCII-safe)
    private var hexEncodedQrData: [UInt8] {
        let hexString = signatureBytes.map { String(format: "%02x", $0) }.joined()
        return Array(hexString.utf8)
    }
}
