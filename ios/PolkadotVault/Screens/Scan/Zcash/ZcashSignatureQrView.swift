//
//  ZcashSignatureQrView.swift
//  Zigner
//

import SwiftUI

struct ZcashSignatureQrView: View {
    let signatureBytes: [UInt8]
    let onDone: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            Text("Zcash Signature")
                .font(PrimaryFont.titleL.font)
                .foregroundColor(.textAndIconsPrimary)
                .padding(.bottom, Spacing.small)

            Text("Scan this QR code with Zafu to complete the transaction")
                .font(PrimaryFont.bodyL.font)
                .foregroundColor(.textAndIconsSecondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal, Spacing.large)
                .padding(.bottom, Spacing.large)

            Spacer()

            AnimatedQRCodeView(
                viewModel: .constant(.init(qrCodes: [signatureBytes]))
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
}
