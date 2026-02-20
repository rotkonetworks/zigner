//
//  SettingsItem.swift
//  Zigner
//
//  Created by Krzysztof Rodak on 12/12/2022.
//

import Foundation

enum SettingsItem: Equatable, Hashable, CaseIterable {
    case penumbraFvkExport
    case zcashFvkExport
    case logs
    case networks
    case verifier
    case privacyPolicy
    case termsAndConditions
    case wipe
}

extension SettingsItem {
    var title: String {
        switch self {
        case .penumbraFvkExport:
            "Penumbra FVK Export"
        case .zcashFvkExport:
            "Zcash FVK Export"
        case .logs:
            Localizable.Settings.Label.logs.string
        case .networks:
            Localizable.Settings.Label.networks.string
        case .verifier:
            Localizable.Settings.Label.verifier.string
        case .privacyPolicy:
            Localizable.Settings.Label.policy.string
        case .termsAndConditions:
            Localizable.Settings.Label.terms.string
        case .wipe:
            Localizable.Settings.Label.wipe.string
        }
    }

    var isDestructive: Bool {
        [.wipe].contains(self)
    }

    var hasDetails: Bool {
        ![.wipe].contains(self)
    }

    var nativeNavigation: Bool {
        ![.wipe, .networks, .verifier].contains(self)
    }
}
