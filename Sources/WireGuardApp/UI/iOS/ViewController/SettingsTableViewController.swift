// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import UIKit
import os.log

class SettingsTableViewController: UITableViewController {

    enum SettingsFields {
        case iosAppVersion
        case goBackendVersion
        case exportZipArchive
        case viewLog
        case dohEnabled
        case dohProvider
        case dohFallback

        var localizedUIString: String {
            switch self {
            case .iosAppVersion: return tr("settingsVersionKeyWireGuardForIOS")
            case .goBackendVersion: return tr("settingsVersionKeyWireGuardGoBackend")
            case .exportZipArchive: return tr("settingsExportZipButtonTitle")
            case .viewLog: return tr("settingsViewLogButtonTitle")
            case .dohEnabled: return tr("tunnelInterfaceDoHEnabled")
            case .dohProvider: return tr("tunnelInterfaceDoHProvider")
            case .dohFallback: return tr("tunnelInterfaceDoHFallback")
            }
        }
    }

    let settingsFieldsBySection: [[SettingsFields]] = [
        [.dohEnabled, .dohProvider, .dohFallback],
        [.iosAppVersion, .goBackendVersion],
        [.exportZipArchive],
        [.viewLog]
    ]

    let tunnelsManager: TunnelsManager?
    var wireguardCaptionedImage: (view: UIView, size: CGSize)?

    init(tunnelsManager: TunnelsManager?) {
        self.tunnelsManager = tunnelsManager
        super.init(style: .grouped)
    }

    required init?(coder aDecoder: NSCoder) {
        fatalError("init(coder:) has not been implemented")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
        title = tr("settingsViewTitle")
        navigationItem.rightBarButtonItem = UIBarButtonItem(barButtonSystemItem: .done, target: self, action: #selector(doneTapped))

        tableView.estimatedRowHeight = 44
        tableView.rowHeight = UITableView.automaticDimension
        tableView.allowsSelection = true

        tableView.register(KeyValueCell.self)
        tableView.register(ButtonCell.self)
        tableView.register(SwitchCell.self)
        tableView.register(ChevronCell.self)

        tableView.tableFooterView = UIImageView(image: UIImage(named: "wireguard.pdf"))
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        guard let logo = tableView.tableFooterView else { return }

        let bottomPadding = max(tableView.layoutMargins.bottom, 10)
        let fullHeight = max(tableView.contentSize.height, tableView.bounds.size.height - tableView.layoutMargins.top - bottomPadding)

        let imageAspectRatio = logo.intrinsicContentSize.width / logo.intrinsicContentSize.height

        var height = tableView.estimatedRowHeight * 1.5
        var width = height * imageAspectRatio
        let maxWidth = view.bounds.size.width - max(tableView.layoutMargins.left + tableView.layoutMargins.right, 20)
        if width > maxWidth {
            width = maxWidth
            height = width / imageAspectRatio
        }

        let needsReload = height != logo.frame.height

        logo.frame = CGRect(x: (view.bounds.size.width - width) / 2, y: fullHeight - height, width: width, height: height)

        if needsReload {
            tableView.tableFooterView = logo
        }
    }

    @objc func doneTapped() {
        dismiss(animated: true, completion: nil)
    }

    func exportConfigurationsAsZipFile(sourceView: UIView) {
        PrivateDataConfirmation.confirmAccess(to: tr("iosExportPrivateData")) { [weak self] in
            guard let self = self else { return }
            guard let tunnelsManager = self.tunnelsManager else { return }
            guard let destinationDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first else { return }

            let destinationURL = destinationDir.appendingPathComponent("wireguard-export.zip")
            _ = FileManager.deleteFile(at: destinationURL)

            let count = tunnelsManager.numberOfTunnels()
            let tunnelConfigurations = (0 ..< count).compactMap { tunnelsManager.tunnel(at: $0).tunnelConfiguration }
            ZipExporter.exportConfigFiles(tunnelConfigurations: tunnelConfigurations, to: destinationURL) { [weak self] error in
                if let error = error {
                    ErrorPresenter.showErrorAlert(error: error, from: self)
                    return
                }

                let fileExportVC = UIDocumentPickerViewController(url: destinationURL, in: .exportToService)
                self?.present(fileExportVC, animated: true, completion: nil)
            }
        }
    }

    func presentLogView() {
        let logVC = LogViewController()
        navigationController?.pushViewController(logVC, animated: true)

    }
}

extension SettingsTableViewController {
    override func numberOfSections(in tableView: UITableView) -> Int {
        return settingsFieldsBySection.count
    }

    override func tableView(_ tableView: UITableView, numberOfRowsInSection section: Int) -> Int {
        return settingsFieldsBySection[section].count
    }

    override func tableView(_ tableView: UITableView, titleForHeaderInSection section: Int) -> String? {
        switch section {
        case 0:
            return tr("tunnelSectionTitleDoH")
        case 1:
            return tr("settingsSectionTitleAbout")
        case 2:
            return tr("settingsSectionTitleExportConfigurations")
        case 3:
            return tr("settingsSectionTitleTunnelLog")
        default:
            return nil
        }
    }

    override func tableView(_ tableView: UITableView, cellForRowAt indexPath: IndexPath) -> UITableViewCell {
        let field = settingsFieldsBySection[indexPath.section][indexPath.row]
        if field == .iosAppVersion || field == .goBackendVersion {
            let cell: KeyValueCell = tableView.dequeueReusableCell(for: indexPath)
            cell.copyableGesture = false
            cell.key = field.localizedUIString
            if field == .iosAppVersion {
                var appVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "Unknown version"
                if let appBuild = Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String {
                    appVersion += " (\(appBuild))"
                }
                cell.value = appVersion
            } else if field == .goBackendVersion {
                cell.value = WIREGUARD_GO_VERSION
            }
            return cell
        } else if field == .exportZipArchive {
            let cell: ButtonCell = tableView.dequeueReusableCell(for: indexPath)
            cell.buttonText = field.localizedUIString
            cell.onTapped = { [weak self] in
                self?.exportConfigurationsAsZipFile(sourceView: cell.button)
            }
            return cell
        } else if field == .viewLog {
            let cell: ButtonCell = tableView.dequeueReusableCell(for: indexPath)
            cell.buttonText = field.localizedUIString
            cell.onTapped = { [weak self] in
                self?.presentLogView()
            }
            return cell
        } else if field == .dohEnabled || field == .dohFallback {
            let cell: SwitchCell = tableView.dequeueReusableCell(for: indexPath)
            cell.message = field.localizedUIString
            let config = DoHSettingsManager.shared.configuration
            cell.isOn = field == .dohEnabled ? config.isEnabled : config.fallbackEnabled
            cell.onSwitchToggled = { isOn in
                var config = DoHSettingsManager.shared.configuration
                if field == .dohEnabled {
                    config.isEnabled = isOn
                    DoHSettingsManager.shared.configuration = config
                } else {
                    config.fallbackEnabled = isOn
                    DoHSettingsManager.shared.configuration = config
                }
            }
            return cell
        } else if field == .dohProvider {
            let cell: ChevronCell = tableView.dequeueReusableCell(for: indexPath)
            cell.message = field.localizedUIString
            let config = DoHSettingsManager.shared.configuration
            cell.detailMessage = config.provider.displayName
            return cell
        }
        fatalError()
    }

    override func tableView(_ tableView: UITableView, willSelectRowAt indexPath: IndexPath) -> IndexPath? {
        let field = settingsFieldsBySection[indexPath.section][indexPath.row]
        if field == .dohProvider {
            return indexPath
        }
        return nil
    }

    override func tableView(_ tableView: UITableView, didSelectRowAt indexPath: IndexPath) {
        let field = settingsFieldsBySection[indexPath.section][indexPath.row]
        tableView.deselectRow(at: indexPath, animated: true)
        if field == .dohProvider {
            showDoHProviderPicker(at: indexPath)
        }
    }

    private func showDoHProviderPicker(at indexPath: IndexPath) {
        let alertController = UIAlertController(title: tr("tunnelInterfaceDoHProvider"), message: nil, preferredStyle: .actionSheet)

        for provider in DoHProvider.allCases {
            let action = UIAlertAction(title: provider.displayName, style: .default) { [weak self] _ in
                if provider == .custom {
                    self?.showCustomDoHURLInput(at: indexPath)
                } else {
                    var config = DoHSettingsManager.shared.configuration
                    config.provider = provider
                    DoHSettingsManager.shared.configuration = config
                    self?.tableView.reloadRows(at: [indexPath], with: .fade)
                }
            }
            alertController.addAction(action)
        }

        let cancelAction = UIAlertAction(title: tr("actionCancel"), style: .cancel)
        alertController.addAction(cancelAction)

        if let popoverController = alertController.popoverPresentationController {
            if let cell = tableView.cellForRow(at: indexPath) {
                popoverController.sourceView = cell
                popoverController.sourceRect = cell.bounds
            }
        }

        present(alertController, animated: true)
    }

    private func showCustomDoHURLInput(at indexPath: IndexPath) {
        let config = DoHSettingsManager.shared.configuration

        let alertController = UIAlertController(
            title: tr("tunnelInterfaceDoHCustom"),
            message: tr("tunnelInterfaceDoHCustomMessage"),
            preferredStyle: .alert
        )

        // DoH URL 输入框
        alertController.addTextField { textField in
            textField.placeholder = "https://doh.server/dns-query"
            textField.keyboardType = .URL
            textField.autocapitalizationType = .none
            textField.autocorrectionType = .no
            if let customURL = config.customURL {
                textField.text = customURL.absoluteString
            }
        }

        // Bootstrap IP 输入框
        alertController.addTextField { textField in
            textField.placeholder = tr("tunnelInterfaceDoHBootstrapIPsPlaceholder")
            textField.keyboardType = .numbersAndPunctuation
            textField.autocapitalizationType = .none
            textField.autocorrectionType = .no
            if !config.customBootstrapIPs.isEmpty {
                textField.text = config.customBootstrapIPs.joined(separator: ", ")
            }
        }

        let confirmAction = UIAlertAction(title: tr("actionSave"), style: .default) { [weak self, weak alertController] _ in
            guard let textFields = alertController?.textFields,
                  textFields.count >= 2 else { return }

            let urlString = textFields[0].text ?? ""
            let bootstrapIPsString = textFields[1].text ?? ""

            // 校验 URL
            guard !urlString.isEmpty, let url = URL(string: urlString) else {
                self?.showInvalidURLAlert()
                return
            }

            // 校验 Bootstrap IP
            let bootstrapIPs = bootstrapIPsString.split(separator: ",")
                .map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty }

            guard !bootstrapIPs.isEmpty else {
                self?.showMissingBootstrapIPAlert()
                return
            }

            var newConfig = DoHSettingsManager.shared.configuration
            newConfig.provider = .custom
            newConfig.customURL = url
            newConfig.customBootstrapIPs = bootstrapIPs
            DoHSettingsManager.shared.configuration = newConfig
            self?.tableView.reloadRows(at: [indexPath], with: .fade)
        }

        let cancelAction = UIAlertAction(title: tr("actionCancel"), style: .cancel)

        alertController.addAction(confirmAction)
        alertController.addAction(cancelAction)

        present(alertController, animated: true)
    }

    private func showMissingBootstrapIPAlert() {
        let alert = UIAlertController(
            title: tr("alertMissingBootstrapIPTitle"),
            message: tr("alertMissingBootstrapIPMessage"),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: tr("actionOK"), style: .default))
        present(alert, animated: true)
    }

    private func showInvalidURLAlert() {
        let alert = UIAlertController(
            title: tr("alertInvalidURLTitle"),
            message: tr("alertInvalidURLMessage"),
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: tr("actionOK"), style: .default))
        present(alert, animated: true)
    }
}
