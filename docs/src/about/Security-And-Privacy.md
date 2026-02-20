# Security and Privacy

## Device security
Zigner is built to be used offline. The mobile device used to run the app will hold important information that needs to be kept securely stored. It is therefore advised to:
- Get a separate mobile device.
- Make a factory reset.
- Enable full-disk encryption on the device, with a reasonable password (might not be on by default, for example for older Android devices).
- Do not use any kind of biometrics such as fingerprint or face recognition for device decryption/unlocking, as those may be less secure than regular passwords. For example, some can be forced to unlock derive by other people.
- Once the app has been installed, enable airplane mode and make sure to switch off Wifi, Bluetooth or any connection ability of the device.
- Only charge the phone on a power outlet that is never connected to the internet. Only charge the phone with the manufacturer's charging adapter. Do not charge the phone on public USB chargers.

## How to get it and use it?

### Install the app
The app is available for Android and iOS:
- [GitHub Releases](https://github.com/rotkonetworks/zigner/releases)

Please double check carefully the origin of the app. Usual security advice apply to this air-gapped wallet:
- When creating an account using Zigner, make sure to write down the recovery phrase and store it in safe places.
- Always double check the information of the transactions you are about to sign or send.
- Make sure to first transfer a small amount with the app and verify that everything is working as expected before transferring larger amounts.

## How to update Zigner securely
Once Zigner is installed, your device should never go online. This would put your private keys at threat. To update, you will need to:
1. Make sure you possess the recovery phrase for each of your accounts. You can find it on Zigner by:
- choosing an identity > click the user icon at the top right > "Show Recovery Phrase"
2. Factory reset the device.
3. Enable full-disk encryption on the device and set a strong password (might not be on by default, for example for older Android devices).
4. Do not use any kind of biometrics such as fingerprint or face recognition for device decryption/unlocking, as those may be less secure than regular passwords.
5. Install Zigner from GitHub Releases (make sure you verify the checksum and APK signature)
6. Once the app has been installed, enable airplane mode and make sure to switch off Wifi, Bluetooth, and any other connection ability the device has.
7. Only charge the phone on a power outlet that is never connected to the internet. Only charge the phone with the manufacturer's charging adapter. Do not charge the phone on public USB chargers.
8. Recover your accounts.

## What data does it collect?
None, it's as simple as that. The Zigner Android and iOS apps do not send any sort of data to anyone and work completely offline once installed.
