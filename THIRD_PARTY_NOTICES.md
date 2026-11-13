# Third-party notices

bacscan itself is MIT licensed (see `LICENSE`). It uses the following components.
Their licences apply to them, not to bacscan.

| Component | Licence | Notes |
|---|---|---|
| [PySide6 / Qt for Python](https://doc.qt.io/qtforpython-6/) (Essentials) | LGPL-3.0 | GUI. Bundled dynamically in the macOS app, installer and DMG. |
| [bacpypes3](https://github.com/JoelBender/bacpypes3) | MIT | BACnet stack |
| [cryptography](https://github.com/pyca/cryptography) | Apache-2.0 / BSD-3-Clause | SNMPv3 AES |
| [openpyxl](https://openpyxl.readthedocs.io/) | MIT | Excel export |
| [psutil](https://github.com/giampaolo/psutil) | BSD-3-Clause | Network interfaces |
| [rich](https://github.com/Textualize/rich) | MIT | CLI output |
| [PyInstaller](https://pyinstaller.org/) | GPL-2.0 with bootloader exception | Build tool only. Its exception allows distributing the bundled app under any licence. |
| Python | PSF-2.0 | Embedded runtime in the app bundle |

## Qt / PySide6 (LGPL-3.0)

The macOS app bundle contains unmodified PySide6 and Qt libraries as separate shared
libraries inside `bacscan.app`. You may replace them with your own build of the same
libraries. The LGPL-3.0 text is at <https://www.gnu.org/licenses/lgpl-3.0.html>, and the
Qt for Python source code is available at <https://code.qt.io/cgit/pyside/pyside-setup.git/>.

## Data

`src/bacscan/data/oui.tsv.gz` is derived from the public IEEE MAC address (OUI) registry
(<https://standards-oui.ieee.org/>). Regenerate it with `scripts/update_oui.py`.
