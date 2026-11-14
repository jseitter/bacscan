"""BACnet/SC settings: hub, certificates, options. The key password stays in memory only."""
from __future__ import annotations

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QWidget,
)


class ScDialog(QDialog):
    def __init__(self, settings: QSettings, key_password: str = "", parent=None):
        super().__init__(parent)
        self.settings = settings
        self.setWindowTitle("BACnet/SC")
        self.setMinimumWidth(560)
        form = QFormLayout(self)

        def text(key: str, placeholder: str = "") -> QLineEdit:
            e = QLineEdit(str(settings.value(key, "")))
            e.setPlaceholderText(placeholder)
            return e

        self.hub = text("sc_hub", "wss://hub.example.com:4443")
        self.failover = text("sc_failover", "optional failover hub")
        self.cert = text("sc_cert", "operational certificate (PEM)")
        self.key = text("sc_key", "private key (PEM)")
        self.ca = text("sc_ca", "CA certificate that signed the hub's certificate (PEM)")
        self.password = QLineEdit(key_password)
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText("only if the private key is encrypted")
        self.show_pw = QCheckBox("Show")
        self.show_pw.toggled.connect(lambda on: self.password.setEchoMode(
            QLineEdit.EchoMode.Normal if on else QLineEdit.EchoMode.Password))
        self.verify = QCheckBox("Verify the hub's certificate")
        self.verify.setChecked(str(settings.value("sc_verify", True)).lower() == "true")
        self.direct = QCheckBox("Connect directly to devices that offer a direct-connect URI")
        self.direct.setChecked(str(settings.value("sc_direct", False)).lower() == "true")

        form.addRow("Hub URI", self.hub)
        form.addRow("Failover hub", self.failover)
        form.addRow("Certificate", self._with_browse(self.cert))
        form.addRow("Private key", self._with_browse(self.key))
        form.addRow("CA certificate", self._with_browse(self.ca))
        pw = QWidget()
        row = QHBoxLayout(pw)
        row.setContentsMargins(0, 0, 0, 0)
        row.addWidget(self.password, 1)
        row.addWidget(self.show_pw)
        form.addRow("Key password", pw)
        form.addRow("", self.verify)
        form.addRow("", self.direct)
        note = QLabel("BACnet/SC replaces BACnet/IP for this scan: bacscan joins the hub as a node (mutual TLS) and "
                      "sends Who-Is through it. Read-only. The key password is kept in memory for this session only. "
                      "Switching off verification is for lab use only.")
        note.setWordWrap(True)
        note.setStyleSheet("color: gray")
        form.addRow(note)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        form.addRow(buttons)

    def _with_browse(self, edit: QLineEdit) -> QWidget:
        w = QWidget()
        row = QHBoxLayout(w)
        row.setContentsMargins(0, 0, 0, 0)
        row.addWidget(edit, 1)
        b = QPushButton("Browse…")

        def pick() -> None:
            path, _ = QFileDialog.getOpenFileName(self, "Select file", edit.text(),
                                                  "PEM files (*.pem *.crt *.cer *.key);;All files (*)")
            if path:
                edit.setText(path)

        b.clicked.connect(pick)
        row.addWidget(b)
        return w

    def accept(self) -> None:
        from ..core.sc import SCError, SCSettings
        hub = self.hub.text().strip()
        try:
            SCSettings(hub=hub, failover=self.failover.text().strip() or None,
                       cert=self.cert.text().strip() or None, key=self.key.text().strip() or None,
                       ca=self.ca.text().strip() or None).validate()
            if not hub:
                raise SCError("enter the hub URI")
        except SCError as e:
            QMessageBox.warning(self, "BACnet/SC", str(e))
            return
        if not self.verify.isChecked():
            if QMessageBox.question(self, "BACnet/SC",
                                    "Without verification anyone can pose as the hub. Use this in a lab only.\n\n"
                                    "Continue without verification?") != QMessageBox.StandardButton.Yes:
                return
        s = self.settings
        for key, w in (("sc_hub", self.hub), ("sc_failover", self.failover), ("sc_cert", self.cert),
                       ("sc_key", self.key), ("sc_ca", self.ca)):
            s.setValue(key, w.text().strip())
        s.setValue("sc_verify", self.verify.isChecked())
        s.setValue("sc_direct", self.direct.isChecked())
        super().accept()
