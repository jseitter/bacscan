"""Draw the app icon with Qt and convert it to packaging/bacscan.icns (macOS iconutil)."""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtCore import QPointF, QRectF, Qt  # noqa: E402
from PySide6.QtGui import QColor, QFont, QGuiApplication, QImage, QLinearGradient, QPainter, QPen  # noqa: E402

OUT = Path(__file__).resolve().parent / "bacscan.icns"


def draw(size: int) -> QImage:
    img = QImage(size, size, QImage.Format.Format_ARGB32)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    s = size / 1024
    rect = QRectF(100 * s, 100 * s, 824 * s, 824 * s)
    grad = QLinearGradient(rect.topLeft(), rect.bottomRight())
    grad.setColorAt(0, QColor("#1e4f9c"))
    grad.setColorAt(1, QColor("#0d2a57"))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(grad)
    p.drawRoundedRect(rect, 185 * s, 185 * s)
    center = QPointF(330 * s, 700 * s)
    for i, r in enumerate((150, 280, 410)):
        pen = QPen(QColor(255, 255, 255, 235 - i * 55), 46 * s)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawArc(QRectF(center.x() - r * s, center.y() - r * s, 2 * r * s, 2 * r * s), 0 * 16, 90 * 16)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#4fc3f7"))
    p.drawEllipse(center, 52 * s, 52 * s)
    p.setPen(QColor("white"))
    font = QFont("Helvetica", int(120 * s) or 1, QFont.Weight.Bold)
    p.setFont(font)
    p.drawText(QRectF(470 * s, 600 * s, 400 * s, 200 * s), Qt.AlignmentFlag.AlignCenter, "BAC")
    p.end()
    return img


def main() -> None:
    QGuiApplication.instance() or QGuiApplication(sys.argv[:1])
    with tempfile.TemporaryDirectory() as tmp:
        iconset = Path(tmp) / "bacscan.iconset"
        iconset.mkdir()
        for base in (16, 32, 128, 256, 512):
            draw(base).save(str(iconset / f"icon_{base}x{base}.png"))
            draw(base * 2).save(str(iconset / f"icon_{base}x{base}@2x.png"))
        subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(OUT)], check=True)
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
