"""Draw the artwork with Qt: app icon (packaging/bacscan.icns), window icon (src/bacscan/gui/icon.png)
and the installer background (packaging/pkg/resources/background.png). Run: uv run python packaging/make_icon.py"""
import os
import subprocess
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PySide6.QtCore import QPointF, QRectF, Qt  # noqa: E402
from PySide6.QtGui import QColor, QFont, QGuiApplication, QImage, QLinearGradient, QPainter, QPen  # noqa: E402

HERE = Path(__file__).resolve().parent
ICNS = HERE / "bacscan.icns"
WINDOW_ICON = HERE.parent / "src" / "bacscan" / "gui" / "icon.png"
PKG_BACKGROUND = HERE / "pkg" / "resources" / "background.png"


def paint_icon(p: QPainter, x: float, y: float, size: float) -> None:
    """Icon on the 1024 grid of macOS app icons: 824 px rounded square, waves above, the name below."""
    s = size / 1024

    def pt(px, py):
        return QPointF(x + px * s, y + py * s)

    body = QRectF(pt(100, 100), pt(924, 924))
    grad = QLinearGradient(body.topLeft(), body.bottomRight())
    grad.setColorAt(0, QColor("#2160b8"))
    grad.setColorAt(1, QColor("#0d2a57"))
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(grad)
    p.drawRoundedRect(body, 185 * s, 185 * s)

    # a dot sending three waves to the upper right
    c = pt(345, 640)
    for i, r in enumerate((130, 250, 370)):
        pen = QPen(QColor(255, 255, 255, 240 - i * 60), 52 * s)
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        p.setPen(pen)
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawArc(QRectF(c.x() - r * s, c.y() - r * s, 2 * r * s, 2 * r * s), 0, 90 * 16)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor("#4fc3f7"))
    p.drawEllipse(c, 62 * s, 62 * s)

    # the waves end at y=640+26 (cap); the text band starts below that
    font = QFont("Helvetica Neue")
    font.setPixelSize(max(1, round(140 * s)))
    font.setWeight(QFont.Weight.Bold)
    p.setFont(font)
    p.setPen(QColor("white"))
    p.drawText(QRectF(pt(100, 715), pt(924, 885)), Qt.AlignmentFlag.AlignCenter, "bacscan")


def draw_icon(size: int) -> QImage:
    img = QImage(size, size, QImage.Format.Format_ARGB32)
    img.fill(Qt.GlobalColor.transparent)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    paint_icon(p, 0, 0, size)
    p.end()
    return img


def draw_pkg_background(scale: int = 2) -> QImage:
    """Installer window background: the icon in the lower left, under the step list."""
    img = QImage(620 * scale, 418 * scale, QImage.Format.Format_ARGB32)
    img.fill(Qt.GlobalColor.transparent)
    img.setDevicePixelRatio(scale)
    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setOpacity(0.9)
    paint_icon(p, 18, 418 - 150, 150)
    p.end()
    return img


def main() -> None:
    QGuiApplication.instance() or QGuiApplication(sys.argv[:1])
    with tempfile.TemporaryDirectory() as tmp:
        iconset = Path(tmp) / "bacscan.iconset"
        iconset.mkdir()
        for base in (16, 32, 128, 256, 512):
            draw_icon(base).save(str(iconset / f"icon_{base}x{base}.png"))
            draw_icon(base * 2).save(str(iconset / f"icon_{base}x{base}@2x.png"))
        subprocess.run(["iconutil", "-c", "icns", str(iconset), "-o", str(ICNS)], check=True)
    draw_icon(512).save(str(WINDOW_ICON))
    draw_pkg_background().save(str(PKG_BACKGROUND))
    for f in (ICNS, WINDOW_ICON, PKG_BACKGROUND):
        print(f"wrote {f}")


if __name__ == "__main__":
    main()
