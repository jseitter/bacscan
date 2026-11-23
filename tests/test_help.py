"""Help system: content consistency, lookup, rendering, GUI window, CLI."""
import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from bacpypes3.basetypes import ObjectType, PropertyIdentifier  # noqa: E402

from bacscan import help as helpmod  # noqa: E402
from bacscan.cli.main import main as cli_main  # noqa: E402
from bacscan.help.objects import OBJECT_TYPES  # noqa: E402
from bacscan.help.properties import PROPERTIES  # noqa: E402


def _valid(cls, name):
    try:
        cls(name)
        return True
    except Exception:
        return False


def test_topic_ids_unique():
    ids = [t.id for t in helpmod.all_topics()]
    assert len(ids) == len(set(ids))


def test_names_are_real_bacnet_names():
    assert [n for n in OBJECT_TYPES if not _valid(ObjectType, n)] == []
    assert [p for p in PROPERTIES if not _valid(PropertyIdentifier, p)] == []
    used = {p for v in OBJECT_TYPES.values() for p in v[3]}
    assert [p for p in used if not _valid(PropertyIdentifier, p)] == []


def test_every_standard_object_type_documented():
    names = {str(ObjectType(n)) for n in ObjectType._enum_map}
    assert sorted(n for n in names if n not in OBJECT_TYPES) == []


def test_scanner_properties_are_explained():
    from bacscan.core.scanner import COMMON_PROPS, DEVICE_PROPS, TYPE_PROPS
    known = set(PROPERTIES)
    wanted = set(COMMON_PROPS) | set(DEVICE_PROPS) | {p for v in TYPE_PROPS.values() for p in v}
    assert sorted(wanted - known) == []


def test_explain_and_search():
    assert helpmod.explain("Analog-Input").group == "Object types"
    assert helpmod.explain("priority-array").group == "Properties"
    assert helpmod.explain("segmentation").group == "Glossary"
    assert helpmod.explain("levels").group == "Guide"
    assert helpmod.explain("128").title.startswith("Proprietary")
    assert helpmod.explain("nonsense-xyz") is None
    assert any(t.id == "object:schedule" for t in helpmod.search("weekly exception"))
    assert helpmod.search("") == []


def test_render():
    t = helpmod.explain("schedule")
    html = helpmod.render_html(t)
    assert "<h2>" in html and "<ul>" in html and "<script" not in html
    assert "**" not in html
    text = helpmod.render_text(t)
    assert text.startswith("Schedule") and "**" not in text
    nasty = helpmod.Topic("x", "<b>t</b>", "Guide", "a <script>alert(1)</script>")
    assert "<script>" not in helpmod.render_html(nasty)


def test_help_window():
    from PySide6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])  # noqa: F841
    from bacscan.gui.help_dialog import HelpWindow
    w = HelpWindow()
    assert "Getting started" in w.browser.toPlainText()
    w.show_topic("object:analog-output")
    assert "priority" in w.browser.toPlainText().lower()
    w.search.setText("segmentation")
    assert w.tree.topLevelItemCount() >= 1
    w.show_topic("property:max-apdu-length-accepted")
    assert w.search.text() == "" and "480" in w.browser.toPlainText()
    w.show_topic("does-not-exist")
    assert "Getting started" in w.browser.toPlainText()


def test_tooltips_explain_types_and_properties():
    from PySide6.QtCore import Qt

    from bacscan.core.models import BacnetObject, PropValue
    from bacscan.gui.models import ObjectModel, PropertyModel
    om = ObjectModel()
    om.set_items([BacnetObject("analog-input", 1)])
    assert "sensor" in om.data(om.index(0, 0), Qt.ItemDataRole.ToolTipRole)
    assert om.data(om.index(0, 1), Qt.ItemDataRole.ToolTipRole) == "1"
    pm = PropertyModel()
    pm.set_items([("units", PropValue(value="x", text="x")), ("(address)", "1.2.3.4")])
    assert "Engineering unit" in pm.data(pm.index(0, 0), Qt.ItemDataRole.ToolTipRole)
    assert pm.data(pm.index(1, 0), Qt.ItemDataRole.ToolTipRole) == "(address)"


def test_cli_help(capsys):
    assert cli_main(["help"]) == 0
    assert "analog-input" in capsys.readouterr().out
    assert cli_main(["help", "schedule"]) == 0
    assert "weekly" in capsys.readouterr().out
    assert cli_main(["help", "nonsense-xyz"]) == 1
