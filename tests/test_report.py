"""Site report (M8): findings, HTML, PDF, CLI; duplicate device instance detection."""
import asyncio
import os
import re

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from bacscan.cli.main import main as cli_main  # noqa: E402
from bacscan.core.findings import DUPLICATE_PREFIX, findings  # noqa: E402
from bacscan.core.models import Scan  # noqa: E402
from bacscan.core.scanner import ScanConfig, Scanner  # noqa: E402
from bacscan.storage import report  # noqa: E402
from bacscan.storage.db import Store  # noqa: E402
from sample_scan import sample_scan  # noqa: E402
from sim_device import build_app  # noqa: E402


def test_findings_rules():
    fs = {f.title: f for f in findings(sample_scan())}
    assert fs["Duplicate BACnet device instance"].severity == "critical"
    assert fs["Duplicate BACnet device instance"].items == ["1001 AHU-1: 10.20.0.11 and 10.20.0.19"]
    assert fs["Telnet open"].items == ["10.20.0.11 (BACnet device)"]
    assert fs["Niagara Fox without TLS (1911)"].items == ["10.20.0.20 (jace-1)"]
    assert fs["Web interface only over HTTP"].items == ["10.20.0.11 (BACnet device)"]  # .13 also has 443
    assert "Modbus TCP" in fs["Unauthenticated control protocols reachable"].items[0]
    assert fs["Gateway does not answer ping"].severity == "warning"
    assert fs["BACnet devices not readable"].items == ["2002 VAV 2.02 (2001:0x06)"]
    assert len(fs["Self-signed TLS certificates"].items) == 2
    assert fs["SNMP v1/v2c answering"].items == ["10.20.0.2 (sw-plant-01)"]
    sev = [f.severity for f in findings(sample_scan())]
    assert sev == sorted(sev, key=["critical", "warning", "info"].index)


def test_findings_empty_scan():
    assert findings(Scan()) == []


def test_html_report(tmp_path):
    path = tmp_path / "r.html"
    report.write_html(sample_scan(), path, objects=True, author="Tester")
    html = path.read_text()
    assert "<script>" not in html  # banner text is escaped
    assert "220 FTP server ready &lt;script&gt;" in html
    for text in ("Riverside Office, building A", "Duplicate BACnet device instance", "Tester",
                 "sw-plant-01", "Appendix: object lists", "AI 1 temp", "analog-input 3, binary-value 1",
                 "Switch neighbours (LLDP)", "sw-plant-01 Gi1/0/5 (VLAN 20)", "WS-C2960X-24PS-L"):
        assert text in html
    assert not re.search(r"(src|href)=\"https?:", html)  # self-contained
    assert "Appendix" not in report.build_html(sample_scan())


def test_pdf_report(tmp_path):
    path = tmp_path / "r.pdf"
    report.write_pdf(sample_scan(), path, objects=True)
    data = path.read_bytes()
    assert data.startswith(b"%PDF")
    assert len(re.findall(rb"/Type\s*/Page\b", data)) >= 2


def test_cli_report(tmp_path, capsys):
    db = tmp_path / "t.db"
    with Store(db) as st:
        st.save(sample_scan())
    assert cli_main(["--db", str(db), "scans", "report", "latest", "-o", str(tmp_path / "x.html")]) == 0
    assert "2 critical" in capsys.readouterr().out
    assert cli_main(["--db", str(db), "scans", "report", "7", "-o", str(tmp_path / "x.pdf")]) == 0
    assert (tmp_path / "x.pdf").stat().st_size > 1000
    assert cli_main(["--db", str(db), "scans", "report", "7", "-o", str(tmp_path / "x.txt")]) == 1


def test_duplicate_instance_detected(port_pair):
    sim_a, scan_port = port_pair
    sim_b = scan_port + 50  # outside the fixture's range of fresh ports

    async def main():
        a = build_app(f"127.0.0.1/32:{sim_a}", 1001, 1)
        b = build_app(f"127.0.0.1/32:{sim_b}", 1001, 1)
        try:
            await asyncio.sleep(0.2)
            cfg = ScanConfig(bind_address=f"127.0.0.1/32:{scan_port}", broadcast=False,
                             targets=[f"127.0.0.1:{sim_a}", f"127.0.0.1:{sim_b}"], whois_timeout=0.8,
                             level="device", apdu_timeout=1.0, retries=0, network_info=False)
            return await Scanner(cfg).run()
        finally:
            a.close()
            b.close()

    scan = asyncio.run(main())
    assert len(scan.devices) == 1
    d = scan.devices[0]
    assert any(e.startswith(DUPLICATE_PREFIX) for e in d.errors)
    assert d.status == "done"  # the duplicate note alone does not make the read partial
    assert findings(scan)[0].title == "Duplicate BACnet device instance"
