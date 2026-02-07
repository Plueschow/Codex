from pathlib import Path

from rjscan.nmap_parser import parse_nmap_xml


def test_parse_nmap_xml():
    path = Path(__file__).parent / "fixtures" / "sample_nmap.xml"
    hosts = parse_nmap_xml(str(path))
    assert hosts[0].address == "192.168.1.10"
    assert hosts[0].ports[0].port == 1099
    assert hosts[0].ports[0].service == "rmiregistry"
    assert hosts[0].ports[0].scripts[0].script_id == "rmi-dumpregistry"
