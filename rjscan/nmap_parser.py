from dataclasses import dataclass, field
from typing import List
import xml.etree.ElementTree as ET


@dataclass
class ScriptResult:
    script_id: str
    output: str


@dataclass
class PortInfo:
    port: int
    protocol: str
    service: str
    product: str
    version: str
    extrainfo: str
    scripts: List[ScriptResult] = field(default_factory=list)


@dataclass
class HostInfo:
    address: str
    ports: List[PortInfo]


def parse_nmap_xml(path: str) -> List[HostInfo]:
    tree = ET.parse(path)
    root = tree.getroot()
    hosts: List[HostInfo] = []
    for host in root.findall("host"):
        addr_node = host.find("address")
        if addr_node is None:
            continue
        address = addr_node.get("addr", "")
        ports: List[PortInfo] = []
        ports_node = host.find("ports")
        if ports_node is None:
            hosts.append(HostInfo(address=address, ports=ports))
            continue
        for port_node in ports_node.findall("port"):
            portid = int(port_node.get("portid", "0"))
            protocol = port_node.get("protocol", "")
            service_node = port_node.find("service")
            service = service_node.get("name", "") if service_node is not None else ""
            product = service_node.get("product", "") if service_node is not None else ""
            version = service_node.get("version", "") if service_node is not None else ""
            extrainfo = service_node.get("extrainfo", "") if service_node is not None else ""
            scripts: List[ScriptResult] = []
            for script_node in port_node.findall("script"):
                scripts.append(
                    ScriptResult(
                        script_id=script_node.get("id", ""),
                        output=script_node.get("output", ""),
                    )
                )
            ports.append(
                PortInfo(
                    port=portid,
                    protocol=protocol,
                    service=service,
                    product=product,
                    version=version,
                    extrainfo=extrainfo,
                    scripts=scripts,
                )
            )
        hosts.append(HostInfo(address=address, ports=ports))
    return hosts
