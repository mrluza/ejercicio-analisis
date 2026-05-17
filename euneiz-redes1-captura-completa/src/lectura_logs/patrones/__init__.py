from .connPatron import connPatron
from .pcapLivePatron import pcapLivePatron
from .curso_2025.arpPatron import arpPatron
from .curso_2025.dnsPatron import dnsPatron
from .curso_2025.tcpPatron import tcpPatron
from .curso_2025.httpPatron import httpPatron
from .curso_2025.dhcpPatron import dhcpPatron
from .curso_2025.icmpPatron import icmpPatron
from .curso_2025.tlsPatron import tlsPatron
from .curso_2025.mdnsPatron import mdnsPatron

PATRONES_DISPONIBLES = {
    'conn': connPatron,
    'pcap_live': pcapLivePatron,
    'arp': arpPatron,
    'dns': dnsPatron,
    'tcp': tcpPatron,
    'http': httpPatron,
    'dhcp': dhcpPatron,
    'icmp': icmpPatron,
    'tls': tlsPatron,
    'mdns': mdnsPatron
}
