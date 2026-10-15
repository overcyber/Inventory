import socket
import struct

from services.netscope_passive import parse_frame


def eth(dst, src, etype, payload):
    mac = lambda s: bytes.fromhex(s.replace(':', ''))
    return mac(dst) + mac(src) + struct.pack('!H', etype) + payload


def ipv4(src, dst, proto, l4=b''):
    srcb = socket.inet_aton(src); dstb = socket.inet_aton(dst)
    total = 20 + len(l4)
    hdr = struct.pack('!BBHHHBBH4s4s',
                      0x45, 0, total, 1, 0, 64, proto, 0, srcb, dstb)
    return hdr + l4


def test_parse_ipv4_tcp_keeps_ethernet_next_hop():
    tcp = struct.pack('!HH', 50123, 443) + b'\x00' * 16
    frame = eth('aa:bb:cc:dd:ee:ff', '00:11:22:33:44:55', 0x0800,
                ipv4('192.168.1.20', '8.8.8.8', 6, tcp))
    p = parse_frame(frame)
    assert p['src_ip'] == '192.168.1.20'
    assert p['dst_ip'] == '8.8.8.8'
    assert p['src_mac'] == '00:11:22:33:44:55'
    assert p['dst_mac'] == 'aa:bb:cc:dd:ee:ff'
    assert p['protocol'] == 'TCP'
    assert p['src_port'] == 50123
    assert p['dst_port'] == 443


def test_parse_vlan_preserves_vlan_id():
    udp = struct.pack('!HHHH', 12345, 53, 8, 0)
    inner = ipv4('192.168.10.23', '192.168.10.1', 17, udp)
    mac = lambda s: bytes.fromhex(s.replace(':', ''))
    frame = (
        mac('38:91:48:4f:1a:97') + mac('1c:bf:59:92:7a:3c') +
        struct.pack('!H', 0x8100) + struct.pack('!HH', 37, 0x0800) + inner
    )
    p = parse_frame(frame)
    assert p['vlan'] == '37'
    assert p['protocol'] == 'UDP'
    assert p['dst_port'] == 53


def test_parse_arp_reply():
    sender_mac = bytes.fromhex('001122334455')
    target_mac = bytes.fromhex('aabbccddeeff')
    arp = struct.pack('!HHBBH', 1, 0x0800, 6, 4, 2)
    arp += sender_mac + socket.inet_aton('192.168.1.20')
    arp += target_mac + socket.inet_aton('192.168.1.100')
    frame = eth('aa:bb:cc:dd:ee:ff', '00:11:22:33:44:55', 0x0806, arp)
    p = parse_frame(frame)
    assert p['protocol'] == 'ARP'
    assert p['arp_op'] == 2
    assert p['arp_sender_ip'] == '192.168.1.20'
    assert p['arp_sender_mac'] == '00:11:22:33:44:55'


def test_parse_dhcp_ack_identity():
    bootp = bytearray(240)
    bootp[0] = 2  # BOOTREPLY
    bootp[1] = 1
    bootp[2] = 6
    bootp[16:20] = socket.inet_aton('192.168.1.45')
    bootp[28:34] = bytes.fromhex('807d3a784d67')
    bootp[236:240] = b'\x63\x82\x53\x63'
    opts = bytes([53, 1, 5, 51, 4]) + struct.pack('!I', 3600) + bytes([255])
    udp_payload = bytes(bootp) + opts
    udp = struct.pack('!HHHH', 67, 68, 8 + len(udp_payload), 0) + udp_payload
    frame = eth('ff:ff:ff:ff:ff:ff', '38:91:48:4f:1a:97', 0x0800,
                ipv4('192.168.1.1', '255.255.255.255', 17, udp))
    p = parse_frame(frame)
    assert p['dhcp']['message_type'] == 5
    assert p['dhcp']['ip'] == '192.168.1.45'
    assert p['dhcp']['client_mac'] == '80:7d:3a:78:4d:67'
    assert p['dhcp']['lease_seconds'] == 3600
