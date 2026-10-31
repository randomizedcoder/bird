#!/usr/bin/env python3
"""Hand-built, well-formed seed inputs for the BIRD fuzz harnesses.

Usage: gen_seeds.py OUTDIR

Writes OUTDIR/fuzz_<harness>/<name> for fuzz_bgp_msg, fuzz_bgp_open and
fuzz_flowspec (fuzz_config seeds are BIRD's own config files, copied by
fuzz.nix). Each seed starts with the harness's control byte (see the
harness sources).

The bgp_msg seeds match the session fuzz_bgp_common.h negotiates: AS4,
ADD-PATH on every channel that has `add paths on` (unicast, multicast,
labeled unicast, VPN unicast), none on VPN multicast, flowspec and EVPN.
"""

import os
import struct
import sys

# ── BGP constants ──────────────────────────────────────────────────────
AFI_IPV4, AFI_IPV6, AFI_L2VPN = 1, 2, 25
SAFI_UNICAST, SAFI_MULTICAST, SAFI_MPLS = 1, 2, 4
SAFI_EVPN, SAFI_MPLS_VPN, SAFI_VPN_MC, SAFI_FLOW = 70, 128, 129, 133

# (afi, safi) -> whether ADD-PATH RX is negotiated
ADD_PATH = {
    (AFI_IPV4, SAFI_UNICAST): True, (AFI_IPV6, SAFI_UNICAST): True,
    (AFI_IPV4, SAFI_MULTICAST): True, (AFI_IPV6, SAFI_MULTICAST): True,
    (AFI_IPV4, SAFI_MPLS): True, (AFI_IPV6, SAFI_MPLS): True,
    (AFI_IPV4, SAFI_MPLS_VPN): True, (AFI_IPV6, SAFI_MPLS_VPN): True,
    (AFI_IPV4, SAFI_VPN_MC): False, (AFI_IPV6, SAFI_VPN_MC): False,
    (AFI_IPV4, SAFI_FLOW): False, (AFI_IPV6, SAFI_FLOW): False,
    (AFI_L2VPN, SAFI_EVPN): False,
}

# Harness control bytes (fuzz_bgp_msg.c)
EBGP_UPDATE, IBGP_UPDATE = 0x00, 0x01
EBGP_REFRESH, IBGP_REFRESH = 0x04, 0x05
EBGP_RAW, IBGP_RAW = 0x06, 0x07

PEER_AS = 65001
LOCAL_AS = 65000

NH4 = bytes([192, 0, 2, 2])
NH6 = bytes.fromhex('20010db8000000000000000000000002')
LL6 = bytes.fromhex('fe800000000000000000000000000002')
RD0 = struct.pack('>HHI', 0, 65000, 100)        # type 0: ASN2:num
RD1 = struct.pack('>H', 1) + bytes([192, 0, 2, 1]) + struct.pack('>H', 7)
RD2 = struct.pack('>HIH', 2, 4200000000, 9)     # type 2: ASN4:num


def attr(code, value, flags=None):
    """One path attribute; picks the extended-length flag as needed."""
    if flags is None:
        flags = 0x40
    if len(value) > 255:
        flags |= 0x10
    if flags & 0x10:
        return bytes([flags, code]) + struct.pack('>H', len(value)) + value
    return bytes([flags, code, len(value)]) + value


def origin(v=0):
    return attr(1, bytes([v]))


def as_path(asns, seg=2):
    return attr(2, bytes([seg, len(asns)]) + b''.join(struct.pack('>I', a) for a in asns))


def next_hop(ip=NH4):
    return attr(3, ip)


def med(v):
    return attr(4, struct.pack('>I', v), 0x80)


def local_pref(v):
    return attr(5, struct.pack('>I', v))


def update(withdrawn=b'', attrs=b'', nlri=b''):
    return struct.pack('>H', len(withdrawn)) + withdrawn + \
        struct.pack('>H', len(attrs)) + attrs + nlri


def pfx4(text, plen, path_id=None):
    """IPv4 NLRI: [path id] pxlen prefix-bytes."""
    a = bytes(int(x) for x in text.split('.'))
    b = a[:(plen + 7) // 8]
    pid = struct.pack('>I', path_id) if path_id is not None else b''
    return pid + bytes([plen]) + b


def pfx6(hexaddr, plen, path_id=None):
    a = bytes.fromhex(hexaddr)
    b = a[:(plen + 7) // 8]
    pid = struct.pack('>I', path_id) if path_id is not None else b''
    return pid + bytes([plen]) + b


def label(v, bos=True):
    return struct.pack('>I', (v << 4) | (1 if bos else 0))[1:]


def labeled(prefix_bytes, plen, labels, path_id=None):
    """RFC 8277 labeled NLRI: pxlen counts label bits."""
    stack = b''.join(label(l, i == len(labels) - 1) for i, l in enumerate(labels))
    pid = struct.pack('>I', path_id) if path_id is not None else b''
    return pid + bytes([plen + 24 * len(labels)]) + stack + prefix_bytes[:(plen + 7) // 8]


def vpn(prefix_bytes, plen, rd, lbl=100, path_id=None):
    pid = struct.pack('>I', path_id) if path_id is not None else b''
    return pid + bytes([plen + 24 + 64]) + label(lbl) + rd + prefix_bytes[:(plen + 7) // 8]


def mp_reach(afi, safi, nh, nlri):
    v = struct.pack('>HB', afi, safi) + bytes([len(nh)]) + nh + b'\x00' + nlri
    return attr(14, v, 0x80)


def mp_unreach(afi, safi, nlri):
    return attr(15, struct.pack('>HB', afi, safi) + nlri, 0x80)


def ebgp_base():
    return origin(0) + as_path([PEER_AS, 64512, 4200000000])


def ibgp_base():
    return origin(0) + attr(2, b'') + local_pref(100)    # empty AS_PATH


# ── Flowspec components (shared by bgp_msg and flowspec seeds) ─────────
def flow4_components():
    """dst 10.0.0.0/8, proto =6, dst port =80 or >=1024, tcp flags SYN."""
    return (bytes([1, 8, 10]) +
            bytes([3, 0x81, 6]) +
            bytes([5, 0x11, 0x00, 0x50, 0x93, 0x04, 0x00]) +
            bytes([9, 0x81, 0x02]))


def flow4_full():
    """One of every IPv4 component type, in order."""
    return (bytes([1, 24, 192, 0, 2]) +             # dst prefix
            bytes([2, 16, 198, 51]) +               # src prefix
            bytes([3, 0x01, 6, 0x81, 17]) +         # proto 6 or 17
            bytes([4, 0x13, 0x00, 0x16, 0xd5, 0x00, 0x19]) +  # port >=22 && <=25
            bytes([5, 0x91, 0x01, 0xbb]) +          # dst port 443
            bytes([6, 0x92, 0x04, 0x00]) +          # src port >1024
            bytes([7, 0x81, 8]) +                   # icmp type 8
            bytes([8, 0x81, 0]) +                   # icmp code 0
            bytes([9, 0x91, 0x00, 0x12]) +          # tcp flags SYN|ACK
            bytes([10, 0x94, 0x05, 0xdc]) +         # pkt len < 1500
            bytes([11, 0x81, 46]) +                 # dscp 46
            bytes([12, 0x82, 0x01]))                # fragment: not DF


def flow6_components():
    """dst 2001:db8::/32 (offset 0), next header =17, flow label =1."""
    return (bytes([1, 32, 0]) + bytes.fromhex('20010db8') +
            bytes([3, 0x81, 17]) +
            bytes([13, 0xa1, 0x00, 0x00, 0x00, 0x01]))


def flow6_offset():
    """dst prefix with a non-zero offset: bits 64..96 of the address."""
    return (bytes([1, 96, 64]) + bytes.fromhex('deadbeef') +
            bytes([2, 48, 0]) + bytes.fromhex('20010db80001'))


def flow_nlri(components):
    n = len(components)
    hdr = bytes([n]) if n < 0xf0 else struct.pack('>H', 0xf000 | n)
    return hdr + components


# ── EVPN NLRI ──────────────────────────────────────────────────────────
ESI = bytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9])


def evpn(rtype, body):
    return bytes([rtype, len(body)]) + body


def evpn_ead():
    return evpn(1, RD0 + ESI + struct.pack('>I', 0) + label(100))


def evpn_mac(ip=None):
    mac = bytes([0x02, 0, 0, 0, 0, 0x01])
    body = RD0 + bytes(10) + struct.pack('>I', 0) + bytes([48]) + mac
    if ip is None:
        body += bytes([0])
    else:
        body += bytes([len(ip) * 8]) + ip
    body += label(1000)
    return evpn(2, body)


def evpn_imet(ip=NH4):
    return evpn(3, RD0 + struct.pack('>I', 0) + bytes([len(ip) * 8]) + ip)


def evpn_es():
    return evpn(4, RD0 + ESI + bytes([32]) + NH4)


def pmsi_ingress_replication(ip=NH4):
    return attr(22, bytes([0, 6]) + label(1000) + ip, 0xc0)


# ── Seed sets ──────────────────────────────────────────────────────────
def bgp_msg_seeds():
    s = {}

    # IPv4 unicast, classic encoding, every common attribute.
    rich = (ebgp_base() + next_hop() + med(10) +
            attr(6, b'') +                                          # ATOMIC_AGGREGATE
            attr(7, struct.pack('>I', PEER_AS) + NH4, 0xc0) +       # AGGREGATOR (AS4)
            attr(8, struct.pack('>II', 0xfde80001, 0xffffff01), 0xc0) +  # COMMUNITY
            attr(16, bytes.fromhex('0002fde800000064') +            # EXT COMMUNITY: RT
                 bytes.fromhex('000300000000000a'), 0xc0) +         # + RO
            attr(26, bytes([1, 0, 11]) + struct.pack('>Q', 5), 0x80) +  # AIGP
            attr(32, struct.pack('>III', 65001, 1, 2) +
                 struct.pack('>III', 4200000000, 3, 4), 0xc0) +     # LARGE COMMUNITY
            attr(35, struct.pack('>I', PEER_AS), 0xc0) +            # ONLY_TO_CUSTOMER
            attr(200, b'unknown-transitive', 0xc0))                 # unknown optional
    s['ipv4_rich'] = (EBGP_UPDATE, update(attrs=rich, nlri=pfx4('10.1.0.0', 16, 1) +
                                          pfx4('10.2.3.0', 24, 2) + pfx4('0.0.0.0', 0, 3)))
    s['ipv4_withdraw'] = (EBGP_UPDATE, update(withdrawn=pfx4('10.1.0.0', 16, 1) +
                                              pfx4('10.2.3.0', 24, 2)))
    s['ipv4_eor'] = (EBGP_UPDATE, update())
    # AS_SET is rejected (treat-as-withdraw): keeps that path covered.
    s['ipv4_as_set'] = (EBGP_UPDATE, update(
        attrs=origin(2) + attr(2, bytes([2, 1]) + struct.pack('>I', PEER_AS) +
                               bytes([1, 3]) + struct.pack('>III', 1, 2, 3)) + next_hop(),
        nlri=pfx4('172.16.0.0', 12, 7)))
    # Non-AS4 attributes on an AS4 session are discarded: still parsed.
    s['ipv4_as4_attrs'] = (EBGP_UPDATE, update(
        attrs=ebgp_base() + next_hop() +
        attr(17, bytes([2, 1]) + struct.pack('>I', 4200000001), 0xc0) +
        attr(18, struct.pack('>I', 4200000001) + NH4, 0xc0),
        nlri=pfx4('10.9.0.0', 16, 9)))
    s['ipv4_ibgp'] = (IBGP_UPDATE, update(
        attrs=ibgp_base() + next_hop(bytes([192, 0, 2, 3])) +
        attr(9, bytes([192, 0, 2, 99]), 0x80) +                     # ORIGINATOR_ID
        attr(10, bytes([192, 0, 2, 100, 192, 0, 2, 101]), 0x80),    # CLUSTER_LIST
        nlri=pfx4('10.50.0.0', 16, 1)))
    # IPv4 NLRI with an IPv6 next hop (RFC 8950 extended next hop).
    s['ipv4_ext_nh'] = (EBGP_UPDATE, update(attrs=ebgp_base() + mp_reach(
        AFI_IPV4, SAFI_UNICAST, NH6 + LL6, pfx4('10.60.0.0', 16, 1))))

    # IPv6 unicast: global, link-local only, global + link-local.
    for name, nh in (('ipv6_global', NH6), ('ipv6_ll', LL6), ('ipv6_global_ll', NH6 + LL6)):
        s[name] = (EBGP_UPDATE, update(attrs=ebgp_base() + mp_reach(
            AFI_IPV6, SAFI_UNICAST, nh,
            pfx6('20010db8000100000000000000000000', 48, 1) +
            pfx6('20010db8000200030000000000000000', 64, 2))))
    s['ipv6_withdraw'] = (EBGP_UPDATE, update(attrs=mp_unreach(
        AFI_IPV6, SAFI_UNICAST, pfx6('20010db8000100000000000000000000', 48, 1))))
    s['ipv6_eor'] = (EBGP_UPDATE, update(attrs=mp_unreach(AFI_IPV6, SAFI_UNICAST, b'')))

    # Multicast SAFI.
    s['ipv4_mc'] = (EBGP_UPDATE, update(attrs=ebgp_base() + mp_reach(
        AFI_IPV4, SAFI_MULTICAST, NH4, pfx4('198.51.100.0', 24, 1))))
    s['ipv6_mc'] = (EBGP_UPDATE, update(attrs=ebgp_base() + mp_reach(
        AFI_IPV6, SAFI_MULTICAST, NH6, pfx6('20010db8005100000000000000000000', 48, 1))))

    # Labeled unicast (RFC 8277): one label, a stack, and a withdraw.
    s['ipv4_mpls'] = (EBGP_UPDATE, update(attrs=ebgp_base() + mp_reach(
        AFI_IPV4, SAFI_MPLS, NH4,
        labeled(bytes([10, 70, 0, 0]), 16, [100], 1) +
        labeled(bytes([10, 71, 0, 0]), 24, [200, 300, 400], 2))))
    s['ipv6_mpls'] = (EBGP_UPDATE, update(attrs=ebgp_base() + mp_reach(
        AFI_IPV6, SAFI_MPLS, NH6,
        labeled(bytes.fromhex('20010db80070'), 48, [3], 1))))
    # Withdraw with the RFC 8277 compatibility label 0x800000.
    s['ipv4_mpls_withdraw'] = (EBGP_UPDATE, update(attrs=mp_unreach(
        AFI_IPV4, SAFI_MPLS, struct.pack('>I', 1) + bytes([16 + 24, 0x80, 0, 0, 10, 70]))))

    # L3VPN (RFC 4364): every RD type, v4 and v6 next hops.
    vpnattrs = ebgp_base() + attr(16, bytes.fromhex('0002fde800000064'), 0xc0)
    s['vpn4'] = (EBGP_UPDATE, update(attrs=vpnattrs + mp_reach(
        AFI_IPV4, SAFI_MPLS_VPN, bytes(8) + NH4,
        vpn(bytes([10, 80, 0, 0]), 16, RD0, 100, 1) +
        vpn(bytes([10, 81, 0, 0]), 24, RD1, 101, 2) +
        vpn(bytes([10, 82, 0, 0]), 32, RD2, 102, 3))))
    s['vpn6'] = (EBGP_UPDATE, update(attrs=vpnattrs + mp_reach(
        AFI_IPV6, SAFI_MPLS_VPN, bytes(8) + NH6 + bytes(8) + LL6,
        vpn(bytes.fromhex('20010db80080'), 48, RD0, 200, 1))))
    s['vpn4_mc'] = (EBGP_UPDATE, update(attrs=vpnattrs + mp_reach(
        AFI_IPV4, SAFI_VPN_MC, bytes(8) + NH4,
        bytes([64 + 16]) + RD0 + bytes([10, 85]))))
    s['vpn6_mc'] = (EBGP_UPDATE, update(attrs=vpnattrs + mp_reach(
        AFI_IPV6, SAFI_VPN_MC, bytes(8) + NH6,
        bytes([64 + 32]) + RD0 + bytes.fromhex('20010db8'))))

    # VPN multicast carries no label: pxlen = RD (64) + prefix bits.

    # Flowspec (no next hop, no ADD-PATH), with a traffic-rate ext community.
    flowattrs = ebgp_base() + attr(16, bytes.fromhex('8006fde900000000'), 0xc0)
    s['flow4'] = (EBGP_UPDATE, update(attrs=flowattrs + mp_reach(
        AFI_IPV4, SAFI_FLOW, b'', flow_nlri(flow4_components()) + flow_nlri(flow4_full()))))
    s['flow6'] = (EBGP_UPDATE, update(attrs=flowattrs + mp_reach(
        AFI_IPV6, SAFI_FLOW, b'', flow_nlri(flow6_components()) + flow_nlri(flow6_offset()))))
    s['flow4_withdraw'] = (EBGP_UPDATE, update(attrs=mp_unreach(
        AFI_IPV4, SAFI_FLOW, flow_nlri(flow4_components()))))

    # EVPN (RFC 7432): every route type, with PMSI tunnel and ESI label.
    evattrs = (ebgp_base() + pmsi_ingress_replication() +
               attr(16, bytes.fromhex('0002fde800000064') +
                    bytes.fromhex('0601000000000000'), 0xc0))      # RT + ESI label
    s['evpn_all'] = (EBGP_UPDATE, update(attrs=evattrs + mp_reach(
        AFI_L2VPN, SAFI_EVPN, NH4,
        evpn_ead() + evpn_mac() + evpn_mac(NH4) + evpn_mac(NH6) +
        evpn_imet() + evpn_imet(NH6) + evpn_es() + evpn(5, RD0 + bytes(30)))))
    s['evpn_withdraw'] = (EBGP_UPDATE, update(attrs=mp_unreach(
        AFI_L2VPN, SAFI_EVPN, evpn_imet())))

    # Two MP attributes in one UPDATE: reach for v6, unreach for v4 mpls.
    s['mp_mixed'] = (EBGP_UPDATE, update(
        attrs=ebgp_base() + next_hop() + mp_reach(AFI_IPV6, SAFI_UNICAST, NH6,
                                     pfx6('20010db8009000000000000000000000', 40, 4)) +
        mp_unreach(AFI_IPV4, SAFI_MPLS, labeled(bytes([10, 70, 0, 0]), 16, [0], 1)),
        nlri=pfx4('10.90.0.0', 16, 4)))

    # ROUTE-REFRESH: plain, BoRR, EoRR (RFC 7313), and an unknown subtype.
    for name, (afi, sub, safi) in {
        'rr_ipv4': (AFI_IPV4, 0, SAFI_UNICAST),
        'rr_ipv6_borr': (AFI_IPV6, 1, SAFI_UNICAST),
        'rr_ipv6_eorr': (AFI_IPV6, 2, SAFI_UNICAST),
        'rr_evpn': (AFI_L2VPN, 0, SAFI_EVPN),
        'rr_flow4_badsub': (AFI_IPV4, 7, SAFI_FLOW),
    }.items():
        s[name] = (EBGP_REFRESH, struct.pack('>HBB', afi, sub, safi))

    # Raw stream: KEEPALIVE, an UPDATE, a NOTIFICATION (Cease).
    def msg(t, body):
        return b'\xff' * 16 + struct.pack('>HB', 19 + len(body), t) + body
    s['raw_stream'] = (EBGP_RAW, msg(4, b'') + msg(2, s['ipv4_rich'][1]) + msg(4, b''))
    s['raw_notification'] = (IBGP_RAW, msg(3, bytes([6, 2]) + b'shutdown'))

    return s


def bgp_open_body(asn, bgp_id, caps, hold=240, extended=False):
    """OPEN body (no header): version, AS, hold, id, optional parameters."""
    body = bytes([4]) + struct.pack('>HHI', asn if asn <= 0xffff else 23456, hold, bgp_id)
    if extended:
        param = bytes([2]) + struct.pack('>H', len(caps)) + caps
        return body + bytes([255, 255]) + struct.pack('>H', len(param)) + param
    param = bytes([2, len(caps)]) + caps
    return body + bytes([len(param)]) + param


def cap(code, value=b''):
    return bytes([code, len(value)]) + value


def bgp_open_seeds():
    afs = list(ADD_PATH)
    mp = b''.join(cap(1, struct.pack('>HBB', a, 0, s)) for a, s in afs)
    gr = cap(64, struct.pack('>H', 120) + b''.join(struct.pack('>HBB', a, s, 0x80) for a, s in afs))
    llgr = cap(71, b''.join(struct.pack('>HBB', a, s, 0x80) + struct.pack('>I', 3600)[1:]
                            for a, s in afs))
    ap = cap(69, b''.join(struct.pack('>HBB', a, s, 3) for a, s in afs))
    as4 = cap(65, struct.pack('>I', PEER_AS))
    host = cap(73, bytes([4]) + b'peer' + bytes([7]) + b'example')
    enh = cap(5, struct.pack('>HHH', AFI_IPV4, SAFI_UNICAST, AFI_IPV6) +
              struct.pack('>HHH', AFI_IPV4, SAFI_MPLS_VPN, AFI_IPV6))
    full = mp + cap(2) + cap(70) + cap(6) + enh + gr + as4 + ap + llgr + host

    mp4 = cap(1, struct.pack('>HBB', AFI_IPV4, 0, SAFI_UNICAST))
    mp6 = cap(1, struct.pack('>HBB', AFI_IPV6, 0, SAFI_UNICAST))
    base = mp4 + mp6 + as4

    ctl = 0x00
    s = {
        'open_full_rfc9072': (ctl, bgp_open_body(PEER_AS, 0xc0000202, full, extended=True)),
        'open_minimal': (ctl, bgp_open_body(PEER_AS, 0xc0000202, base)),
        'open_role_peer': (ctl, bgp_open_body(PEER_AS, 0xc0000202, base + cap(9, bytes([2])))),
        'open_gr_restart': (ctl, bgp_open_body(PEER_AS, 0xc0000202, base + cap(
            64, struct.pack('>H', 0x8078) + struct.pack('>HBB', AFI_IPV4, SAFI_UNICAST, 0x80)))),
        'open_no_caps': (ctl, bytes([4]) + struct.pack('>HHI', PEER_AS, 90, 0xc0000202) + b'\x00'),
        'open_hold_0': (ctl, bgp_open_body(PEER_AS, 0xc0000202, base, hold=0)),
        'open_as_trans': (ctl, bgp_open_body(4200000000, 0xc0000202,
                                             mp4 + cap(65, struct.pack('>I', 4200000000)))),
        'open_unknown_cap': (ctl, bgp_open_body(PEER_AS, 0xc0000202, base + cap(128, b'\x01\x02\x03'))),
        'open_two_params': (ctl, bytes([4]) + struct.pack('>HHI', PEER_AS, 180, 0xc0000202) +
                            bytes([2 + len(mp4) + 2 + len(as4)]) +
                            bytes([2, len(mp4)]) + mp4 + bytes([2, len(as4)]) + as4),
    }
    raw_open = bgp_open_body(PEER_AS, 0xc0000202, base)
    s['open_raw_framed'] = (0x01, b'\xff' * 16 + struct.pack('>HB', 19 + len(raw_open), 1) + raw_open)
    return s


def flowspec_seeds():
    return {
        'flow4_basic': (0x00, flow4_components()),
        'flow4_full': (0x00, flow4_full()),
        'flow4_dst_only': (0x00, bytes([1, 32, 192, 0, 2, 1])),
        'flow4_unnormalized': (0x00, bytes([1, 20, 10, 0xff, 0xff])),   # host bits set
        'flow6_basic': (0x01, flow6_components()),
        'flow6_offset': (0x01, flow6_offset()),
        'flow6_full': (0x01, bytes([1, 64, 0]) + bytes.fromhex('20010db800000001') +
                       bytes([3, 0x81, 58, 7, 0x81, 128, 8, 0x81, 0, 13, 0xa4, 0, 0x0f, 0xff, 0xff])),
    }


def write(outdir, harness, seeds):
    d = os.path.join(outdir, harness)
    os.makedirs(d, exist_ok=True)
    for name, (ctl, body) in sorted(seeds.items()):
        with open(os.path.join(d, name), 'wb') as f:
            f.write(bytes([ctl]) + body)
    return len(seeds)


def main():
    if len(sys.argv) != 2:
        sys.exit('usage: gen_seeds.py OUTDIR')
    out = sys.argv[1]
    n = write(out, 'fuzz_bgp_msg', bgp_msg_seeds())
    n += write(out, 'fuzz_bgp_open', bgp_open_seeds())
    n += write(out, 'fuzz_flowspec', flowspec_seeds())
    print(f'gen_seeds: wrote {n} seeds to {out}')


if __name__ == '__main__':
    main()
