#!/usr/bin/env python3
"""Hand-built, well-formed seed inputs for the BIRD fuzz harnesses.

Usage: gen_seeds.py OUTDIR

Writes OUTDIR/fuzz_<harness>/<name> for every harness except fuzz_config (fuzz_config seeds are BIRD's own config files, copied by
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


# ── Babel (fuzz_babel.c) ───────────────────────────────────────────────
# Control byte: bit 0 b_auth, bit 1 unicast dst, bit 2 second neighbour,
# bit 3 raw packet (header included), bit 4 advance the clock afterwards
# (time byte added by write()).
BABEL_PLAIN, BABEL_AUTH, BABEL_UNICAST, BABEL_RAW, BABEL_TIMERS = 0, 1, 2, 8, 16


def btlv(t, body):
    return bytes([t, len(body)]) + body


def b_hello(seqno=1, interval=400, flags=0, sub=b''):
    return btlv(4, struct.pack('>HHH', flags, seqno, interval) + sub)


def b_tstamp(ts, rcvd=None):
    body = struct.pack('>I', ts) + (struct.pack('>I', rcvd) if rcvd is not None else b'')
    return btlv(3, body)


def b_ihu(ae, addr, rxcost=96, interval=1200, sub=b''):
    return btlv(5, bytes([ae, 0]) + struct.pack('>HH', rxcost, interval) + addr + sub)


def b_router_id(rid):
    return btlv(6, b'\0\0' + struct.pack('>Q', rid))


def b_next_hop(ae, addr):
    return btlv(7, bytes([ae, 0]) + addr)


def b_update(ae, plen, prefix, metric=96, seqno=1, flags=0, omitted=0, interval=1600, sub=b''):
    return btlv(8, bytes([ae, flags, plen, omitted]) +
                struct.pack('>HHH', interval, seqno, metric) + prefix + sub)


def b_route_req(ae, plen, prefix=b'', sub=b''):
    return btlv(9, bytes([ae, plen]) + prefix + sub)


def b_seqno_req(ae, plen, prefix, rid, seqno=2, hops=16, sub=b''):
    return btlv(10, bytes([ae, plen]) + struct.pack('>HBBQ', seqno, hops, 0, rid) + prefix + sub)


def b_src_prefix(plen, prefix):
    return btlv(128, bytes([plen]) + prefix)


def babel_pkt(body, trailer=b''):
    return bytes([42, 2]) + struct.pack('>H', len(body)) + body + trailer


LL6_PEER = bytes.fromhex('0000000000000002')            # AE 3: low 64 bits
LL6_LOCAL = bytes.fromhex('0000000000000001')
IP6_PFX = bytes.fromhex('20010db80100')                  # 2001:db8:100::/48
IP4_PFX = bytes([10, 1])                                 # 10.1.0.0/16
RID = 0x0200000000000002


def babel_seeds():
    hello = b_hello()
    s = {
        'hello': (BABEL_PLAIN, hello),
        'hello_unicast': (BABEL_PLAIN | BABEL_UNICAST, b_hello(flags=0x8000)),
        'hello_tstamp': (BABEL_PLAIN, b_hello(sub=b_tstamp(1000))),
        'hello_ihu': (BABEL_PLAIN, hello + b_ihu(3, LL6_LOCAL)),
        'hello_ihu_tstamp': (BABEL_PLAIN, b_hello(sub=b_tstamp(2000)) +
                             b_ihu(3, LL6_LOCAL, sub=b_tstamp(1500, 1000))),
        'ihu_ip6': (BABEL_PLAIN, b_ihu(2, bytes.fromhex('20010db8000000000000000000000001'))),
        'ihu_wildcard': (BABEL_PLAIN, b_ihu(0, b'')),
        'update_ip6': (BABEL_PLAIN | BABEL_TIMERS, hello + b_ihu(3, LL6_LOCAL) +
                       b_router_id(RID) + b_update(2, 48, IP6_PFX)),
        'update_ip6_nh': (BABEL_PLAIN, b_router_id(RID) +
                          b_next_hop(2, bytes.fromhex('20010db8000000000000000000000002')) +
                          b_update(2, 64, bytes.fromhex('20010db800020000'))),
        'update_ip4': (BABEL_PLAIN, b_router_id(RID) + b_next_hop(1, bytes([10, 0, 0, 2])) +
                       b_update(1, 16, IP4_PFX)),
        'update_ip4_via_ip6': (BABEL_PLAIN, b_router_id(RID) + b_update(4, 24, bytes([10, 2, 0]))),
        'update_compressed': (BABEL_PLAIN, b_router_id(RID) +
                              b_update(2, 64, bytes.fromhex('20010db800030000'), flags=0x80) +
                              b_update(2, 64, bytes.fromhex('0004'), omitted=6)),
        'update_rid_from_prefix': (BABEL_PLAIN, b_update(2, 128, bytes.fromhex(
            '20010db8000000050000000000000001'), flags=0x40)),
        'update_retract': (BABEL_PLAIN, b_router_id(RID) + b_update(2, 48, IP6_PFX, metric=0xffff)),
        'retract_wildcard': (BABEL_PLAIN, b_update(0, 0, b'', metric=0xffff)),
        'route_req': (BABEL_PLAIN | BABEL_UNICAST, b_route_req(2, 48, IP6_PFX)),
        'route_req_wildcard': (BABEL_PLAIN, b_route_req(0, 0)),
        'seqno_req': (BABEL_PLAIN | BABEL_UNICAST, b_seqno_req(2, 48, IP6_PFX, RID)),
        'ack_req': (BABEL_PLAIN | BABEL_UNICAST, btlv(2, struct.pack('>HHH', 0, 0x1234, 100))),
        'padding': (BABEL_PLAIN, bytes([0]) + btlv(1, b'\0\0\0') + hello),
        'neighbour2': (BABEL_PLAIN | 4, hello + b_ihu(3, LL6_LOCAL)),
        'sadr_update': (BABEL_AUTH, hello + b_router_id(RID) +
                        b_update(2, 48, IP6_PFX, sub=b_src_prefix(32, bytes.fromhex('20010db8')))),
        'sadr_route_req': (BABEL_AUTH, b_route_req(2, 48, IP6_PFX,
                                                   sub=b_src_prefix(32, bytes.fromhex('20010db8')))),
        'auth_challenge_req': (BABEL_AUTH | BABEL_UNICAST, btlv(18, bytes(range(8)))),
        'auth_challenge_reply': (BABEL_AUTH | BABEL_UNICAST, btlv(19, bytes(range(8)))),
    }
    # Authenticated packet: TLVs, then a trailer with PC and an HMAC-SHA256 MAC
    # (wrong value; b_auth is permissive, so the TLVs are still processed).
    trailer = btlv(17, struct.pack('>I', 1) + b'idx0') + btlv(16, bytes(32))
    s['auth_pc_mac'] = (BABEL_AUTH | BABEL_RAW, babel_pkt(hello + b_ihu(3, LL6_LOCAL), trailer))
    s['raw_plain'] = (BABEL_PLAIN | BABEL_RAW, babel_pkt(hello))
    return s


# ── RIP (fuzz_rip.c) ───────────────────────────────────────────────────
# Control byte: bits 0-2 instance (0 plain, 1 crypto, 2 plaintext, 3 demand,
# 4 RIPng), bit 3 unicast dst, bit 4 second neighbour, bit 5 advance the
# clock afterwards (time byte added by write()).
RIP_PLAIN, RIP_CRYPTO, RIP_TEXT, RIP_DEMAND, RIP_NG = range(5)
RIP_UNICAST, RIP_NEIGH2, RIP_TIMERS = 8, 16, 32


def rip_hdr(cmd, version=2):
    return bytes([cmd, version, 0, 0])


def rip_v2(prefix, plen, metric=1, nh=b'\0\0\0\0', tag=0, afi=2):
    mask = (0xffffffff << (32 - plen)) & 0xffffffff if plen else 0
    return struct.pack('>HH', afi, tag) + bytes(prefix) + struct.pack('>I', mask) + nh + \
        struct.pack('>I', metric)


def rip_ng(prefix16, plen, metric=1, tag=0):
    return prefix16 + struct.pack('>HBB', tag, plen, metric)


def rip_update_hdr(flush=0, seq=1):
    return bytes([1, flush]) + struct.pack('>H', seq)


def rip_seeds():
    whole_v2 = rip_v2([0, 0, 0, 0], 0, metric=16, afi=0)
    routes = rip_v2([10, 1, 0, 0], 16) + rip_v2([10, 2, 0, 0], 24, metric=3, nh=bytes([10, 0, 0, 3])) + \
        rip_v2([10, 3, 3, 3], 32, metric=16)
    pw = b'fuzz' + bytes(12)
    plain_auth = struct.pack('>HH', 0xffff, 2) + pw
    # RFC 4822: auth block (packet length up to the trailer, key id 1 (the first password), auth
    # data length 4 + 32 for HMAC-SHA256, sequence number), then the trailer.
    resp_body = rip_v2([10, 4, 0, 0], 16)
    crypto_block = struct.pack('>HHHBBIII', 0xffff, 3, 4 + 20 + len(resp_body), 1, 36, 1, 0, 0)
    crypto_tail = struct.pack('>HH', 0xffff, 1) + bytes(32)
    ng_whole = rip_ng(bytes(16), 0, metric=16)
    ng_routes = rip_ng(bytes.fromhex('20010db8010000000000000000000000'), 48) + \
        rip_ng(bytes.fromhex('fe800000000000000000000000000003'), 0, metric=0xff) + \
        rip_ng(bytes.fromhex('20010db8020000000000000000000000'), 64, metric=2)
    return {
        'v2_request_all': (RIP_PLAIN, rip_hdr(1) + whole_v2),
        'v2_request_unicast': (RIP_PLAIN | RIP_UNICAST, rip_hdr(1) + rip_v2([10, 0, 0, 0], 8)),
        'v2_response': (RIP_PLAIN | RIP_TIMERS, rip_hdr(2) + routes),
        'v2_response_neigh2': (RIP_PLAIN | RIP_NEIGH2, rip_hdr(2) + rip_v2([10, 5, 0, 0], 16)),
        'v1_response': (RIP_PLAIN, rip_hdr(2, 1) + rip_v2([10, 6, 0, 0], 0)),
        'text_response': (RIP_TEXT, rip_hdr(2) + plain_auth + routes),
        'text_request': (RIP_TEXT, rip_hdr(1) + plain_auth + whole_v2),
        'crypto_response': (RIP_CRYPTO, rip_hdr(2) + crypto_block + resp_body + crypto_tail),
        'demand_update_request': (RIP_DEMAND, rip_hdr(9) + rip_update_hdr() + whole_v2),
        'demand_update_response': (RIP_DEMAND | RIP_TIMERS, rip_hdr(10) + rip_update_hdr(seq=7) + routes),
        'demand_update_flush': (RIP_DEMAND, rip_hdr(10) + rip_update_hdr(flush=1, seq=8) + routes),
        'demand_ack': (RIP_DEMAND, rip_hdr(11) + rip_update_hdr(seq=1)),
        'ng_request_all': (RIP_NG, rip_hdr(1, 1) + ng_whole),
        'ng_response': (RIP_NG | RIP_TIMERS, rip_hdr(2, 1) + ng_routes),
        'ng_request_unicast': (RIP_NG | RIP_UNICAST, rip_hdr(1, 1) +
                               rip_ng(bytes.fromhex('20010db8010000000000000000000000'), 48)),
    }


# ── RPKI-RTR (fuzz_rpki.c) ─────────────────────────────────────────────
# Control byte: bit 0 synchronized session (id 0x4242, serial 1), bits 1-2
# negotiated version.
RPKI_SESSION = 0x4242


def rpki_ctl(synced, version):
    return (1 if synced else 0) | (version << 1)


def rpki_pdu(ver, ptype, field16, body=b''):
    return struct.pack('>BBHI', ver, ptype, field16, 8 + len(body)) + body


def rpki_cache_response(ver):
    return rpki_pdu(ver, 3, RPKI_SESSION)


def rpki_ipv4(ver, prefix, plen, maxlen, asn, announce=True):
    return rpki_pdu(ver, 4, 0, bytes([1 if announce else 0, plen, maxlen, 0]) + bytes(prefix) +
                    struct.pack('>I', asn))


def rpki_ipv6(ver, prefix16, plen, maxlen, asn, announce=True):
    return rpki_pdu(ver, 6, 0, bytes([1 if announce else 0, plen, maxlen, 0]) + prefix16 +
                    struct.pack('>I', asn))


def rpki_aspa(ver, customer, providers, announce=True):
    body = struct.pack('>I', customer) + b''.join(struct.pack('>I', a) for a in providers)
    return struct.pack('>BBBBI', ver, 11, 1 if announce else 0, 0, 8 + len(body)) + body


def rpki_eod(ver, serial=1):
    body = struct.pack('>I', serial)
    if ver >= 1:
        body += struct.pack('>III', 3600, 600, 7200)
    return rpki_pdu(ver, 7, RPKI_SESSION, body)


def rpki_error(ver, code, enc=b'', text=b''):
    body = struct.pack('>I', len(enc)) + enc + struct.pack('>I', len(text)) + text
    return rpki_pdu(ver, 10, code, body)


def rpki_seeds():
    p4 = rpki_ipv4(1, [192, 0, 2, 0], 24, 24, 64500)
    p6 = rpki_ipv6(1, bytes.fromhex('20010db8000000000000000000000000'), 32, 48, 64500)
    s = {
        'sync_v0': (rpki_ctl(False, 0), rpki_cache_response(0) +
                    rpki_ipv4(0, [198, 51, 100, 0], 24, 28, 64501) + rpki_eod(0)),
        'sync_v1': (rpki_ctl(False, 1), rpki_cache_response(1) + p4 + p6 + rpki_eod(1)),
        'sync_v2_aspa': (rpki_ctl(False, 2), rpki_cache_response(2) + rpki_ipv4(2, [192, 0, 2, 0], 24, 24, 64500) +
                         rpki_aspa(2, 64500, [64501, 64502, 64503]) + rpki_eod(2)),
        'sync_many': (rpki_ctl(False, 1), rpki_cache_response(1) +
                      b''.join(rpki_ipv4(1, [10, i, 0, 0], 16, 24, 64500 + i) for i in range(32)) +
                      rpki_eod(1)),
        'serial_notify': (rpki_ctl(True, 1), rpki_pdu(1, 0, RPKI_SESSION, struct.pack('>I', 2))),
        'incremental': (rpki_ctl(True, 1), rpki_cache_response(1) + p4 +
                        rpki_ipv4(1, [192, 0, 2, 0], 24, 24, 64500, announce=False) + rpki_eod(1, 2)),
        'aspa_withdraw': (rpki_ctl(True, 2), rpki_cache_response(2) +
                          rpki_aspa(2, 64500, [], announce=False) + rpki_eod(2, 2)),
        'cache_reset': (rpki_ctl(True, 1), rpki_pdu(1, 8, 0)),
        'error_no_data': (rpki_ctl(False, 1), rpki_error(1, 2, text=b'no data')),
        'error_encapsulated': (rpki_ctl(False, 1), rpki_error(1, 0, enc=rpki_pdu(1, 2, 0),
                                                              text=b'corrupt data')),
        'version_downgrade': (rpki_ctl(False, 2), rpki_cache_response(1) + p4 + rpki_eod(1)),
        'router_key': (rpki_ctl(True, 1), rpki_pdu(1, 9, 0, bytes(20 + 4 + 64))),
        'eod_session_mismatch': (rpki_ctl(True, 1), rpki_pdu(1, 7, 0x1111, struct.pack('>IIII', 2, 1, 1, 1))),
    }
    return s


# ── netlink (fuzz_netlink.c) ───────────────────────────────────────────
# Control byte: bit 0 route table scan (else async notifications), bits 1-2
# scanning protocol (k4, k6, k4t = table 100, kmpls). Host byte order.
NL_ASYNC, NL_SCAN_K4, NL_SCAN_K6, NL_SCAN_K4T, NL_SCAN_MPLS = 0, 1, 3, 5, 7
AF_INET_, AF_INET6_, AF_MPLS_ = 2, 10, 28
RTM_NEWLINK, RTM_DELLINK, RTM_NEWADDR, RTM_DELADDR = 16, 17, 20, 21
RTM_NEWROUTE, RTM_DELROUTE = 24, 25
FZ0 = 2                                  # fz0's ifindex (fuzz_iface.h)


def nl_pad(b):
    return b + bytes(-len(b) % 4)


def rta(t, data):
    return nl_pad(struct.pack('<HH', 4 + len(data), t) + data)


def nlmsg(t, payload, flags=0, seq=1):
    return nl_pad(struct.pack('<IHHII', 16 + len(payload), t, flags, seq, 0) + payload)


def rtmsg(family, dst_len, table=254, proto=3, scope=0, rtype=1, flags=0):
    return struct.pack('<BBBBBBBBI', family, dst_len, 0, 0, table, proto, scope, rtype, flags)


def u32le(v):
    return struct.pack('<I', v)


def mpls_label(v, bos=True):
    return struct.pack('>I', (v << 12) | (0x100 if bos else 0) | 0xff)


def rtnh(ifindex, attrs=b'', hops=0, flags=0):
    return nl_pad(struct.pack('<HBBi', 8 + len(attrs), flags, hops, ifindex) + attrs)


def nl_route4(dst, plen, gw=None, oif=FZ0, table=254, extra=b'', msg=RTM_NEWROUTE, proto=3):
    attrs = rta(15, u32le(table)) + rta(1, bytes(dst)) + rta(4, u32le(oif))
    if gw:
        attrs += rta(5, bytes(gw))
    return nlmsg(msg, rtmsg(AF_INET_, plen, table=min(table, 255), proto=proto) + attrs + extra)


def nl_route6(dst16, plen, gw16=None, oif=FZ0, extra=b'', msg=RTM_NEWROUTE):
    attrs = rta(15, u32le(254)) + rta(1, dst16) + rta(4, u32le(oif))
    if gw16:
        attrs += rta(5, gw16)
    return nlmsg(msg, rtmsg(AF_INET6_, plen) + attrs + extra)


def ifinfo(index, flags, family=0):
    return struct.pack('<BBHiII', family, 0, 1, index, flags, 0xffffffff)


def nl_link(index, name, flags=0x11043, mtu=1500, extra=b'', msg=RTM_NEWLINK):
    return nlmsg(msg, ifinfo(index, flags) + rta(3, name + b'\0') + rta(4, u32le(mtu)) + extra)


def nl_addr(family, plen, index, addr, extra=b'', msg=RTM_NEWADDR, scope=0):
    return nlmsg(msg, struct.pack('<BBBBI', family, plen, 0, scope, index) +
                 rta(2, addr) + rta(1, addr) + extra)


def netlink_seeds():
    gw4 = [10, 0, 0, 2]
    gw6 = bytes.fromhex('fe800000000000000000000000000002')
    p6 = bytes.fromhex('20010db8010000000000000000000000')
    multipath4 = rta(9, rtnh(FZ0, rta(5, bytes([10, 0, 0, 2]))) + rtnh(FZ0, rta(5, bytes([10, 0, 0, 3])), hops=1))
    multipath6 = rta(9, rtnh(FZ0, rta(5, gw6)) +
                     rtnh(FZ0, rta(5, bytes.fromhex('fe800000000000000000000000000003'))))
    metrics = rta(8, rta(2, u32le(1400)) + rta(10, u32le(64)) + rta(4, u32le(10)))
    encap_mpls = rta(21, struct.pack('<H', 1)) + rta(22, rta(1, mpls_label(100, False) + mpls_label(200)))
    via6 = rta(18, struct.pack('<H', AF_INET6_) + gw6)
    vxlan = rta(18, rta(1, b'vxlan\0') + rta(2, rta(1, u32le(42)) + rta(4, bytes([10, 0, 0, 1])) +
                                         rta(7, b'\x01')))
    mpls_route = nlmsg(RTM_NEWROUTE, rtmsg(AF_MPLS_, 20) + rta(1, mpls_label(1000)) +
                       rta(19, mpls_label(2000)) + rta(18, struct.pack('<H', AF_INET_) + bytes(gw4)) +
                       rta(4, u32le(FZ0)))
    return {
        'route4_async': (NL_ASYNC, nl_route4([10, 9, 0, 0], 16, gw4)),
        'route4_del_async': (NL_ASYNC, nl_route4([10, 9, 0, 0], 16, gw4) +
                             nl_route4([10, 9, 0, 0], 16, gw4, msg=RTM_DELROUTE)),
        'route4_scan': (NL_SCAN_K4, nl_route4([10, 9, 0, 0], 16, gw4) +
                        nl_route4([10, 8, 0, 0], 24, gw4, extra=rta(6, u32le(100)) + rta(7, bytes([10, 0, 0, 1])))),
        'route4_multipath': (NL_SCAN_K4, nl_route4([10, 7, 0, 0], 16, extra=multipath4)),
        'route4_metrics': (NL_SCAN_K4, nl_route4([10, 6, 0, 0], 16, gw4, extra=metrics)),
        'route4_mpls_encap': (NL_SCAN_K4, nl_route4([10, 5, 0, 0], 16, gw4, extra=encap_mpls)),
        'route4_via6': (NL_SCAN_K4, nl_route4([10, 4, 0, 0], 16, extra=via6)),
        'route4_table100': (NL_SCAN_K4T, nl_route4([10, 3, 0, 0], 16, gw4, table=100)),
        'route4_unreachable': (NL_SCAN_K4, nlmsg(RTM_NEWROUTE, rtmsg(AF_INET_, 16, rtype=7) +
                                                 rta(15, u32le(254)) + rta(1, bytes([10, 2, 0, 0])))),
        'route4_bird_proto': (NL_SCAN_K4, nl_route4([10, 1, 0, 0], 16, gw4, proto=12)),
        'route6_scan': (NL_SCAN_K6, nl_route6(p6, 48, gw6) +
                        nl_route6(bytes.fromhex('20010db8020000000000000000000000'), 64, extra=multipath6)),
        'route6_async': (NL_ASYNC, nl_route6(p6, 48, gw6, extra=rta(20, b'\x01'))),
        'route6_sadr': (NL_ASYNC, nl_route6(p6, 48, gw6, extra=rta(2, bytes.fromhex('20010db8000000000000000000000000')))),
        'mpls_scan': (NL_SCAN_MPLS, mpls_route),
        'link_new': (NL_ASYNC, nl_link(7, b'eth7')),
        'link_down': (NL_ASYNC, nl_link(7, b'eth7', flags=0x1002)),
        'link_del': (NL_ASYNC, nl_link(7, b'eth7') + nl_link(7, b'eth7', msg=RTM_DELLINK)),
        'link_vxlan': (NL_ASYNC, nl_link(8, b'vx8', extra=vxlan)),
        'link_master': (NL_ASYNC, nl_link(9, b'vrf9', extra=rta(18, rta(1, b'vrf\0'))) +
                        nl_link(10, b'eth10', extra=rta(10, u32le(9)))),
        'link_rename_fz0': (NL_ASYNC, nl_link(FZ0, b'renamed')),
        'addr4_new': (NL_ASYNC, nl_link(7, b'eth7') +
                      nl_addr(AF_INET_, 24, 7, bytes([10, 77, 0, 1]), extra=rta(4, bytes([10, 77, 0, 255])))),
        'addr4_ptp': (NL_ASYNC, nl_link(7, b'eth7', flags=0x11051) + nlmsg(RTM_NEWADDR,
                      struct.pack('<BBBBI', AF_INET_, 32, 0, 0, 7) + rta(2, bytes([10, 78, 0, 1])) +
                      rta(1, bytes([10, 78, 0, 2])))),
        'addr6_new': (NL_ASYNC, nl_addr(AF_INET6_, 64, FZ0, bytes.fromhex('20010db8000500000000000000000001'),
                                        extra=rta(8, u32le(0x80)))),
        'addr6_del_fz0': (NL_ASYNC, nl_addr(AF_INET6_, 64, FZ0, bytes.fromhex('20010db8000000000000000000000001'),
                                            msg=RTM_DELADDR)),
    }


# ── CLI (fuzz_cli.c) ───────────────────────────────────────────────────
# Control byte: bit 0 restricted CLI. Input: '\n'-separated commands, run
# against the config in fuzz_cli.c (static s4/s6/sroa/saspa/sflow/svpn,
# pipe p4, filter fz_in, function fz_tag, tables t4b r4 at f4 v4).
CLI_FULL, CLI_RESTRICTED = 0, 1


def cli_seeds():
    cmds = {
        'show_basic': ['show status', 'show memory', 'show protocols', 'show protocols all',
                       'show interfaces', 'show interfaces summary', 'show symbols',
                       'show symbols table', 'show symbols filter', 'show symbols function'],
        'show_route': ['show route', 'show route all', 'show route count', 'show route stats',
                       'show route for 10.1.2.3', 'show route for 10.1.0.0/16 all',
                       'show route in 10.0.0.0/8', 'show route table master6 all',
                       'show route table t4b', 'show route protocol s4',
                       'show route primary', 'show route filtered'],
        'show_route_filter': ['show route filter fz_in', 'show route where net.len > 16',
                              'show route where bgp_path ~ [= * 65001 * =] all',
                              'show route where (65000,1) ~ bgp_community',
                              'show route export p4', 'show route noexport p4',
                              'show route preexport p4', 'show route table r4 all',
                              'show route table at all', 'show route table f4 all',
                              'show route table v4 all'],
        'eval': ['eval 1 + 2 * 3', 'eval fz_tag(5)', 'eval 10.0.0.0/8 ~ [ 10.0.0.0/8+ ]',
                 'eval [1, 2, 3..10]', 'eval "abc" ~ "a*"', 'eval (1,2)',
                 'eval -empty-.add((1,2))', 'eval 2001:db8::/32.len',
                 'eval format(10.0.0.1)', 'eval 1.2.3.4.mask(8)',
                 'eval from_hex("0102ff")', 'eval +empty+.prepend(65001).len'],
        'proto_control': ['disable s6', 'show protocols s6', 'enable s6', 'restart s4',
                          'reload s4', 'reload in s4', 'reload out s4', 'disable "s*"',
                          'enable all', 'debug s4 all', 'debug s4 off', 'mrtdump s4 all',
                          'mrtdump s4 off'],
        'echo': ['echo all', 'echo all 1024', 'echo { warning, error }', 'echo off'],
        'dump': ['dump resources "x"', 'dump interfaces "x"', 'dump neighbors "x"',
                 'dump attributes "x"', 'dump routes "x"', 'dump protocols "x"',
                 'dump filters "x"', 'dump sockets "x"', 'dump events "x"'],
        'mrt_dump': ['mrt dump table "master4" to "x"', 'mrt dump table "master6" filter fz_in to "x"'],
        'show_roa_aspa': ['show route table r4 all', 'show route table at all',
                          'eval roa_check(r4, 10.1.0.0/16, 65001)',
                          'eval roa_check(r4, 10.1.0.0/16, 65002)'],
        'configure_stubs': ['configure', 'configure check', 'configure soft "x"', 'configure confirm',
                            'configure undo', 'configure status', 'down', 'graceful restart'],
        'restrict_cmd': ['restrict', 'disable s4', 'dump resources "x"', 'show status'],
        'errors': ['show route for', 'eval (', 'show route table nonexistent', 'enable nonexistent',
                   'foo bar', '', 'show', '"unterminated', 'eval 1 /* c'],
    }
    s = {}
    for name, lines in cmds.items():
        s[name] = (CLI_FULL, ('\n'.join(lines) + '\n').encode())
    s['restricted_mix'] = (CLI_RESTRICTED, ('\n'.join(cmds['proto_control'] + cmds['dump'] +
                                                    cmds['show_basic']) + '\n').encode())
    s['crlf'] = (CLI_FULL, b'show status\r\nshow route count\r\n')
    s['long_line'] = (CLI_FULL, b'eval ' + b'1+' * 600 + b'1\n')
    return s


# ── OSPF (fuzz_ospf.c) ─────────────────────────────────────────────────
# Control byte: bits 0-1 interface (0 v2 area 0, 1 v3 area 0, 2 v2 NSSA,
# 3 v3 stub), bit 2 unicast, bit 3 raw packet, bit 4 keep LSA checksums,
# bit 5 advance the clock afterwards (time byte added by write()).
# Non-raw input: packet type byte, then the body
# after the OSPF header; the harness fixes the LSA checksums in LSUs.
OSPF_V2, OSPF_V3, OSPF_V2_NSSA, OSPF_V3_STUB = 0, 1, 2, 3
OSPF_UNICAST, OSPF_RAW, OSPF_KEEP_CKSUM, OSPF_TIMERS = 4, 8, 16, 32
P_HELLO, P_DBDES, P_LSREQ, P_LSUPD, P_LSACK = 1, 2, 3, 4, 5
BIRD_RID = bytes([10, 0, 0, 1])


def ospf_nbr(i):
    return bytes([10, 0, i, 2])


def lsa(v3, ltype, lsid, adv, body, seq=0x80000001, age=1, opts=0x22):
    if v3:
        hdr = struct.pack('>HH', age, ltype)
    else:
        hdr = struct.pack('>HBB', age, opts, ltype)
    hdr += bytes(lsid) + bytes(adv) + struct.pack('>IHH', seq, 0, 20 + len(body))
    return hdr + body


def lsa_hdr(full):
    return full[:20]


def lsu(*lsas):
    return bytes([P_LSUPD]) + struct.pack('>I', len(lsas)) + b''.join(lsas)


def v2_router(adv, links, flags=0):
    body = struct.pack('>BBH', flags, 0, len(links))
    for lid, data, ltype, metric in links:
        body += bytes(lid) + bytes(data) + struct.pack('>BBH', ltype, 0, metric)
    return body


def v2_ext(mask, metric, fwd=b'\0\0\0\0', tag=0, e2=True):
    return bytes(mask) + struct.pack('>I', (0x80000000 if e2 else 0) | metric) + bytes(fwd) + struct.pack('>I', tag)


def v3_px(plen, prefix16, popts=0):
    nb = (plen + 31) // 32 * 4
    return bytes([plen, popts]), prefix16[:nb]


def v3_router(links, flags=0, opts=0x13):
    body = struct.pack('>I', (flags << 24) | opts)
    for ltype, metric, ifid, nifid, nrid in links:
        body += struct.pack('>BBHII', ltype, 0, metric, ifid, nifid) + bytes(nrid)
    return body


def v3_intra(prefixes, ref_type=0x2001, ref_id=0, ref_adv=b'\0\0\0\0'):
    body = struct.pack('>HHI', len(prefixes), ref_type, ref_id) + bytes(ref_adv)
    for plen, pfx, metric in prefixes:
        h, a = v3_px(plen, pfx)
        body += h + struct.pack('>H', metric) + a
    return body


def v3_inter(plen, pfx, metric=10):
    h, a = v3_px(plen, pfx)
    return struct.pack('>I', metric) + h + b'\0\0' + a


def v3_ext(plen, pfx, metric=20, fwd=None, tag=None):
    flags = 0x04 | (0x02 if fwd else 0) | (0x01 if tag is not None else 0)
    h, a = v3_px(plen, pfx)
    body = struct.pack('>I', (flags << 24) | metric) + h + b'\0\0' + a
    if fwd:
        body += fwd
    if tag is not None:
        body += struct.pack('>I', tag)
    return body


def v3_link(ll16, prefixes, prio=1, opts=0x13):
    body = struct.pack('>I', (prio << 24) | opts) + ll16 + struct.pack('>I', len(prefixes))
    for plen, pfx in prefixes:
        h, a = v3_px(plen, pfx)
        body += h + b'\0\0' + a
    return body


def ospf_seeds():
    n0, n1, n2, n3 = ospf_nbr(0), ospf_nbr(1), ospf_nbr(2), ospf_nbr(3)
    p6a = bytes.fromhex('20010db8010000000000000000000000')
    p6b = bytes.fromhex('20010db8020000000000000000000000')
    rt2 = lsa(False, 1, n0, n0, v2_router(n0, [(BIRD_RID, bytes([10, 0, 0, 2]), 1, 10),
                                              (bytes([10, 0, 0, 0]), bytes([255, 255, 255, 0]), 3, 10),
                                              (bytes([172, 16, 0, 0]), bytes([255, 255, 0, 0]), 3, 5)],
                                          flags=0x02))
    # OSPFv3 links: (type, metric, our iface id, neighbour iface id, neighbour
    # router id); BIRD's iface id is the OS index (fz1 = 3, fz3 = 5).
    rt3 = lsa(True, 0x2001, b'\0\0\0\0', n1, v3_router([(1, 10, 7, 3, BIRD_RID)], flags=0x02))
    s = {
        'v2_hello': (OSPF_V2, bytes([P_HELLO]) + bytes([255, 255, 255, 0]) +
                     struct.pack('>HBBIII', 10, 0x02, 1, 40, 0, 0) + BIRD_RID),
        'v3_hello': (OSPF_V3, bytes([P_HELLO]) + struct.pack('>IIHHII', 7, (1 << 24) | 0x13, 10, 40, 0, 0) +
                     BIRD_RID),
        'v2_lsu_router': (OSPF_V2 | OSPF_TIMERS, lsu(rt2)),
        'v2_lsu_network': (OSPF_V2, lsu(lsa(False, 2, bytes([10, 0, 0, 2]), n0,
                                            bytes([255, 255, 255, 0]) + BIRD_RID + n0))),
        'v2_lsu_summary': (OSPF_V2 | OSPF_TIMERS, lsu(rt2, lsa(False, 3, bytes([192, 168, 0, 0]), n0,
                                                               bytes([255, 255, 0, 0]) + struct.pack('>I', 20)),
                                                    lsa(False, 4, bytes([10, 9, 9, 9]), n0,
                                                        bytes(4) + struct.pack('>I', 30)))),
        'v2_lsu_external': (OSPF_V2 | OSPF_TIMERS, lsu(rt2, lsa(False, 5, bytes([198, 51, 100, 0]), n0,
                                                                v2_ext([255, 255, 255, 0], 100, tag=7)),
                                                     lsa(False, 5, bytes([203, 0, 113, 0]), n0,
                                                         v2_ext([255, 255, 255, 0], 50, fwd=[10, 0, 0, 2],
                                                                e2=False)))),
        'v2_nssa_lsu': (OSPF_V2_NSSA | OSPF_TIMERS,
                        lsu(lsa(False, 1, n2, n2, v2_router(n2, [(BIRD_RID, bytes([10, 0, 2, 2]), 1, 10)],
                                                            flags=0x02), opts=0x08),
                            lsa(False, 7, bytes([198, 18, 0, 0]), n2,
                                v2_ext([255, 254, 0, 0], 10, fwd=[10, 0, 2, 2]), opts=0x08))),
        'v2_lsu_opaque': (OSPF_V2, lsu(lsa(False, 10, bytes([1, 0, 0, 1]), n0,
                                           struct.pack('>HH', 1, 4) + b'\0\0\0\1', opts=0x42))),
        'v2_lsu_maxage': (OSPF_V2, lsu(lsa(False, 5, bytes([198, 51, 100, 0]), n0,
                                           v2_ext([255, 255, 255, 0], 100), age=3600, seq=0x80000002))),
        'v2_lsreq': (OSPF_V2, bytes([P_LSREQ]) + struct.pack('>I', 1) + BIRD_RID + BIRD_RID),
        'v2_lsack': (OSPF_V2, bytes([P_LSACK]) + lsa_hdr(rt2)),
        'v2_dbdes_dup': (OSPF_V2 | OSPF_UNICAST, bytes([P_DBDES]) + struct.pack('>HBBI', 1500, 0x02, 0x01, 1)),
        'v2_raw_hello': (OSPF_V2 | OSPF_RAW, bytes([2, 1]) + struct.pack('>H', 48) + n0 + bytes(4) +
                         bytes(8) + bytes(8) + bytes([255, 255, 255, 0]) +
                         struct.pack('>HBBIII', 10, 0x02, 1, 40, 0, 0) + BIRD_RID),
        'v3_lsu_router': (OSPF_V3 | OSPF_TIMERS, lsu(rt3)),
        'v3_lsu_intra': (OSPF_V3 | OSPF_TIMERS, lsu(rt3, lsa(True, 0x2009, b'\0\0\0\1', n1,
                                                              v3_intra([(48, p6a, 10), (64, p6b, 20)],
                                                                       ref_adv=n1)))),
        'v3_lsu_inter': (OSPF_V3 | OSPF_TIMERS, lsu(rt3, lsa(True, 0x2003, b'\0\0\0\2', n1, v3_inter(48, p6a)),
                                                    lsa(True, 0x2004, b'\0\0\0\3', n1,
                                                        struct.pack('>II', 0x13, 10) + bytes([10, 7, 7, 7])))),
        'v3_lsu_external': (OSPF_V3 | OSPF_TIMERS, lsu(rt3, lsa(True, 0x4005, b'\0\0\0\4', n1,
                                                                v3_ext(48, p6b, fwd=bytes.fromhex(
                                                                    '20010db8000100000000000000000002'), tag=9)),
                                                     lsa(True, 0x4005, b'\0\0\0\5', n1, v3_ext(0, bytes(16))))),
        'v3_lsu_link': (OSPF_V3, lsu(lsa(True, 0x0008, b'\0\0\0\7', n1,
                                         v3_link(bytes.fromhex('fe800000000000000000000000000002'),
                                                 [(64, bytes.fromhex('20010db8000100000000000000000000'))])))),
        'v3_stub_lsu': (OSPF_V3_STUB | OSPF_TIMERS,
                        lsu(lsa(True, 0x2001, b'\0\0\0\0', n3, v3_router([(1, 10, 7, 5, BIRD_RID)], opts=0x11)),
                            lsa(True, 0x2009, b'\0\0\0\1', n3, v3_intra([(56, p6a, 5)], ref_adv=n3)))),
        'v3_lsu_unknown': (OSPF_V3, lsu(lsa(True, 0xa021, b'\0\0\0\1', n1, struct.pack('>HH', 1, 4) + bytes(4)))),
        'v3_lsreq': (OSPF_V3, bytes([P_LSREQ]) + struct.pack('>HH', 0, 0x2001) + bytes(4) + BIRD_RID),
        'v3_lsack': (OSPF_V3, bytes([P_LSACK]) + lsa_hdr(rt3)),
        'v2_bad_cksum': (OSPF_V2 | OSPF_KEEP_CKSUM, lsu(rt2)),
    }
    return s


# ── BFD (fuzz_bfd.c) ───────────────────────────────────────────────────
# Control byte: bits 0-1 session (0 single-hop keyed MD5, 1 multihop no
# auth, 2 single-hop IPv6 meticulous keyed SHA1), bit 2 set Your
# Discriminator to the session's.
BFD_MD5, BFD_MH, BFD_SHA1, BFD_YOUR = 0, 1, 2, 4
BFD_DOWN, BFD_INIT, BFD_UP = 1, 2, 3
BFD_P, BFD_F, BFD_A, BFD_D = 0x20, 0x10, 0x04, 0x02


def bfd_ctl(state, flags=0, my=0x1111, your=0, auth=b'', diag=0, mult=3,
            tx=1000000, rx=1000000, echo=0):
    if auth:
        flags |= BFD_A
    length = 24 + len(auth)
    return struct.pack('>BBBBIIIII', (1 << 5) | diag, (state << 6) | flags, mult, length,
                       my, your, tx, rx, echo) + auth


def bfd_auth(atype, key_id=1, seq=1, digest_len=0, password=b''):
    if atype == 1:                                   # simple password
        return struct.pack('>BBB', 1, 3 + len(password), key_id) + password
    return struct.pack('>BBBBI', atype, 8 + digest_len, key_id, 0, seq) + bytes(digest_len)


def bfd_seeds():
    return {
        'mh_down': (BFD_MH, bfd_ctl(BFD_DOWN)),
        'mh_init': (BFD_MH | BFD_YOUR, bfd_ctl(BFD_INIT)),
        'mh_up_poll': (BFD_MH | BFD_YOUR, bfd_ctl(BFD_UP, BFD_P, tx=50000, rx=50000)),
        'mh_up_final': (BFD_MH | BFD_YOUR, bfd_ctl(BFD_UP, BFD_F)),
        'mh_demand': (BFD_MH | BFD_YOUR, bfd_ctl(BFD_UP, BFD_D)),
        'mh_admin_down': (BFD_MH | BFD_YOUR, bfd_ctl(0, diag=7)),
        'md5_down': (BFD_MD5, bfd_ctl(BFD_DOWN, auth=bfd_auth(2, digest_len=16))),
        'md5_init': (BFD_MD5 | BFD_YOUR, bfd_ctl(BFD_INIT, auth=bfd_auth(2, seq=2, digest_len=16))),
        'md5_noauth': (BFD_MD5, bfd_ctl(BFD_DOWN)),
        'md5_simple': (BFD_MD5, bfd_ctl(BFD_DOWN, auth=bfd_auth(1, password=b'fuzz'))),
        'sha1_down': (BFD_SHA1, bfd_ctl(BFD_DOWN, auth=bfd_auth(5, digest_len=20))),
        'sha1_up': (BFD_SHA1 | BFD_YOUR, bfd_ctl(BFD_UP, auth=bfd_auth(5, seq=9, digest_len=20))),
    }


def ospf_lsa_seeds():
    """Each LSA from the OSPF LSU seeds, alone (fuzz_ospf_lsa.c: control
    byte bit 0 = OSPFv3)."""
    out = {}
    for name, (ctl, body) in ospf_seeds().items():
        if ctl & OSPF_RAW or not body or body[0] != P_LSUPD:
            continue
        count, pos = struct.unpack('>I', body[1:5])[0], 5
        for k in range(count):
            length = struct.unpack('>H', body[pos + 18:pos + 20])[0]
            out[f'{name}_{k}'] = (ctl & 1, body[pos:pos + length])
            pos += length
    return out


# Harnesses whose control byte has a "time byte follows" bit: (bit, byte).
# The seeds advance the clock by 6 s (past OSPF's MinLSInterval).
TIME_BYTE = {'fuzz_babel': (16, 59), 'fuzz_rip': (32, 59), 'fuzz_ospf': (32, 59)}


def write(outdir, harness, seeds):
    d = os.path.join(outdir, harness)
    os.makedirs(d, exist_ok=True)
    bit, dt = TIME_BYTE.get(harness, (0, 0))
    for name, (ctl, body) in sorted(seeds.items()):
        if ctl & bit:
            body = bytes([dt]) + body
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
    n += write(out, 'fuzz_babel', babel_seeds())
    n += write(out, 'fuzz_rip', rip_seeds())
    n += write(out, 'fuzz_rpki', rpki_seeds())
    n += write(out, 'fuzz_netlink', netlink_seeds())
    n += write(out, 'fuzz_cli', cli_seeds())
    n += write(out, 'fuzz_ospf', ospf_seeds())
    n += write(out, 'fuzz_ospf_lsa', ospf_lsa_seeds())
    n += write(out, 'fuzz_bfd', bfd_seeds())
    print(f'gen_seeds: wrote {n} seeds to {out}')


if __name__ == '__main__':
    main()
