/*
 *	libFuzzer harness: OSPF LSA validation and parsing.
 *
 *	The LSA-level half of fuzz_ospf, without the packet and neighbour
 *	machinery, so it runs much faster: lsa_ntoh_hdr() / lsa_ntoh_body(),
 *	the type and scope mapping (incl. OSPFv2 opaque LSAs and OSPFv3
 *	unknown types), lsa_validate() and every per-type validator (router,
 *	network, summary, external / NSSA, link, intra-area-prefix, the
 *	OSPFv3 prefix lists and the extended / TLV-based LSAs), then for LSAs
 *	that validate, the readers the SPF calculation uses on them:
 *	lsa_walk_rt() (OSPFv2), lsa_parse_sum_net(), lsa_parse_sum_rt(),
 *	lsa_parse_ext() and lsa_get_tlv(). Reachable from any OSPF neighbour
 *	(LSUs), or anyone it floods for.
 *
 *	Input: one control byte, then one LSA (20-byte header + body, network
 *	byte order, as in an LSU; the header's length field is ignored).
 *	  bit 0  0 = OSPFv2, 1 = OSPFv3
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "fuzz_sock.h"
#include "fuzz_iface.h"

#include "proto/ospf/ospf.h"

#define FUZZ_OSPF_LSA_CONFIG						\
  "router id 10.0.0.1;\n"						\
  FUZZ_DEVICE_CONFIG							\
  "protocol ospf v2 o2 {\n"						\
  "  ipv4;\n"								\
  "  area 0 { interface \"fz0\" { type ptp; }; };\n"			\
  "}\n"									\
  "protocol ospf v3 o3 {\n"						\
  "  ipv6;\n"								\
  "  area 0 { interface \"fz1\" { type ptp; }; };\n"			\
  "}\n"

static struct ospf_proto *fuzz_p[2];
static struct ospf_iface *fuzz_ifa[2];

static void
fuzz_setup(void)
{
  fuzz_bird_init(FUZZ_OSPF_LSA_CONFIG);

  fuzz_p[0] = (struct ospf_proto *) fuzz_proto_find(&proto_ospf, "o2");
  fuzz_p[1] = (struct ospf_proto *) fuzz_proto_find(&proto_ospf, "o3");

  fuzz_iface_add(0);
  fuzz_iface_add(1);

  for (uint i = 0; i < 2; i++)
  {
    fuzz_ifa[i] = HEAD(fuzz_p[i]->iface_list);

    if (!NODE_VALID(fuzz_ifa[i]))
    {
      fprintf(stderr, "fuzz: no OSPF interface on fz%u\n", i);
      abort();
    }
  }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  FUZZ_ONCE(fuzz_setup());

  uint8_t ctl = fuzz_take_byte(&data, &size);
  uint v3 = ctl & 1;
  struct ospf_proto *p = fuzz_p[v3];
  struct ospf_iface *ifa = fuzz_ifa[v3];

  if ((size <= sizeof(struct ospf_lsa_header)) || (size > 65535) || (size % 4))
    return 0;

  /* Exactly-sized copies, so ASan sees reads past the LSA */
  struct ospf_lsa_header lsa;
  uint blen = size - sizeof(struct ospf_lsa_header);
  byte *raw = xmalloc(size);
  void *body = xmalloc(blen);

  memcpy(raw, data, size);
  lsa_ntoh_hdr((void *) raw, &lsa);
  lsa.length = size;
  lsa_ntoh_body(raw + sizeof(struct ospf_lsa_header), body, blen);
  xfree(raw);

  u32 type, domain;
  lsa_get_type_domain(&lsa, ifa, &type, &domain);

  if (type && lsa_validate(&lsa, type, ospf_is_v2(p), body))
  {
    struct top_hash_entry en = {
      .lsa = lsa,
      .lsa_type = type,
      .domain = domain,
      .lsa_body = body,
    };
    int af = ospf_is_v2(p) ? NET_IP4 : NET_IP6;

    switch (type)
    {
    case LSA_T_RT:
    {
      /* OSPFv3 walks gather all of a router's LSAs from the LSDB (only
       * fuzz_ospf has one); OSPFv2 walks the LSA itself. */
      if (!ospf_is_v2(p))
	break;

      struct ospf_lsa_rt_walk rt;
      lsa_walk_rt_init(p, &en, &rt);
      for (uint k = 0; (k < 4096) && lsa_walk_rt(&rt); k++)
	;
      break;
    }

    case LSA_T_SUM_NET:
    {
      net_addr net;
      u8 pxopts;
      u32 metric;
      lsa_parse_sum_net(&en, ospf_is_v2(p), af, &net, &pxopts, &metric);
      break;
    }

    case LSA_T_SUM_RT:
    {
      u32 drid, metric, options;
      lsa_parse_sum_rt(&en, ospf_is_v2(p), &drid, &metric, &options);
      break;
    }

    case LSA_T_EXT:
    case LSA_T_NSSA:
    {
      struct ospf_lsa_ext_local rt;
      lsa_parse_ext(&en, ospf_is_v2(p), af, &rt);
      break;
    }

    default:
      if (lsa_is_opaque(type))
	for (uint t = 0; t < 4; t++)
	  lsa_get_tlv(&en, t);
    }
  }

  xfree(body);
  return 0;
}
