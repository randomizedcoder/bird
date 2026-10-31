/*
 *	libFuzzer harness: the configuration language.
 *
 *	conf/cf-lex.l (flex), the bison grammar assembled from every
 *	config.Y (protocols, channels, filters, flowspec, MPLS, ...), the
 *	filter compiler (filter/f-inst.c, constant folding, trie/tree
 *	construction) and each protocol's postconfig checks. The input is
 *	parsed only, never committed. Reachable from `birdc configure` and
 *	from any file pulled in by `include`.
 *
 *	The parse error path longjmps out of the grammar (cf_error()), so
 *	every input exercises the cleanup of a half-built config.
 *
 *	Input: config text. `include "file"` still opens the named file
 *	(a missing one is a parse error), but the read hook serves every
 *	file's contents from the remaining input, never from disk.
 *
 *	Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "fuzz_bird.h"

static const byte *fuzz_pos;
static uint fuzz_remain;

static int
fuzz_cf_read(byte *dest, uint max_len, int fd UNUSED)
{
  if (max_len > fuzz_remain)
    max_len = fuzz_remain;
  memcpy(dest, fuzz_pos, max_len);
  fuzz_pos += max_len;
  fuzz_remain -= max_len;
  return max_len;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  FUZZ_ONCE(fuzz_bird_init(NULL));

  if (size > 65536)
    return 0;

  struct config *cfg = config_alloc("fuzz.conf");
  fuzz_pos = data;
  fuzz_remain = size;
  cf_read_hook = fuzz_cf_read;

  config_parse(cfg);
  config_free(cfg);
  return 0;
}
