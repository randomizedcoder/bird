/* Fixture for format-result-advance, format-result-accumulate,
 * bsprintf-unbounded and assert-side-effect. */

int format_advance(char *buf, int buflen, int vid)
{
	int c = bsnprintf(buf, buflen, "%d", vid);
	// ruleid: format-result-advance
	ADVANCE(buf, buflen, c);
	return c;
}

int format_advance_checked(char *buf, int buflen, int vid)
{
	int c = bsnprintf(buf, buflen, "%d", vid);

	if (c < 0)
		return -1;
	// ok: format-result-advance
	ADVANCE(buf, buflen, c);
	return c;
}

int format_accumulate(char *buf, int buflen, int vid)
{
	int c = 0;

	// ruleid: format-result-accumulate
	c += bsnprintf(buf, buflen, " vlan %d", vid);
	// ok: format-result-accumulate
	c = bsnprintf(buf, buflen, " vlan %d", vid);
	return c;
}

void unbounded(char *buf, int n)
{
	// ruleid: bsprintf-unbounded
	bsprintf(buf, "%d", n);
	// ok: bsprintf-unbounded
	bsnprintf(buf, 16, "%d", n);
}

void asserts(int *refs, int i, int n)
{
	// ruleid: assert-side-effect
	ASSERT(i++ < n);
	// ruleid: assert-side-effect
	ASSERT(--refs[0] >= 0);
	// ok: assert-side-effect
	ASSERT(i < n);
	// ok: assert-side-effect
	ASSERT_DIE(i++ < n);
}
