/* Fixture for wire-len-to-memcpy-unchecked, wire-len-advance-unchecked
 * and copy-len-subtraction. */
#include <string.h>

void positive_u8(byte *pos, byte *dst)
{
	uint len;

	len = get_u8(pos);
	// ruleid: wire-len-to-memcpy-unchecked
	memcpy(dst, pos + 1, len);
}

void positive_decl_u16(byte *pos, byte *dst)
{
	uint len = get_u16(pos);
	// ruleid: wire-len-to-memcpy-unchecked
	bmemcpy(dst, pos + 2, len);
}

void negative_checked(byte *pos, uint size, byte *dst)
{
	uint len = get_u8(pos);

	if (len > size)
		return;
	// ok: wire-len-to-memcpy-unchecked
	memcpy(dst, pos + 1, len);
}

void negative_checked_block(byte *pos, uint size, byte *dst)
{
	uint len;

	len = get_u16(pos);
	if (len + 2 > size) {
		return;
	}
	// ok: wire-len-to-memcpy-unchecked
	memcpy(dst, pos + 2, len);
}

void advance_unchecked(byte *pos, uint size)
{
	uint len = get_u8(pos + 1);
	// ruleid: wire-len-advance-unchecked
	ADVANCE(pos, size, 2 + len);
}

void advance_checked(byte *pos, uint size)
{
	uint len = get_u8(pos + 1);

	if (size < 2 + len)
		return;
	// ok: wire-len-advance-unchecked
	ADVANCE(pos, size, 2 + len);
}

void subtraction(byte *dst, byte *pkt, uint len, uint hdr)
{
	// ruleid: copy-len-subtraction
	memcpy(dst, pkt + hdr, len - hdr);
	// ok: copy-len-subtraction
	memcpy(dst, pkt, len);
}
