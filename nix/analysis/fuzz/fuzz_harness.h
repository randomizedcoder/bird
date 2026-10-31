// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Shared helpers for the out-of-tree BIRD libFuzzer harnesses.
 *
 * Each harness defines LLVMFuzzerTestOneInput(); one-time global setup goes
 * behind FUZZ_ONCE so it runs on the first input only. Harnesses build two
 * ways: with -fsanitize=fuzzer for libFuzzer, or with replay_main.c to
 * replay a corpus as a plain program.
 */
#ifndef BIRD_NIX_FUZZ_HARNESS_H
#define BIRD_NIX_FUZZ_HARNESS_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define FUZZ_ONCE(setup)                                                       \
	do {                                                                   \
		static bool fuzz_once_done;                                    \
		if (!fuzz_once_done) {                                         \
			fuzz_once_done = true;                                 \
			setup;                                                 \
		}                                                              \
	} while (0)

/* Consume one selector byte; returns 0 when the input is empty. */
static inline uint8_t fuzz_take_byte(const uint8_t **data, size_t *size)
{
	uint8_t b;

	if (*size == 0)
		return 0;
	b = **data;
	(*data)++;
	(*size)--;
	return b;
}

#endif
