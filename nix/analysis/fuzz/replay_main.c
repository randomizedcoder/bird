// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Plain main() driver: replays each file (or every file in each directory)
 * given on the command line through LLVMFuzzerTestOneInput. Used by the
 * fuzz-replay flake check so harnesses keep building and running without
 * libFuzzer.
 */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "fuzz_harness.h"

static int replay_file(const char *path)
{
	FILE *f = fopen(path, "rb");
	uint8_t *buf;
	long len;

	if (!f) {
		perror(path);
		return 1;
	}
	fseek(f, 0, SEEK_END);
	len = ftell(f);
	fseek(f, 0, SEEK_SET);
	buf = malloc(len ? (size_t)len : 1);
	if (!buf || fread(buf, 1, (size_t)len, f) != (size_t)len) {
		fprintf(stderr, "%s: read failed\n", path);
		fclose(f);
		free(buf);
		return 1;
	}
	fclose(f);
	LLVMFuzzerTestOneInput(buf, (size_t)len);
	free(buf);
	return 0;
}

static int replay_path(const char *path, unsigned *count)
{
	struct stat st;
	struct dirent *de;
	DIR *d;
	int rc = 0;

	if (stat(path, &st) < 0) {
		perror(path);
		return 1;
	}
	if (!S_ISDIR(st.st_mode)) {
		(*count)++;
		return replay_file(path);
	}
	d = opendir(path);
	if (!d) {
		perror(path);
		return 1;
	}
	while ((de = readdir(d))) {
		char child[4096];

		if (de->d_name[0] == '.')
			continue;
		snprintf(child, sizeof(child), "%s/%s", path, de->d_name);
		rc |= replay_path(child, count);
	}
	closedir(d);
	return rc;
}

int main(int argc, char **argv)
{
	unsigned count = 0;
	int rc = 0;

	for (int i = 1; i < argc; i++)
		rc |= replay_path(argv[i], &count);
	printf("replayed %u inputs\n", count);
	return rc;
}
