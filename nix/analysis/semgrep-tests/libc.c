/* Fixture for the generic libc rules. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>

void strings(char *d, const char *s, size_t n)
{
	// ruleid: unsafe-sprintf
	sprintf(d, "%s", s);
	// ok: unsafe-sprintf
	snprintf(d, n, "%s", s);
	// ruleid: unsafe-strcpy-strcat
	strcpy(d, s);
	// ruleid: unsafe-strcpy-strcat
	strcat(d, s);
	// ruleid: strncpy-usage
	strncpy(d, s, n);
}

void formats(struct cli *c, char *buf, const char *user, int n)
{
	// ruleid: potential-format-string
	printf(user);
	// ok: potential-format-string
	printf("%s", user);
	// ruleid: potential-format-string
	cli_msg(-1000, user);
	// ok: potential-format-string
	cli_msg(-1000, "value %d", n);
	// ruleid: potential-format-string
	bsnprintf(buf, 16, user);
	// ok: potential-format-string
	bsnprintf(buf, 16, "%s", user);
}

void misc(const char *s, int n)
{
	// ruleid: atoi-usage
	int v = atoi(s);
	// ok: atoi-usage
	long w = strtol(s, NULL, 10);
	// ruleid: alloca-usage
	char *p = alloca(n);
	// ok: alloca-usage
	char *q = alloca(sizeof(long));
	(void)v; (void)w; (void)p; (void)q;
}
