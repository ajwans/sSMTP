/*

 See COPYRIGHT for the license

*/
#include <sys/types.h>
#include <stdio.h>
#include <pwd.h>

#define BUF_SZ  (1024 * 2)	/* A pretty large buffer, but not outrageous */

#define MAXWAIT (10 * 60)	/* Maximum wait between commands, in seconds */
#define MEDWAIT (5 * 60)

#define MAXSYSUID 999		/* Highest UID which is a system account */

#ifndef _POSIX_ARG_MAX
#define MAXARGS 4096
#else
#define MAXARGS  _POSIX_ARG_MAX
#endif

/* ssmtp assumes MAXHOSTNAMELEN is alwyas in sys/param.h this is
   not always the case (System V/Solaris) */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 256
#endif

typedef enum {False, True} bool_t;

struct string_list {
	char *string;
	struct string_list *next;
};

typedef struct string_list headers_t;
typedef struct string_list rcpt_t;


#ifdef HAVE_SASL
#define B64DEC(in, inlen, out, outmax, outlen) \
	sasl_decode64(in, inlen, out, outmax, outlen)
#define B64ENC(in, inlen, out, outmax, outlen) \
	sasl_encode64(in, inlen, out, outmax, outlen)
#else
#define B64DEC(in, inlen, out, outmax, outlen) do {	\
		*outlen = from64tobits(out, in)		\
	} while (0)
#define B64ENC(in, inlen, out, outmax, outlen) \
	to64frombits(out, in, inlen)

/* base64.c */
void to64frombits(char *, const char *, int);
int from64tobits(char *, const char *);
#endif /* HAVE_SASL */

char **parse_options(int argc, char **argv);
int ssmtp(char **argv);
