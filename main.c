#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include "ssmtp.h"
#include "xgethostname.h"

/*
 * main() -- make the program behave like sendmail, then call ssmtp
 */
int main(int argc, char **argv)
{
	char **new_argv;

	/* Try to be bulletproof :-) */
	(void)signal(SIGHUP, SIG_IGN);
	(void)signal(SIGINT, SIG_IGN);
	(void)signal(SIGTTIN, SIG_IGN);
	(void)signal(SIGTTOU, SIG_IGN);

	new_argv = parse_options(argc, argv);

	exit(ssmtp(new_argv));
}
