#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "ssmtp.h"

%%{
	machine rfc822;

	action SaveHeader {
		*h = 0;
		header_save(header, headers, recips, minus_t_set);
		h = header;
	}

	action SaveChar {
		*h = fc;
		h++;
	}

	header_name = (print - [ :])+ @{ *h = fc; h++; };

	eol = [\r]? [\n] %{ *h = '\r'; h++; *h = '\n'; h++; };
	neol = [^\r\n] @SaveChar;

	whitespace = [ 	];

	header_value = whitespace* neol+ (eol whitespace @SaveChar neol+)**;

	header = header_name ':' @SaveChar header_value eol %SaveHeader;

	main := header+ eol @{ in_header = 0; };
}%%

%% write data;

void
header_parse(
	int			fd,
	struct list_head	*headers,
	struct list_head	*recips,
	bool_t			minus_t_set)
{
	int in_header = 1;
	int cs;
	char c[2];
	char *p, *pe, *eof = NULL;

	char header[BUF_SZ * 2];
	char *h = header;

	c[1] = 0;
	pe = &c[1];

	%% write init;

	while (in_header && read(fd, c, 1) > 0) {
		p = c;
		%% write exec;
	}
}
