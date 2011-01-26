#include <CUnit/Basic.h>

#include "ssmtp.h"
#include "ccan/list/list.h"

static int
init_header_tests(void)
{
	return 0;
}

static int
clean_header_tests(void)
{
	return 0;
}

static void
test_crlf(void)
{
	char *msg = "From: root\r\nTo: root\r\nSubject: ssmtp test - another recipicient taken from the body\r\n\r\nHello, world.\r\nTo: cbiedl\r\n^^^^^^^^^^ this guy will receive mail\r\nFrom: cbiedl (This line will be stripped)\r\nHello, world.\r\n.\r\n";

	int			fds[2];
	struct list_head	rcpt_list;
	struct list_head	header_list;
	struct string_node	*node;
	int			nrecips = 0;

	list_head_init(&rcpt_list);
	list_head_init(&header_list);

	CU_ASSERT_FATAL(pipe(fds) != -1);
	CU_ASSERT(write(fds[1], msg, strlen(msg)) == strlen(msg));

	close(fds[1]);

	header_parse(fds[0], &header_list, &rcpt_list, True);

	list_for_each(&rcpt_list, node, list)
		nrecips++;
	CU_ASSERT(nrecips == 1);

	node = list_top(&rcpt_list, struct string_node, list);
	CU_ASSERT(strcmp(node->string, "root") == 0);
}

int
main(int argc, char **argv)
{
	CU_pSuite	pSuite = NULL;
	unsigned int	ret;

	if (CUE_SUCCESS != CU_initialize_registry())
		return CU_get_error();

	pSuite = CU_add_suite("headers", init_header_tests, clean_header_tests);

	if (NULL == CU_add_test(pSuite, "test with \\r\\n", test_crlf)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	ret = CU_get_number_of_tests_failed();
	CU_cleanup_registry();
	return ret;
}
