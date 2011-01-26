#include <CUnit/Basic.h>
#include <unistd.h>

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

/*
 * 
 */
static void
test_duplicate_recipient(void)
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
	CU_ASSERT((unsigned)write(fds[1], msg, strlen(msg)) == strlen(msg));

	close(fds[1]);

	header_parse(fds[0], &header_list, &rcpt_list, True);

	list_for_each(&rcpt_list, node, list)
		nrecips++;
	CU_ASSERT(nrecips == 1);

	node = list_top(&rcpt_list, struct string_node, list);
	CU_ASSERT(strcmp(node->string, "root") == 0);
}

static void
test_long_indented_paragraph(void)
{
	char *msg = "From: root\r\nTo: root\r\nSubject: ssmtp test: long block of indented test\r\n\r\n1\r\n 6 0 abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\r\n 2 1 6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\r\n 2 2 6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\r\n 2 3 6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\r\n 2 4 6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\r\n 2 5 6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\r\n 2 6 6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\r\n 2 7 6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\r\n 2 8 6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\r\n 2 9 6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\r\n 2 a 6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\r\n 2 b 6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\r\n 2 c 6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\r\n 2 d 6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\r\n 2 e 6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\r\n 2 f 6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\r\n 2 0 6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\r\n 2 1 6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\r\n 2 2 6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\r\n 2 3 6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\r\n 2 4 6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\r\n 2 5 6789abcdef0123456789ab+ --- all characters following the + are stripped ...\r\n 2 6 6789abcdef0123456789abcdef0123456789abcde+0123456789abcdef0123456789abcdef0123456789abcd\r\n 2 7 6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\r\n 2 8 6789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd\r\n until here\r\n";
	CU_ASSERT(msg != NULL);
}

static void
test_lost_last_line(void)
{
	char *msg = "From: root\r\nTo: root\r\nSubject: ssmtp test - last lines are stripped\r\n\r\nHello, world.\r\nYou\r\n will not see these two lines.\r\n";

	CU_ASSERT(msg != NULL);
}

int
main(void)
{
	CU_pSuite	pSuite = NULL;
	unsigned int	ret;

	if (CUE_SUCCESS != CU_initialize_registry())
		return CU_get_error();

	pSuite = CU_add_suite("headers", init_header_tests, clean_header_tests);

	if (NULL == CU_add_test(pSuite, "test for duplicate recipient",
				test_duplicate_recipient)		||
	    NULL == CU_add_test(pSuite, "test for long indented paragraph",
				test_long_indented_paragraph)		||
	    NULL == CU_add_test(pSuite, "test for lost last line",
				test_lost_last_line)) {
		CU_cleanup_registry();
		return CU_get_error();
	}

	CU_basic_set_mode(CU_BRM_VERBOSE);
	CU_basic_run_tests();
	ret = CU_get_number_of_tests_failed();
	CU_cleanup_registry();
	return ret;
}
