/*
 * Copyright 2016-2018 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <ayla/utypes.h>
#include <ayla/log.h>
#include <ayla/assert.h>
#include <ayla/buffer.h>

#define TEST_BUF_SIZE	10

static char *cmdname;


struct queue_buf q1, q2, q3;

void *test_data_alloc(size_t len)
{
	unsigned i;
	void *data;

	data = malloc(len);
	REQUIRE(data, REQUIRE_MSG_ALLOCATION);
	for (i = 0; i < len; ++i) {
		((u8 *)data)[i] = i & 0xff;
	}
	return data;
}

void test_dump_all(bool with_hex)
{
	queue_buf_dump(&q1, "QUEUE 1", with_hex);
	queue_buf_dump(&q2, "QUEUE 2", with_hex);
	queue_buf_dump(&q3, "QUEUE 3", with_hex);
}

void test_dump_json(const char *msg, json_t *json)
{
	char *output;

	if (!json) {
		log_err("JSON is NULL");
		return;
	}
	output = json_dumps(json, JSON_INDENT(4));
	REQUIRE(output, REQUIRE_MSG_ALLOCATION);
	if (msg) {
		log_debug("%s:\n%s", msg, output);
	} else {
		log_debug("%s", output);
	}
	free(output);
}

void test_dump_all_json(void)
{
	json_t *json;

	json = queue_buf_parse_json(&q1, 0);
	test_dump_json("QUEUE 1", json);
	json_decref(json);
	json = queue_buf_parse_json(&q2, 0);
	test_dump_json("QUEUE 2", json);
	json_decref(json);
	json = queue_buf_parse_json(&q3, 0);
	test_dump_json("QUEUE 3", json);
	json_decref(json);
}

void test_put(size_t len)
{
	void *data = test_data_alloc(len);
	log_debug("%zu bytes", len);
	queue_buf_put(&q1, data, len);
	queue_buf_put(&q2, data, len);
	queue_buf_put(&q3, data, len);
	free(data);
}

void test_reset(void)
{
	queue_buf_reset(&q1);
	queue_buf_reset(&q2);
	queue_buf_reset(&q3);
}

void test_trim(size_t len)
{
	queue_buf_trim(&q1, len);
	queue_buf_trim(&q2, len);
	queue_buf_trim(&q3, len);
}

void test_trim_head(size_t len)
{
	queue_buf_trim_head(&q1, len);
	queue_buf_trim_head(&q2, len);
	queue_buf_trim_head(&q3, len);
}

/*
 * Main function
 */
int main(int argc, char **argv)
{
	cmdname = strrchr(argv[0], '/');
	if (cmdname) {
		cmdname++;
	} else {
		cmdname = argv[0];
	}
	log_init(cmdname, LOG_OPT_NO_SYSLOG |
	    LOG_OPT_FUNC_NAMES | LOG_OPT_DEBUG | LOG_OPT_CONSOLE_OUT);

	/* Initialize */
	queue_buf_init(&q1, 0, 0);
	queue_buf_init(&q2, 0, TEST_BUF_SIZE);
	queue_buf_init(&q3, QBUF_OPT_PRE_ALLOC, TEST_BUF_SIZE);
	log_debug("Initialized");
	test_dump_all(true);

	/* Put incremental */
	unsigned i;
	log_debug("\nIncremental put");
	for (i = 0; i < 10; ++i) {
		test_put((i + 1) * 2);
	}
	test_dump_all(true);

	/* Reset */
	log_debug("\nReset");
	test_reset();
	test_dump_all(true);

	/* Large put */
	log_debug("\nLarge put 25");
	test_put(25);
	test_dump_all(true);

	/* Trim */
	log_debug("\nTrim -5");
	test_trim(20);
	test_dump_all(true);
	log_debug("\nTrim -10");
	test_trim(10);
	test_dump_all(true);
	log_debug("\nTrim -5");
	test_trim(5);
	test_dump_all(true);

	/* Trim head */
	log_debug("\nReset and put 10 + 10 for trim test");
	test_reset();
	test_put(10);
	test_put(10);
	test_dump_all(true);
	log_debug("\nTrim Head -5");
	test_trim_head(15);
	test_dump_all(true);
	log_debug("\nTrim Head -5");
	test_trim_head(10);
	test_dump_all(true);
	log_debug("\nTrim Head -5");
	test_trim_head(5);
	test_dump_all(true);

	/* Concat */
	log_debug("\nConcatenate q2 + q3");
	queue_buf_concat(&q2, &q3);
	test_dump_all(true);
	log_debug("\nConcatenate q1 + q2");
	queue_buf_concat(&q1, &q2);
	test_dump_all(true);


	/* Coelesce */
	log_debug("\nCoelesce q1");
	queue_buf_coalesce(&q1);
	test_dump_all(true);

	/* Copyout */
	log_debug("\nPut 15");
	test_put(15);
	log_debug("\nCopyout q1");
	void *copy_buf = malloc(q1.len);
	REQUIRE(copy_buf, REQUIRE_MSG_ALLOCATION);
	queue_buf_copyout(&q1, copy_buf, q1.len, 0);
	queue_buf_dump(&q1, "QUEUE 1", true);
	log_debug_hex("q1 Copy buffer", copy_buf, q1.len);
	free(copy_buf);

	/* To JSON */
	json_t *json;
	const char *json_str =
		"{\"widget\": {"
		"    \"debug\": \"on\","
		"    \"window\": {"
		"        \"title\": \"Sample Widget\","
		"        \"name\": \"main_window\","
		"        \"width\": 500,"
		"        \"height\": 500"
		"    },"
		"    \"image\": { "
		"        \"src\": \"Images/Button.png\","
		"        \"name\": \"sun1\","
		"        \"hOffset\": 250,"
		"        \"vOffset\": 250,"
		"        \"alignment\": \"center\""
		"    },"
		"    \"text\": {"
		"        \"data\": \"Click Here\","
		"        \"size\": 36,"
		"        \"style\": \"bold\","
		"        \"name\": \"text1\","
		"        \"hOffset\": 250,"
		"        \"vOffset\": 100,"
		"        \"alignment\": \"center\""
		"    }"
		"}}";
	log_debug("\nLoad JSON string, then test To_JSON parsing:\n%s",
	    json_str);
	test_reset();
	queue_buf_put(&q1, json_str, strlen(json_str));
	queue_buf_put(&q2, json_str, strlen(json_str));
	queue_buf_put(&q3, json_str, strlen(json_str));
	test_dump_all(true);
	test_dump_all_json();

	log_debug("\nBuild two JSON strings and concatenate them");
	queue_buf_trim(&q2, strlen(json_str) - 1);	/* Remove last '}' */
	queue_buf_put(&q2, ",", 1);
	queue_buf_trim_head(&q3, strlen(json_str) - 8);	/* Trim off "{"widget */
	queue_buf_put_head(&q3, "\"widget2", strlen("\"widget2"));
	queue_buf_concat(&q2, &q3);
	queue_buf_dump(&q2, "QUEUE 2", true);
	json = queue_buf_parse_json(&q2, 0);
	test_dump_json("QUEUE 2", json);
	json_decref(json);

	log_debug("\nPut JSON, then parse and dump it");

	test_reset();
	json = json_loads(json_str, 0, NULL);
	REQUIRE(json, REQUIRE_MSG_ALLOCATION);
	queue_buf_put_json(&q1, json);
	queue_buf_put_json(&q2, json);
	queue_buf_put_json(&q3, json);
	json_decref(json);
	test_dump_all(true);
	test_dump_all_json();

	return 0;
}
