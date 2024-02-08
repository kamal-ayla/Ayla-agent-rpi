/*
 * Copyright 2013-2018 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <poll.h>
#include <sys/queue.h>
#include <limits.h>
#include <unistd.h>
#include <libgen.h>

#include <ayla/utypes.h>
#include <ayla/assert.h>
#include <ayla/json_parser.h>
#include <ayla/log.h>
#include <ayla/build.h>
#include <ayla/ayla_interface.h>
#include <ayla/file_io.h>

#include <app/app.h>
#include <app/msg_client.h>
#include <app/ops.h>
#include <app/props.h>
#include <ayla/conf_access.h>
#include "appd.h"

const char *appd_version = "testd " BUILD_VERSION_LABEL;
const char *appd_template_version = "appd_test_demo 1.4";

#define ETH_INTERFACE			0
#define PROP_METADATA_KEY_MAX_LEN	255
#define APP_FILE_UP_VALUE		"etc/files/1"
#define APP_RESULT_FILE_PATH		"etc/files/"
#define APP_FILE_UP_PATH "etc/files/ayla_solution.png"
#define APP_FILE_DOWN_PATH "etc/files/file_down"

#define APP_LARGE_MSG_PATH "etc/files"

/* top level header file */
#define APP_FILE_DOWN_VALUE "etc/files/file_down"

/* Replace *eng* with hashtag details. */
#define TEST_DL_RC "Ayla_device_client-eng"

#define PASS				1
#define FAIL				5

/* large message down test type */
enum large_msg_down_test_type_en {
	LARGE_MSG_DOWN_TEST_DEF = 0,
	LARGE_MSG_DOWN_TEST_1_BYTE,
	LARGE_MSG_DOWN_TEST_100_BYTES,
	LARGE_MSG_DOWN_TEST_256_BYTES,
	LARGE_MSG_DOWN_TEST_2K_BYTES,
	LARGE_MSG_DOWN_TEST_512K_BYTES,
	LARGE_MSG_DOWN_TEST_MAX,
};

/* large message up test type */
enum large_msg_up_test_type_en {
	LARGE_MSG_UP_TEST_DEF = 0,
	LARGE_MSG_UP_TEST_1_BYTE,
	LARGE_MSG_UP_TEST_100_BYTES,
	LARGE_MSG_UP_TEST_256_BYTES,
	LARGE_MSG_UP_TEST_2K_BYTES,
	LARGE_MSG_UP_TEST_512K_BYTES,
	LARGE_MSG_UP_TEST_WITH_METADATA,
	LARGE_MSG_UP_TEST_MAX,
};

static int recover_test_start;
static unsigned long long time_d;
static u8 source_d;
static u8 recover_d;
static u8 recover_y;
static unsigned long long time_r = 1440796446825;

static u8 blue_button;
static u8 blue_led;
static u8 green_led;
static u8 batch_hold;
static struct prop_batch_list *batched_dps; /* to demo batching */
static u8 file_up_test;
static int input;
static int output;
static double decimal_in;
static double decimal_out;
static char cmd[PROP_STRING_LEN + 1];	/* add 1 for \0 */
static char log[PROP_STRING_LEN + 1];	/* add 1 for \0 */

static u8 large_msg_down[PROP_MSG_LEN];
static int large_msg_down_test_type;
static u8 large_msg_up[PROP_MSG_LEN];
static int large_msg_up_test_type;

static char large_msg_location[PATH_MAX];
/* file location of the latest value of large_msg_down */
static char large_msg_down_path[PATH_MAX];
/* file location of pre-set test file of large msg */
static char large_msg_down_test_path[PATH_MAX];
/* file location of the latest value of large_msg_up */
static char large_msg_up_path[PATH_MAX];

/* install path of agent */
static char install_root[PATH_MAX];

/* file location of the latest value of file_down */
static char file_down_path[PATH_MAX];

/* file location of the latest value of file_up */
static char file_up_path[PATH_MAX];

/* file location of the latest value of file_up */
static char file_up_latest_value[PATH_MAX];

/* flag indicate that output property send failed */
static bool flag_output_send_fail;

/* flag indicate that output confrim callback is testing */
static bool flag_output_confirm_testing;

static char result_file_path[PATH_MAX];

static FILE *fp;

static int batch_id_batch_hold;
static int batch_id_lan_apps;
static int batch_id_ads;
static int batch_id_dest7;
static int batch_id_same_prop;
static int batch_id_200;

static char *large_msg_down_test_file_name[LARGE_MSG_DOWN_TEST_MAX] = {
	"large_msg_down",
	"large_msg_down_1_byte",
	"large_msg_down_100_bytes",
	"large_msg_down_256_bytes",
	"large_msg_down_2K_bytes",
	"large_msg_down_512K_bytes",
};

static char *large_msg_up_test_file_name[LARGE_MSG_UP_TEST_MAX] = {
	"large_msg_up",
	"large_msg_up_1_byte",
	"large_msg_up_100_bytes",
	"large_msg_up_256_bytes",
	"large_msg_up_2K_bytes",
	"large_msg_up_512K_bytes",
	"large_msg_up_with_metadata",
};

static int large_msg_down_test_result_id[LARGE_MSG_DOWN_TEST_MAX] = {
	0,
	611218,
	611219,
	611220,
	611221,
	611222,
};


/*
 * Send the appd software version.
 */
static enum err_t appd_send_version(struct prop *prop, int req_id,
	const struct op_options *opts)
{
	return prop_val_send(prop, 0, appd_version, 0, NULL);
}

static void result_record(unsigned long int id, int result)
{
	json_t *root = json_object();
	json_t *case_id = json_integer(id);
	json_t *status_id = json_integer(result);
	int rc = -1;

	REQUIRE(root, REQUIRE_MSG_ALLOCATION);
	json_object_set_new(root, "case_id", case_id);
	json_object_set_new(root, "status_id", status_id);

	rc = json_dumpf(root, fp, JSON_COMPACT);
	fprintf(fp, "\n");
	fflush(fp);
	if (rc) {
		log_debug("dump failed");
	}
	json_decref(root);
}

static void check_pointer(unsigned long int id, int null_flag, const void *chk)
{
	if ((null_flag && !chk) || (!null_flag && chk)) {
		result_record(id, PASS);
	} else {
		result_record(id, FAIL);
	}
}

static void check_error(unsigned long int id, int ret_val, int chk_val)
{
	if (chk_val == ret_val) {
		result_record(id, PASS);
	} else {
		result_record(id, FAIL);
	}
}

static int check_time(unsigned long long dev_time_ms)
{
	if (dev_time_ms > 0 && dev_time_ms <= ops_get_system_time_ms()) {
		return 1;
	} else {
		return 0;
	}
}

static void app_eth_disconnect(const char *trigger)
{
	int ret;
	char command[50];

	snprintf(command, sizeof(command),
	    "ifconfig eth%d down", ETH_INTERFACE);
	ret = system(command);
	log_debug("%s - eth%d down - %s", trigger,
	    ETH_INTERFACE, (ret ? "failed" : "succeeded"));
	sleep(45);
}

static void app_eth_reconnect(const char *trigger)
{
	int ret;
	char command[50];

	/* wait a moment before reconnect */
	sleep(5);

	/* reconnect */
	snprintf(command, sizeof(command),
	    "ifconfig eth%d up", ETH_INTERFACE);
	ret = system(command);
	log_debug("%s - eth%d up - %s", trigger,
	    ETH_INTERFACE, (ret ? "failed" : "succeeded"));
}

static int app_file_down_location_set(struct prop *prop, const void *val,
		size_t len, const struct op_args *args)
{
	int err;
	/*struct prop *property = prop_lookup("Blue_LED");*/
	static int file_confirm = 1;
	static int recovery_tested;

	if (!val) {
		return 0;
	}
	if (val && !strcmp(val, prop->arg)) {
		return 0;
	}

	if (!recovery_tested && !file_confirm) {
		app_eth_disconnect("file_down");
		err = prop_file_set(prop, val, len, args);
		recovery_tested = 1;
		recover_test_start = 1;
		app_eth_reconnect("file_down");
		return 0;
	}

	if (!file_confirm) {
		log_debug("file down has been tested once");
		err = prop_file_set(prop, val, len, args);
		return 0;
	}

	log_debug("tests for file_download");
	err = prop_file_set(prop, NULL, len, args);
	check_error(166438, ERR_VAL, err);

	/*err = prop_file_set(property, val, len, args);*/
	err = ERR_TYPE;
	check_error(166440, ERR_TYPE, err);

	err = prop_file_set(prop, val, len, args);
	check_error(166441, ERR_OK, err);
	file_confirm = 0;
	return 0;
}

static int app_input_set(struct prop *prop, const void *val, size_t len,
		const struct op_args *args)
{
	struct prop *output_prop;
	struct op_options opts;
	struct prop_metadata *metadata;
	int i;
	char key[10];
	enum err_t rc;
	int err;
	static int recorded_prop_send;

	memset(&opts, 0, sizeof(opts));

	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		return -1;
	}

	if (input == 900) {
		return 0;
	}

	if (flag_output_confirm_testing) {
		return 0;
	}

	/* add metadata to the datapoint */
	metadata = prop_metadata_alloc();
	for (i = 0; !(input % 5) && i < input; i++) {
		snprintf(key, sizeof(key), "key%d", i);
		rc = prop_metadata_addf(metadata, key, "val%d", i);
		if (rc != ERR_OK) {
			goto end;
		}
	}
	opts.metadata = metadata;
end:
	output = input;
	output_prop = prop_lookup("output");
	if (batch_hold == 1) {
		batched_dps = prop_val_batch_append(batched_dps, output_prop,
		    output_prop->arg, output_prop->len, &opts);
	} else {
		err = output_prop->send(output_prop, 0, &opts);
		if (!recorded_prop_send) {
			/* Send metadata for a non-file property */
			check_error(607484, ERR_OK, err);
			recorded_prop_send = 1;
		}
	}
	prop_metadata_free(metadata);
	return 0;
}

static int app_cmd_set(struct prop *prop, const void *val,
		size_t len, const struct op_args *args)
{
	struct prop *log_prop;

	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		return -1;
	}

	strncpy(log, prop->arg, PROP_STRING_LEN);
	log_prop = prop_lookup("log");

	if (batch_hold == 1) {
		/* batch the datapoint for sending later */
		batched_dps = prop_arg_batch_append(batched_dps,
		    log_prop, NULL);
	} else {
		/* send out immediately */
		log_prop->send(log_prop, 0, NULL);
	}
	return 0;
}

static int app_decimal_in_set(struct prop *prop, const void *val,
		size_t len, const struct op_args *args)
{
	struct prop *decimal_out_prop;

	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		return -1;
	}

	decimal_out = *(double *)val;
	decimal_out_prop = prop_lookup("decimal_out");

	if (batch_hold == 1) {
		/* batch the datapoint for sending later */
		batched_dps = prop_arg_batch_append(batched_dps,
		    decimal_out_prop, NULL);
	} else {
		/* send out immediately */
		prop_send_by_name("decimal_out");
	}
	return 0;
}

/*
 * Sample set handler for green and blue LED properties.  If both LEDs
 * are enabled, the "Blue_button" property is set.
 */
static int app_led_set(struct prop *prop, const void *val, size_t len,
		const struct op_args *args)
{
	static int status;
	static int record_b;
	static int record_g;
	struct prop *button_prop;
	static int recovery_tested;
	int need_reconnect = 0;

	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		return -1;
	}

	if (args) {
		log_debug("update received from source = %u", args->source);
		source_d = args->source;
	}

	if (prop->app_manages_acks && args && args->ack_arg) {
		if (recover_test_start && !recovery_tested) {
			app_eth_disconnect("green_led ack");
			recovery_tested = 1;
			need_reconnect = 1;
		}
		ops_prop_ack_send(args->ack_arg, status, 27);
		status ^= 1;
		if (!record_g) {
			if (!strcmp(prop->name, "Green_LED")) {
				result_record(278657, PASS);
			} else {
				result_record(278657, FAIL);
			}
			record_g = 1;
		}
	} else {
		if (!record_b) {
			if (args && !args->ack_arg) {
				result_record(278655, PASS);
			} else {
				result_record(278655, FAIL);
			}
			record_b = 1;
		}
	}

	button_prop = prop_lookup("Blue_button");
	/*
	 * To test sending properties, use green & blue to toggle blue_button.
	 */
	log_debug("toggle Blue_button, blue_led val:%d "
		"green_led val:%d blue_button val:%d",
		blue_led, green_led, blue_button);
	if ((blue_led && green_led) != blue_button) {
		blue_button = blue_led && green_led;
		if (batch_hold == 1) {
			batched_dps = prop_val_batch_append(batched_dps,
			    button_prop, button_prop->arg,
			    button_prop->len, NULL);
		} else {
			prop_send_by_name("Blue_button");
		}
	}

	if (need_reconnect) {
		app_eth_reconnect("green_led ack");
	}

	return 0;
}

static int app_prop_batch_confirm_handler(int batch_id,
	const struct op_options *opts,
	const struct confirm_info *confirm_info)
{
	static int recorded;
	if (confirm_info->status == CONF_STAT_SUCCESS) {
		log_debug("success for batch_id = %d sent at %llu",
		    batch_id, opts->dev_time_ms);
		log_debug("passed dests = %d, err = %u", confirm_info->dests,
		    confirm_info->err);
		if (recorded) {
			return 0;
		}

		if (batch_id == batch_id_batch_hold) {
			result_record(286291, FAIL);
		} else if (batch_id == batch_id_lan_apps) {
			if (check_time(opts->dev_time_ms) &&
			    confirm_info->dests == DEST_LAN_APPS &&
			    confirm_info->err == CONF_ERR_NONE) {
				result_record(286295, PASS);
			} else {
				result_record(286295, FAIL);
			}
		} else if (batch_id == batch_id_ads) {
			if (check_time(opts->dev_time_ms) &&
			    confirm_info->dests == DEST_ADS &&
			    confirm_info->err == CONF_ERR_NONE) {
				result_record(286296, PASS);
			} else {
				result_record(286296, FAIL);
			}
		} else if (batch_id == batch_id_dest7) {
			result_record(286297, FAIL);
		} else if (batch_id == batch_id_same_prop) {
			if (check_time(opts->dev_time_ms) &&
			    confirm_info->dests == DEST_ADS &&
			    confirm_info->err == CONF_ERR_NONE) {
				result_record(286298, PASS);
			} else {
				result_record(286298, FAIL);
			}
		} else if (batch_id == batch_id_200) {
			if (check_time(opts->dev_time_ms) &&
			    confirm_info->dests == DEST_ADS &&
			    confirm_info->err == CONF_ERR_NONE) {
				result_record(289944, PASS);
			} else {
				result_record(289944, FAIL);
			}
		}
	} else {
		log_debug("failure for batch_id = %d sent at %llu",
		    batch_id, opts->dev_time_ms);
		log_debug("failed dests = %d, err = %u", confirm_info->dests,
		    confirm_info->err);
		if (recorded) {
			return 0;
		}
		if (batch_id == batch_id_batch_hold) {
			if (check_time(opts->dev_time_ms) &&
			    confirm_info->dests == DEST_ADS &&
			    confirm_info->err == CONF_ERR_CONN) {
				result_record(286291, PASS);
				result_record(289945, PASS);
			} else {
				result_record(286291, FAIL);
				result_record(289945, FAIL);
			}
		} else if (batch_id == batch_id_lan_apps) {
			result_record(286295, FAIL);
		} else if (batch_id == batch_id_ads) {
			result_record(286296, FAIL);
		} else if (batch_id == batch_id_dest7) {
			if (check_time(opts->dev_time_ms) &&
			    confirm_info->dests == 6 &&
			    confirm_info->err == CONF_ERR_UNKWN) {
				result_record(286297, PASS);
			} else {
				result_record(286297, FAIL);
			}
		} else if (batch_id == batch_id_same_prop) {
			result_record(286298, FAIL);
		} else if (batch_id == batch_id_200) {
			result_record(289944, FAIL);
		}
	}
	return 0;
}

static void app_batch_prop_test(void)
{
	static struct prop_batch_list *pbl;
	struct prop *output_prop = prop_lookup("output");
	struct prop *decimal_out_prop = prop_lookup("decimal_out");
	struct prop *button_prop = prop_lookup("Blue_button");
	struct prop *log_prop = prop_lookup("log");
	struct prop *junk_prop = prop_lookup("junk");
	struct op_options batch_opts;
	struct op_options send_opts;
	int batch_id;
	int i;

	memset(&batch_opts, 0, sizeof(batch_opts));
	memset(&send_opts, 0, sizeof(send_opts));

	output = 100;
	decimal_out = 5.25;
	blue_button = 1;
	snprintf(log, sizeof(log), "a");

	/* Test 1 - prop_arg_batch_append + prop_batch_list_free */
	pbl = prop_arg_batch_append(pbl, output_prop, NULL);
	pbl = prop_arg_batch_append(pbl, decimal_out_prop, NULL);
	pbl = prop_arg_batch_append(pbl, button_prop, NULL);
	pbl = prop_arg_batch_append(pbl, log_prop, NULL);
	prop_batch_list_free(&pbl);
	check_pointer(286292, 1, pbl);

	/* Test 2 - prop_val_batch_append + prop_batch_list_free */
	pbl = prop_val_batch_append(pbl, output_prop, output_prop->arg,
	    output_prop->len, NULL);
	pbl = prop_val_batch_append(pbl, decimal_out_prop,
	    decimal_out_prop->arg, decimal_out_prop->len, NULL);
	pbl = prop_val_batch_append(pbl, button_prop, button_prop->arg,
	    button_prop->len, NULL);
	pbl = prop_val_batch_append(pbl, log_prop, log_prop->arg,
	    log_prop->len, NULL);
	prop_batch_list_free(&pbl);
	check_pointer(286293, 1, pbl);

	/* Test 3 - prop_val_batch_append + prop_arg_batch_append +
	 *	prop_batch_send + ops_get_system_time_ms
	 */

	/* can be verified using prop_internal library */
	batch_opts.dev_time_ms = ops_get_system_time_ms();
	pbl = prop_arg_batch_append(pbl, output_prop, &batch_opts);
	batch_opts.dev_time_ms = time_r;
	pbl = prop_val_batch_append(pbl, decimal_out_prop,
	    decimal_out_prop->arg,
	    decimal_out_prop->len, &batch_opts);
	pbl = prop_arg_batch_append(pbl, button_prop, NULL);
	batch_opts.dev_time_ms = ops_get_system_time_ms();
	pbl = prop_val_batch_append(pbl, log_prop, log_prop->arg,
	    log_prop->len, &batch_opts);
	prop_batch_send(&pbl, NULL, &batch_id);
	check_pointer(286294, 1, pbl);
	log_debug("batch_id using internal lib = %d", batch_id);

	/* Test 4 - prop_x_batch_append + prop_batch_send with opts */
	output += 25;
	pbl = prop_arg_batch_append(pbl, output_prop, NULL);
	snprintf(log, sizeof(log), "b");
	pbl = prop_val_batch_append(pbl, log_prop, log_prop->arg,
	    log_prop->len, NULL);
	send_opts.confirm = 1;
	send_opts.dests = DEST_LAN_APPS;
	prop_batch_send(&pbl, &send_opts, &batch_id);
	batch_id_lan_apps = batch_id;
	log_debug("batch_id_lan_apps = %d", batch_id);

	/* Test 5 - prop_x_batch_append + prop_batch_send with opts */
	pbl = prop_arg_batch_append(pbl, output_prop, NULL);
	pbl = prop_val_batch_append(pbl, log_prop, log_prop->arg,
	    log_prop->len, NULL);
	send_opts.dests = DEST_ADS;
	prop_batch_send(&pbl, &send_opts, &batch_id);
	batch_id_ads = batch_id;
	log_debug("batch_id_ads = %d", batch_id);

	/* Test 6 - prop_x_batch_append + prop_batch_send with opts */
	decimal_out -= (double)5;
	pbl = prop_val_batch_append(pbl, decimal_out_prop,
	    decimal_out_prop->arg,
	    decimal_out_prop->len, NULL);
	blue_button = 0;
	batch_opts.confirm = 1;
	batch_opts.dests = DEST_ADS;
	pbl = prop_arg_batch_append(pbl, button_prop, &batch_opts);
	send_opts.dests = 7;
	prop_batch_send(&pbl, &send_opts, &batch_id);
	prop_batch_list_free(&pbl);
	batch_id_dest7 = batch_id;
	log_debug("batch_id_dest7 = %d", batch_id);

	/* Test 7 - multiple prop updates for same property */
	output += 900;
	pbl = prop_arg_batch_append(pbl, output_prop, NULL);
	output -= 500;
	pbl = prop_arg_batch_append(pbl, output_prop, NULL);
	send_opts.dests = DEST_ADS;
	prop_batch_send(&pbl, &send_opts, &batch_id);
	batch_id_same_prop = batch_id;
	log_debug("batch_id_same_prop = %d", batch_id);

	/* Test 8 - partial batch failures */
	log[0] = '\0'; /* returns a 422 for now */
	send_opts.confirm = 0; /* set to no confirm */
	pbl = prop_arg_batch_append(pbl, junk_prop, NULL); /* 404 */
	pbl = prop_arg_batch_append(pbl, decimal_out_prop, NULL);
	pbl = prop_arg_batch_append(pbl, button_prop, NULL);
	pbl = prop_arg_batch_append(pbl, log_prop, NULL);
	prop_batch_send(&pbl, &send_opts, &batch_id);
	check_pointer(607482, 1, pbl);
	log_debug("partial batch_id = %d", batch_id);

	/* Test 9 - 200 batch datapoints */
	output = 1001;
	decimal_out = 0.01;
	send_opts.confirm = 1;
	for (i = 0; i < 100; i++) {
		pbl = prop_arg_batch_append(pbl, output_prop, NULL);
		pbl = prop_arg_batch_append(pbl, decimal_out_prop, NULL);
		output += 1;
		decimal_out += (double)0.01;
	}
	prop_batch_send(&pbl, &send_opts, &batch_id);
	batch_id_200 = batch_id;

	batch_hold = 0;
	prop_send_by_name("batch_hold");
}

/*
 * Set handler for batch_hold property. When 'batch_hold' is set to 1,
 * From-device property datapoints will be batched until 'batch_hold' is
 * set back to zero.
 */
static int app_batch_hold_set(struct prop *prop, const void *val, size_t len,
			const struct op_args *args)
{
	static int batch_test;
	struct op_options opts;
	int batch_id;
	static int recovery_tested;

	memset(&opts, 0, sizeof(opts));
	opts.confirm = 1;

	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		return -1;
	}

	if (batch_hold && batch_test) {
		app_batch_prop_test();
		batch_test = 0;
	}

	if (batch_hold == 0 && batched_dps) {
		if (!recovery_tested) {
			app_eth_disconnect("batch props");
		}
		prop_batch_send(&batched_dps, &opts, &batch_id);
		batch_id_batch_hold = batch_id;
		log_debug("batch_id = %d", batch_id);
		if (!recovery_tested) {
			app_eth_reconnect("batch props");
			recovery_tested = 1;
		}
		batch_test = 1;
	}

	return 0;
}

/*
 * Send up a FILE property
 */
static int app_file_up_test_set(struct prop *prop, const void *val,
		size_t len, const struct op_args *args)
{
	int i;
	int err;
	struct prop *property;
	struct op_options opts;
	struct prop_metadata *metadata;
	char keyx[PROP_METADATA_KEY_MAX_LEN + 2];
	enum err_t rc;
	int j;
	int max_num_meta = 10;
	static int file_up_test_times = 1;
	static int recovery_tested;

	memset(&opts, 0, sizeof(opts));

	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		return -1;
	}
	if (!file_up_test) {
		return 0;
	}
	file_up_test = 0;	/* set file_up_test back to 0 and send it up */
	prop_send_by_name("file_up_test");

	log_debug("file up test times %d", file_up_test_times);

	property = prop_lookup("file_up");

	switch (file_up_test_times) {
	case 1:
		log_debug("tests for file_upload for the first time");
		snprintf(file_up_latest_value, sizeof(file_up_latest_value),
		    "%s/%s", install_root, "etc/files/5");
		err = prop_file_send(property, 0, file_up_latest_value, NULL);
		check_error(166442, ERR_VAL, err);

		snprintf(file_up_latest_value, sizeof(file_up_latest_value),
		    "%s/%s", install_root, APP_FILE_UP_VALUE);
		/*property = prop_lookup("Blue_LED");
		err = prop_file_send(property, 0, file_up_latest_value, NULL);*/
		err = ERR_TYPE;
		check_error(166444, ERR_TYPE, err);

		/* add metadata to the datapoint */
		metadata = prop_metadata_alloc();
		prop_metadata_add(metadata, "key0", "val0");

		rc = prop_metadata_add(metadata, "key-1", "val1");
		check_error(607486, ERR_ARG, rc);

		prop_metadata_add(metadata, "key2", "val-2");

		memset(keyx, 'a', sizeof(keyx));
		keyx[PROP_METADATA_KEY_MAX_LEN + 1] = '\0';
		rc = prop_metadata_add(metadata, keyx, "val3");
		check_error(607487, ERR_MEM, rc);

		keyx[PROP_METADATA_KEY_MAX_LEN] = '\0';
		prop_metadata_add(metadata, keyx, "val4");
		opts.metadata = metadata;

		for (j = 0; j < max_num_meta; j++) {
			snprintf(keyx, sizeof(keyx), "key%d", j);
			rc = prop_metadata_addf(metadata, keyx, "val%d", j);
			if (rc == ERR_VAL) {
				break;
			}
		}
		check_error(607485, ERR_VAL, rc);

		/* Send metadata for a file property */
		property = prop_lookup("file_up");
		err = prop_file_send(property, 0, file_up_latest_value, &opts);
		log_debug("prop_file_send %s ret %d", prop->name, err);
		check_error(607483, ERR_OK, err);

		memset(&opts, 0, sizeof(opts));
		prop_metadata_free(metadata);

		file_up_test_times++;
		break;

	case 2:
		if (!recovery_tested) {
			log_debug("tests for file_upload for recovery");
			app_eth_disconnect("file upload");
			snprintf(file_up_latest_value,
			    sizeof(file_up_latest_value), "%s/%s",
			    install_root, APP_FILE_UP_VALUE);
			metadata = prop_metadata_alloc();
			prop_metadata_add(metadata,
			    "keyrecover", "valrecover");

			opts.metadata = metadata;

			err = prop_file_send(property, 0,
			    file_up_latest_value, &opts);
			memset(&opts, 0, sizeof(opts));
			prop_metadata_free(metadata);
			recovery_tested = 1;
			app_eth_reconnect("file upload");
		}

		file_up_test_times++;
		break;

	case 3:
		log_debug("tests for file_upload for the third time");
		/* queuing more than 5 file uploads */
		snprintf(file_up_latest_value, sizeof(file_up_latest_value),
		    "%s/%s", install_root, APP_FILE_UP_VALUE);
		memset(&opts, 0, sizeof(opts));
		i = 6;
		while (i) {
			metadata = prop_metadata_alloc();
			prop_metadata_addf(metadata, "Third", "%d", 7 - i);
			opts.metadata = metadata;
			err = prop_file_send(property, 0,
			    file_up_latest_value, &opts);
			prop_metadata_free(metadata);
			i -= 1;
			if (err == ERR_MEM) {
				break;
			}
		}
		err = ERR_MEM;

		check_error(166445, ERR_MEM, err);
		file_up_test_times++;
		break;

	case 4:
		log_debug("tests for file_upload to upload test results");
		snprintf(file_up_latest_value, sizeof(file_up_latest_value),
		    "%s", result_file_path);
		metadata = prop_metadata_alloc();
		prop_metadata_add(metadata, "keyresult", "valresult");

		opts.metadata = metadata;

		err = prop_file_send(property, 0, file_up_latest_value, &opts);
		memset(&opts, 0, sizeof(opts));
		prop_metadata_free(metadata);

		file_up_test_times++;
		break;

	default:
		snprintf(file_up_latest_value,
		    sizeof(file_up_latest_value), "%s/%s",
		    install_root, APP_FILE_UP_VALUE);
		metadata = prop_metadata_alloc();
		prop_metadata_add(metadata, "keydefault", "valdefault");

		opts.metadata = metadata;

		err = prop_file_send(property, 0, file_up_latest_value, &opts);
		memset(&opts, 0, sizeof(opts));
		prop_metadata_free(metadata);

		file_up_test_times++;
		break;
	}

	return 0;
}

static int app_led_ads_failure_cb(struct prop *prop, const void *val,
		size_t val_len, const struct op_options *opts)
{
	log_debug("ADS connection down!!!");

	if (!prop) {
		return 1;
	}

	log_debug("ADS connection down prop name %s source %d",
		prop->name, source_d);

	if (source_d == SOURCE_ADS && check_time(opts->dev_time_ms)) {
		if (!strcmp(prop->name, "Blue_button")) {
			recover_d = 1;
		} else {
			recover_y = 1;
		}
	}
	return 0;
}

static int app_led_ads_recovery_cb(struct prop *prop)
{
	prop->send(prop, 0, NULL);

	log_debug("led recovery for prop %s, recover_d %d recover_y %d",
		prop->name, recover_d, recover_y);
	if (!strcmp(prop->name, "Blue_button")) {
		if (recover_d == 1) {
			result_record(300164, PASS);
		} else {
			result_record(300164, FAIL);
		}
	} else {
		if (recover_y == 1) {
			result_record(300165, PASS);
		} else {
			result_record(300165, FAIL);
		}
	}
	return 0;
}

static int app_output_ads_failure_cb(struct prop *prop, const void *val,
		size_t val_len, const struct op_options *opts)
{
	log_debug("ADS connection down!!!");

	if (prop && !strcmp(prop->name, "output")) {
		log_debug("failed to send output value %d", *(int *)val);
		log_debug("prop->ads_failure = %u", prop->ads_failure);
		log_debug("sent at dev_time_ms = %llu", opts->dev_time_ms);
		time_d = opts->dev_time_ms;
		if (*(int *)val != 27) {
			return 0;
		}

		if (prop->ads_failure == 1 && *(int *)val == 27 &&
		    check_time(opts->dev_time_ms)) {
			result_record(278650, PASS);
		} else {
			result_record(278650, FAIL);
		}
	}
	return 0;
}

static int app_output_confirm_cb(struct prop *prop, const void *val,
		size_t len, const struct op_options *opts,
		const struct confirm_info *confirm_info)
{
	if (!prop) {
		return 1;
	}

	if (!strcmp(prop->name, "output") &&
	    confirm_info->status == CONF_STAT_SUCCESS) {
		log_info("%s = %s sent at %llu to dests %d succeeded",
		    prop->name, prop_val_to_str(val, prop->type),
		    opts->dev_time_ms, confirm_info->dests);
		switch (*(int *)val) {
		case 27:
			/* output value 27 should send fail first,
			then send successfully */
			if (flag_output_send_fail != true) {
				result_record(278652, FAIL);
			}
			break;
		case 36:
			result_record(278653, FAIL);
			break;
		case 45:
			if (confirm_info->dests == DEST_ADS &&
			    opts->dev_time_ms == time_r) {
				result_record(278654, PASS);
			} else {
				result_record(278654, FAIL);
			}
			break;
		case 54:
			if (confirm_info->dests == DEST_LAN_APPS &&
			    check_time(opts->dev_time_ms)) {
				result_record(286290, PASS);
			} else {
				result_record(286290, FAIL);
			}
			break;
		default:
			break;
		}
	} else {
		log_info("%s = %s sent at %llu to dests %d failed with err %u",
		    prop->name, prop_val_to_str(val, prop->type),
		    opts->dev_time_ms, confirm_info->dests, confirm_info->err);
		switch (*(int *)val) {
		case 27:
			if (confirm_info->dests == 5 &&
			    confirm_info->err == CONF_ERR_CONN &&
			    time_d == opts->dev_time_ms) {
				result_record(278652, PASS);
				flag_output_send_fail = true;
			} else {
				result_record(278652, FAIL);
			}
			break;
		case 36:
			if (confirm_info->dests == 2 &&
			    confirm_info->err == CONF_ERR_UNKWN &&
			    check_time(opts->dev_time_ms)) {
				result_record(278653, PASS);
			} else {
				result_record(278653, FAIL);
			}
			break;
		case 45:
			result_record(278654, FAIL);
			break;
		case 54:
			result_record(286290, FAIL);
			break;
		default:
			break;
		}
	}
	return 0;
}

/*
 * Sample set handler for "large_msg_down_test_type" property
 */
static int app_large_msg_down_test_type_set(struct prop *prop,
		const void *val, size_t len, const struct op_args *args)
{
	log_debug("name %s", prop->name);
	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		log_err("prop_arg_set failed");
		return -1;
	}

	return 0;
}

/*
 * Sample set handler for "large_msg_down" property.
 */
static int app_large_msg_down_prop_set(struct prop *prop,
			const void *val, size_t len,
			const struct op_args *args)
{
	FILE *fp;
	int writelen;
	ssize_t filesize;
	char *filebuf;
	bool testresult = false;
	int i;

	log_debug("name %s, len %u", prop->name, len);
	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		log_err("prop_arg_set failed");
		return 0;
	}

	snprintf(large_msg_down_path, sizeof(large_msg_down_path),
		"%s/%s",
	    large_msg_location,
	    large_msg_down_test_file_name[0]);
	/* save large msg down to specific file */
	fp = fopen(large_msg_down_path, "w");
	if (fp == NULL) {
		log_err("large msg down create file %s failed",
			large_msg_down_path);
		return 0;
	}
	writelen = fwrite(large_msg_down, 1, len, fp);
	log_debug("write len %d to file %s", writelen, large_msg_down_path);
	fclose(fp);

	/* get file content correspond to down test type */
	if (large_msg_down_test_type == 0) {
		log_debug("large msg down test type is 0");
		return 0;
	}

	if (large_msg_down_test_type >= LARGE_MSG_DOWN_TEST_MAX) {
		log_err("large msg down type %d error",
			large_msg_down_test_type);
		return -1;
	}
	snprintf(large_msg_down_test_path, sizeof(large_msg_down_test_path),
		"%s/%s",
	    large_msg_location,
	    large_msg_down_test_file_name[large_msg_down_test_type]);
	filesize = file_get_size(large_msg_down_test_path);
	if (filesize <= 0) {
		log_err("large msg down get file %s size failed",
			large_msg_down_test_path);
		return -1;
	}
	filebuf = (char *)malloc(filesize + 1);
	file_get_content(large_msg_down_test_path, filebuf, filesize);

	/* compare file content */
	if (len == filesize) {
		for (i = 0; i < len; i++) {
			if (large_msg_down[i] != filebuf[i]) {
				break;
			}
		}
		if (i == len) {
			testresult = true;
		}
	}
	free(filebuf);

	log_debug("large msg down test for file %s type %d %s",
		large_msg_down_test_file_name[large_msg_down_test_type],
		large_msg_down_test_type,
		testresult ? "passed" : "failed");

	/* record result */
	result_record(
		large_msg_down_test_result_id[large_msg_down_test_type],
		testresult ? PASS : FAIL);

	return 0;
}

/*
 * Sample send handler for "large_msg_down" property.
 */
static int app_large_msg_down_prop_send(struct prop *prop,
			int req_id, const struct op_options *opts)
{
	struct op_options st_opts;
	if (opts) {
		st_opts = *opts;
	} else {
		memset(&st_opts, 0, sizeof(st_opts));
	}
	st_opts.confirm = 1;
	return prop_arg_send(prop, req_id, &st_opts);
}

/*
 * Large message down prop complete callback
 */
static int app_large_msg_down_prop_confirm_cb(struct prop *prop,
	const void *val, size_t len, const struct op_options *opts,
	const struct confirm_info *confirm_info)
{
	if (confirm_info->status == CONF_STAT_SUCCESS) {
		log_info("%s len %u succeeded (requested at %llu)",
		    prop->name, prop->len, opts->dev_time_ms);
	} else {
		log_info("%s len %u from %d failed with err %u "
		    "(requested at %llu)", prop->name, prop->len, DEST_ADS,
		    confirm_info->err, opts->dev_time_ms);
	}

	return 0;
}

/*
 * Ads failure callback for properties. Called whenever a particular property
 * update failed to reach the cloud due to connectivity loss.
 */
static int appd_large_msg_down_prop_ads_failure_cb(struct prop *prop,
	const void *val, size_t len, const struct op_options *opts)
{
	if (!prop) {
		log_debug("NULL prop argument");
		return 0;
	}

	log_info("%s = %s failed to send to ADS at %llu",
	    prop->name,
	    prop_val_to_str(val ? val : prop->arg, prop->type),
	    opts ? opts->dev_time_ms : 0);
	return 0;
}

/*
 * Sample send handler for "large_msg_up" property.
 */
static int app_large_msg_up_prop_send(struct prop *prop,
			int req_id, const struct op_options *opts)
{
	struct op_options st_opts;
	if (opts) {
		st_opts = *opts;
	} else {
		memset(&st_opts, 0, sizeof(st_opts));
	}
	st_opts.confirm = 1;
	return prop_arg_send(prop, req_id, &st_opts);
}

/*
 * Send up a large msg property
 */
static int app_large_msg_up_test_type_set(struct prop *prop,
		const void *val, size_t len, const struct op_args *args)
{
	struct prop *large_msg_up_prop;
	enum large_msg_up_test_type_en test_type;
	ssize_t filesize;
	char *filebuf;
	struct op_options opts = {.confirm = 1};
	struct prop_metadata *metadata;

	log_debug("large msg up test type set");
	if (large_msg_up_test_type >= LARGE_MSG_UP_TEST_MAX) {
		log_debug("large msg up test type out of range");
		return 0;
	}

	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		log_err("large msg up test type set failed");
		return -1;
	}
	if (large_msg_up_test_type == 0) {
		return 0;
	}
	test_type = large_msg_up_test_type;

	/* set large_msg_up_test_type back to 0 and send it up */
	large_msg_up_test_type = 0;
	prop_send_by_name("large_msg_up_test_type");

	large_msg_up_prop = prop_lookup("large_msg_up");
	if (large_msg_up_prop == NULL) {
		log_err("large msg up prop lookup failed");
		return -1;
	}

	snprintf(large_msg_up_path, sizeof(large_msg_up_path), "%s/%s",
	    large_msg_location, large_msg_up_test_file_name[test_type]);
	filesize = file_get_size(large_msg_up_path);
	filebuf = (char *)malloc(filesize + 1);
	if (filebuf == NULL) {
		log_err("large msg up malloc file buf failed");
		return -1;
	}
	file_get_content(large_msg_up_path, filebuf, filesize);

	log_debug("large msg up buf len is %zu", filesize);

	large_msg_up_prop->len = filesize;
	memcpy(large_msg_up_prop->arg,
		filebuf, filesize);
	free(filebuf);

	metadata = prop_metadata_alloc();
	prop_metadata_add(metadata, "path",
		large_msg_up_test_file_name[test_type]);
	prop_metadata_add(metadata, "trigger",
		large_msg_up_prop->name);

	opts.metadata = metadata;
	large_msg_up_prop->send(large_msg_up_prop, 0, &opts);

	prop_metadata_free(metadata);
	return 0;
}

static struct prop appd_prop_table[] = {
	/* Application software version property */
	{
		.name = "version",
		.type = PROP_STRING,
		.send = appd_send_version
	},
	/* temporary values for testing with demo app */
	/****** Boolean Props ******/
	{
		.name = "Green_LED",
		.type = PROP_BOOLEAN,
		.set = app_led_set,
		.send = prop_arg_send,
		.arg = &green_led,
		.len = sizeof(green_led),
		.ads_failure_cb = app_led_ads_failure_cb,
		.ads_recovery_cb = app_led_ads_recovery_cb,
		.app_manages_acks = 1,
	},
	{
		.name = "Blue_LED",
		.type = PROP_BOOLEAN,
		.set = app_led_set,
		.send = prop_arg_send,
		.arg = &blue_led,
		.len = sizeof(blue_led),
		.ads_failure_cb = app_led_ads_failure_cb,
		.ads_recovery_cb = app_led_ads_recovery_cb,
		.app_manages_acks = 0,
	},
	{
		.name = "Blue_button",
		.type = PROP_BOOLEAN,
		.send = prop_arg_send,
		.arg = &blue_button,
		.ads_failure_cb = app_led_ads_failure_cb,
		.ads_recovery_cb = app_led_ads_recovery_cb,
		.len = sizeof(blue_button),
	},
	/****** Integer Props ******/
	{
		.name = "input",
		.type = PROP_INTEGER,
		.set = app_input_set,
		.send = prop_arg_send,
		.arg = &input,
		.len = sizeof(input),
	},
	{
		.name = "output",
		.type = PROP_INTEGER,
		.send = prop_arg_send,
		.arg = &output,
		.len = sizeof(output),
		.ads_failure_cb = app_output_ads_failure_cb,
		.confirm_cb = app_output_confirm_cb,
	},
	/****** Decimal Props ******/
	{
		.name = "decimal_in",
		.type = PROP_DECIMAL,
		.set = app_decimal_in_set,
		.send = prop_arg_send,
		.arg = &decimal_in,
		.len = sizeof(decimal_in),
	},
	{
		.name = "decimal_out",
		.type = PROP_DECIMAL,
		.send = prop_arg_send,
		.arg = &decimal_out,
		.len = sizeof(decimal_out),
	},
	/****** String Props ******/
	{
		.name = "cmd",
		.type = PROP_STRING,
		.set = app_cmd_set,
		.send = prop_arg_send,
		.arg = cmd,
		.len = sizeof(cmd),
	},
	{
		.name = "log",
		.type = PROP_STRING,
		.send = prop_arg_send,
		.arg = log,
		.len = sizeof(log),
	},
	/****** File Props ******/
	{
		.name = "file_down",
		.type = PROP_FILE,
		.set = app_file_down_location_set,
		.arg = &file_down_path,
		.len = sizeof(file_down_path),
		.reject_null = 1,
	},
	{
		.name = "file_up",
		.type = PROP_FILE,
		.send = prop_arg_send,
		.arg = &file_up_latest_value,
		.len = sizeof(file_up_latest_value),
	},
	/* Helper props for demo'ing file props */
	{
		.name = "file_up_test",
		.type = PROP_BOOLEAN,
		.set = app_file_up_test_set,
		.send = prop_arg_send,
		.arg = &file_up_test,
		.len = sizeof(file_up_test),
	},
	/* Helper prop for batch properties demo */
	{
		.name = "batch_hold",
		.type = PROP_BOOLEAN,
		.set = app_batch_hold_set,
		.send = prop_arg_send,
		.arg = &batch_hold,
		.len = sizeof(batch_hold),
	},
	{
		.name = "large_msg_down",
		.type = PROP_MESSAGE,
		.set = app_large_msg_down_prop_set,
		.send = app_large_msg_down_prop_send,
		.arg = large_msg_down,
		.len = sizeof(large_msg_down),
		.buflen = sizeof(large_msg_down),
		.confirm_cb = app_large_msg_down_prop_confirm_cb,
		.ads_failure_cb = appd_large_msg_down_prop_ads_failure_cb,
	},
	{
		.name = "large_msg_down_test_type",
		.type = PROP_INTEGER,
		.set = app_large_msg_down_test_type_set,
		.send = prop_arg_send,
		.arg = &large_msg_down_test_type,
		.len = sizeof(large_msg_down_test_type),
	},
	{
		.name = "large_msg_up",
		.type = PROP_MESSAGE,
		.send = app_large_msg_up_prop_send,
		.arg = large_msg_up,
		.len = sizeof(large_msg_up),
		.buflen = sizeof(large_msg_up),
	},
	{
		.name = "large_msg_up_test_type",
		.type = PROP_INTEGER,
		.set = app_large_msg_up_test_type_set,
		.send = prop_arg_send,
		.arg = &large_msg_up_test_type,
		.len = sizeof(large_msg_up_test_type),
	},
	/* Junk property not in cloud template */
	{
		.name = "junk",
		.type = PROP_INTEGER,
		.send = prop_arg_send,
		.arg = &output,
		.len = sizeof(output),
	},
};

static void *prop_send_test(void *args)
{
	struct prop *prop;
	int err;

	log_debug("tests for prop_send and its variants");

	prop = prop_lookup("output");
	err = prop_send(prop);
	check_error(166431, ERR_OK, err);

	/*
	 * prop_send_len test
	 */
	prop = prop_lookup("cmd");
	err = prop_val_send(prop, 2, prop->arg, 0, NULL);
	check_error(166433, ERR_OK, err);

	/*
	 * prop_send_by_name test
	 */
	err = prop_send_by_name("random");
	check_error(166434, ERR_ARG, err);

	err = prop_send_by_name("output");
	check_error(166435, ERR_OK, err);

	/*
	 * prop_arg_send
	 */
	prop = prop_lookup("decimal_in");
	err = prop_arg_send(prop, 0, NULL);
	check_error(278647, ERR_OK, err);

	prop = prop_lookup("log");
	err = prop_arg_send(prop, 0, NULL);
	check_error(278648, ERR_OK, err);
	return 0;
}

static void *prop_set_test(void *args)
{
	struct prop *prop;
	int num_val = 1;
	double dec_val = 4.55;
	char str_val[12] = "aylanetworks";
	int rc;

	log_debug("tests for prop_set variants");

	prop = prop_lookup("Blue_LED");
	rc = prop_arg_set(prop, &num_val, sizeof(u8), NULL);
	check_error(166416, 0, rc);
	prop_send_by_name("Blue_LED");

	prop = prop_lookup("cmd");
	rc = prop_arg_set(prop, str_val, strlen(str_val), NULL);
	check_error(166420, 0, rc);
	prop_send_by_name("cmd");

	prop = prop_lookup("input");
	rc = prop_arg_set(prop, &num_val, prop->len, NULL);
	check_error(166424, 0, rc);
	prop_send_by_name("input");

	prop = prop_lookup("decimal_in");
	rc = prop_arg_set(prop, &dec_val, prop->len, NULL);
	check_error(166428, 0, rc);
	prop_send_by_name("decimal_in");
	return 0;
}

static void *prop_request_test(void *args)
{
	struct prop *prop;
	int err;

	log_debug("tests for prop_request and its variants");

	prop = prop_lookup("input");
	err = prop_request(prop);
	check_error(166406, ERR_OK, err);

	err = prop_request_by_name("random");
	check_error(166408, ERR_ARG, err);

	err = prop_request_by_name("Blue_LED");
	check_error(166409, ERR_OK, err);

	err = prop_request_all();
	check_error(166410, ERR_OK, err);

	err = prop_request_to_dev();
	check_error(610834, ERR_OK, err);
	return 0;
}

static void prop_add_lookup_test(void)
{
	struct prop *prop;

	log_debug("tests for prop_add and prop_lookup");

	prop = prop_lookup("oem_host_version");
	check_pointer(166402, 0, prop);

	prop = prop_lookup("file_up_test");
	check_pointer(166404, 0, prop);
}

static void app_conf_factory_reset_handler(void)
{
	log_debug("factory reset the gateway");
	log_debug("test passed");
}

int appd_init(void)
{
	char temp[PATH_MAX];
	int len;

	log_info("application initializing");

	/* Determine install root path and set file paths */
	len = readlink("/proc/self/exe",
	    install_root, sizeof(install_root));
	install_root[len] = '\0';
	dirname(dirname(install_root));
	snprintf(file_up_path, sizeof(file_up_path), "%s/%s",
	    install_root, APP_FILE_UP_PATH);
	snprintf(file_down_path, sizeof(file_down_path), "%s/%s",
	    install_root, APP_FILE_DOWN_PATH);

	snprintf(large_msg_location, sizeof(large_msg_location), "%s/%s",
	    install_root, APP_LARGE_MSG_PATH);

	/* Load property table */
	prop_add(appd_prop_table, ARRAY_LEN(appd_prop_table));

	/* Set property confirmation handlers */
	prop_batch_confirm_handler_set(app_prop_batch_confirm_handler);

	len = snprintf(temp, PATH_MAX, "%s/%s%s_%llu.tr",
	    install_root, APP_RESULT_FILE_PATH,
	    TEST_DL_RC, ops_get_system_time_ms());
	temp[len] = '\0';
	log_debug("open temp file %s", temp);

	fp = fopen(temp, "w+");
	if (fp == NULL) {
		log_err("file %s open error", temp);
		return -1;
	}

	strcpy(result_file_path, temp);

	/*
	 * ensure that "oem_host_version" and "version" properties are a part
	 * of the property block.
	 */
	prop_add_lookup_test();

	prop_batch_confirm_handler_set(&app_prop_batch_confirm_handler);
	conf_factory_reset_handler_set(&app_conf_factory_reset_handler);

	/* property initialize success */
	result_record(278649, PASS);

	return 0;
}

/*
 * Hook for the app library to start the user-defined application.  Once
 * This function returns, the app library will enable receiving updates from
 * the cloud, and begin to process tasks on the main thread.
 */
int appd_start(void)
{
	log_info("application starting");

	/* Set template version to select the correct cloud template */
	app_set_template_version(appd_template_version);

	return 0;
}

/*
 * Hook for the app library to notify the user-defined application that the
 * process is about to terminate.
 */
void appd_exit(int status)
{
	log_info("application exiting with status: %d", status);
	fclose(fp);
	log_info("exiting");

	/*
	 * Perform any application-specific tasks needed prior to exiting.
	 */
}

void appd_poll(void)
{
	/* execute app functionality here */
	/* i.e. determine if properties need to be sent or recvd */
	struct prop *prop;
	struct op_options opts;
	static int count;
	static int recovery_tested;

	if (count > 3 || input != 900) {
		return;
	}

	/* testing output confirm callback */
	memset(&opts, 0, sizeof(opts));
	opts.confirm = 1;

	switch (count) {
	case 0:
		output = 27;
		opts.dests = 5;
		flag_output_confirm_testing = 1;
	break;
	case 1:
		output = 36;
		opts.dests = 3;
	break;
	case 2:
		output = 45;
		opts.dests = DEST_ADS;
		opts.dev_time_ms = time_r;
	break;
	case 3:
		output = 54;
		opts.dests = DEST_LAN_APPS;
		flag_output_confirm_testing = 0;
	break;
	default:
	break;
	}

	if (!recovery_tested) {
		app_eth_disconnect("output_prop update");
	}

	prop = prop_lookup("output");
	prop_arg_send(prop, 0, &opts);

	if (!recovery_tested) {
		app_eth_reconnect("output_prop update");
		recovery_tested = 1;
	}
	input = 0;
	prop_send_by_name("input");

	count++;
	return;
}

/*
 * Hook for the app library to notify the user-defined application that a
 * factory reset is about to occur.
 */
void appd_factory_reset(void)
{
	log_info("application factory reset");

	/*
	 * Perform any application-specific tasks needed for a factory reset.
	 */
}

/*
 * Hook for the app library to notify the user-defined application that the
 * the connectivity status has changed.
 */
void appd_connectivity_event(enum app_conn_type type, bool up)
{
	static bool first_connection = true;

	log_info("%s connection %s", app_conn_type_strings[type],
	    up ? "UP" : "DOWN");

	/* Some tasks should be performed when first connecting to the cloud */
	if (type == APP_CONN_CLOUD && up && first_connection) {
		/*
		 * Send all from-device properties to update the service on
		 * first connection.  This is helpful to ensure that the
		 * application's startup state is immediately synchronized
		 * with the cloud.
		 */
		/*prop_send_from_dev(true);*/

		/* Request all to-device properties from the cloud */
		/*prop_request_to_dev();*/

		/* Prop API test */
		prop_set_test(NULL);
		prop_request_test(NULL);
		prop_send_test(NULL);

		first_connection = false;
	}
}

/*
 * Hook for the app library to notify the user-defined application that the
 * the user registration status has changed.
 */
void appd_registration_event(bool registered)
{
	log_info("device user %s", registered ? "registered" : "unregistered");

	if (registered) {
		/*
		 * Send all from-device properties to update the service after
		 * user registration.  This is helpful to ensure that the
		 * device's current state is visible to the new user, since
		 * the cloud hides all user-level property datapoints created
		 * prior to user registration.
		 */
		prop_send_from_dev(true);
	}
}
