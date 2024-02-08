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

#include <ayla/utypes.h>
#include <ayla/json_parser.h>
#include <ayla/ayla_interface.h>
#include <ayla/log.h>
#include <ayla/build.h>

#include <ayla/ops.h>
#include <ayla/props.h>
#include <ayla/data.h>
#include <ayla/conf_access.h>
#include <ayla/sched.h>

#include "app.h"

const char oem_host_version[] = "appd_demo 1.3";
const char version[] = "appd_demo " BUILD_VERSION_LABEL;

#define APP_FILE_UP_PATH "../etc/files/ayla_solution.png"
#define APP_FILE_DOWN_PATH "../etc/files/file_down"

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

/* file location of the latest value of file_down */
static char file_down_path[PATH_MAX] = APP_FILE_DOWN_PATH;

/* file location of the latest value of file_up */
static char file_up_path[PATH_MAX] = APP_FILE_UP_PATH;

/*
 * File download complete callback
 */
static int app_file_down_confirm_cb(struct prop *prop, const void *val,
	size_t len, const struct op_options *opts,
	const struct confirm_info *confirm_info)
{
	if (confirm_info->status == CONF_STAT_SUCCESS) {
		log_info("%s download succeeded (requested at %llu)",
		    prop->name, opts->dev_time_ms);
	} else {
		log_info("%s download from %d failed with err %u "
		    "(requested at %llu)", prop->name, DEST_ADS,
		    confirm_info->err, opts->dev_time_ms);
	}

	return 0;
}

/*
 * File upload complete callback
 */
static int app_file_up_confirm_cb(struct prop *prop, const void *val,
	size_t len, const struct op_options *opts,
	const struct confirm_info *confirm_info)
{
	if (confirm_info->status == CONF_STAT_SUCCESS) {
		log_info("%s upload succeeded (requested at %llu)",
		    prop->name, opts->dev_time_ms);
	} else {
		log_info("%s upload to %d failed with err %u "
		    "(requested at %llu)", prop->name, DEST_ADS,
		    confirm_info->err, opts->dev_time_ms);
	}

	return 0;
}

/*
 * Confirm callback for properties
 */
static int app_prop_confirm_cb(struct prop *prop, const void *val, size_t len,
	    const struct op_options *opts,
	    const struct confirm_info *confirm_info)
{
	if (!prop) {
		log_debug("NULL prop argument");
		return 0;
	}

	if (confirm_info->status == CONF_STAT_SUCCESS) {
		log_info("%s = %s send at %llu to dests %d succeeded",
		    prop->name, prop_val_to_str(val, prop->type),
		    opts->dev_time_ms, confirm_info->dests);
	} else {
		log_info("%s = %s send at %llu to dests %d failed with err %u",
		    prop->name, prop_val_to_str(val, prop->type),
		    opts->dev_time_ms, confirm_info->dests, confirm_info->err);
	}
	return 0;
}

/*
 * Confirm callback for properties
 */
static int app_batch_confirm_handler(int batch_id,
	    const struct op_options *opts,
	    const struct confirm_info *confirm_info)
{
	if (confirm_info->status == CONF_STAT_SUCCESS) {
		log_info("Batch id %d send at %llu to dests %d succeeded",
		    batch_id, opts->dev_time_ms, confirm_info->dests);
	} else {
		log_info("Batch id %d send at %llu to dests %d failed "
		    "with err %u", batch_id, opts->dev_time_ms,
		    confirm_info->dests, confirm_info->err);
	}

	return 0;
}

/*
 * Ads failure callback for properties. Called whenever a particular property
 * update failed to reach the cloud due to connectivity loss.
 */
static int app_prop_ads_failure_cb(struct prop *prop, const void *val,
	size_t len, const struct op_options *opts)
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
 * Sample set handler for "input" property.  Squares "input" and sends result
 * as the "output" property.
 */
static int app_input_set(struct prop *prop, const void *val, size_t len,
			const struct op_args *args)
{
	struct op_options opts = {.confirm = 1};
	struct prop_batch_list *result;
	struct prop *output_prop;
	struct prop_metadata *metadata;

	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		return -1;
	}

	/* For purposes of the demo, put the square of input into "output" */
	if (input > 46340 || input < -46340) {
		/* square would overflow */
		output = -1;
	} else {
		output = input * input;
	}
	/* Add some datapoint metadata */
	metadata = prop_metadata_alloc();
	prop_metadata_addf(metadata, "source", "%d x %d", input, input);
	opts.metadata = metadata;

	output_prop = prop_lookup("output");
	if (batch_hold) {
		/* batch the datapoint for sending later */
		result = prop_arg_batch_append(batched_dps, output_prop, &opts);
		if (result) {
			batched_dps = result;
		}
	} else {
		/* send out immediately */
		output_prop->send(output_prop, 0, &opts);
	}
	prop_metadata_free(metadata);
	return 0;
}

/*
 * Sample set handler for "cmd" property.  Copies new value to a "log"
 * property and sends it.
 */
static int app_cmd_set(struct prop *prop, const void *val, size_t len,
			const struct op_args *args)
{
	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		return -1;
	}

	/* for purposes of the demo, copy the value of cmd into log */
	snprintf(log, sizeof(log), "%s", cmd);
	prop_send_by_name("log");

	return 0;
}

/*
 * Sample set handler for "decimal_in" property.  Copies new value
 * to a "decimal_out" property and sends it.
 */
static int app_decimal_in_set(struct prop *prop, const void *val, size_t len,
				const struct op_args *args)
{
	struct prop *decimal_out_prop;

	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		return -1;
	}

	/* for purposes of the demo, copy the val to decimal_out */
	decimal_out = *(double *)val;
	decimal_out_prop = prop_lookup("decimal_out");

	if (batch_hold) {
		/* batch the datapoint for sending later */
		batched_dps = prop_arg_batch_append(batched_dps,
		    decimal_out_prop, NULL);
	} else {
		/* send out immediately */
		decimal_out_prop->send(decimal_out_prop, 0, NULL);
	}

	return 0;
}

/*
 * Set handler for batch_hold property. When 'batch_hold' is set to 1,
 * 'decimal_out' and 'output' datapoints will be batched until 'batch_hold' is
 * set back to zero.
 */
static int app_batch_hold_set(struct prop *prop, const void *val, size_t len,
			const struct op_args *args)
{
	struct op_options opts = {.confirm = 1};

	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		return -1;
	}
	if (!batch_hold && batched_dps) {
		prop_batch_send(&batched_dps, &opts, NULL);
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
	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		return -1;
	}

	/*
	 * To test sending properties, use green & blue to toggle blue_button.
	 */
	if ((blue_led && green_led) != blue_button) {
		blue_button = blue_led && green_led;
		prop_send_by_name("Blue_button");
	}
	return 0;
}

/*
 * Send up a FILE property
 */
static int app_file_up_test_set(struct prop *prop, const void *val, size_t len,
				const struct op_args *args)
{
	struct op_options opts = {.confirm = 1};
	struct prop_metadata *metadata;
	struct prop *file_up_prop;

	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		return -1;
	}

	if (!file_up_test) {
		return 0;
	}
	/* Set file_up_test back to 0 and send it up */
	file_up_test = 0;
	prop_send(prop);

	/* Include some datapoint metadata with the file */
	metadata = prop_metadata_alloc();
	prop_metadata_add(metadata, "path", file_up_path);
	prop_metadata_add(metadata, "trigger", prop->name);

	/* Begin sending file */
	file_up_prop = prop_lookup("file_up");
	opts.metadata = metadata;
	file_up_prop->send(file_up_prop, 0, &opts);

	prop_metadata_free(metadata);
	return 0;
}

static struct prop app_prop_table[] = {
	/* required properties for Ayla devices to associate proper template */
	{
		.name = "oem_host_version",
		.type = PROP_STRING,
		.send = prop_arg_send,
		.arg = (char *)oem_host_version,
		.len = sizeof(oem_host_version),
	},
	{
		.name = "version",
		.type = PROP_STRING,
		.send = prop_arg_send,
		.arg = (char *)version,
		.len = sizeof(version),
	},
	/* sample properties for testing with demo app */
	/****** Boolean Props ******/
	{
		.name = "Green_LED",
		.type = PROP_BOOLEAN,
		.set = app_led_set,
		.send = prop_arg_send,
		.arg = &green_led,
		.len = sizeof(green_led),
		.ads_failure_cb = app_prop_ads_failure_cb,
	},
	{
		.name = "Blue_LED",
		.type = PROP_BOOLEAN,
		.set = app_led_set,
		.send = prop_arg_send,
		.arg = &blue_led,
		.len = sizeof(blue_led),
		.ads_failure_cb = app_prop_ads_failure_cb,
	},
	{
		.name = "Blue_button",
		.type = PROP_BOOLEAN,
		.send = prop_arg_send,
		.arg = &blue_button,
		.len = sizeof(blue_button),
		.ads_failure_cb = app_prop_ads_failure_cb,
	},
	/****** Integer Props ******/
	{
		.name = "input",
		.type = PROP_INTEGER,
		.set = app_input_set,
		.send = prop_arg_send,
		.arg = &input,
		.len = sizeof(input),
		.ads_failure_cb = app_prop_ads_failure_cb,
	},
	{
		.name = "output",
		.type = PROP_INTEGER,
		.send = prop_arg_send,
		.arg = &output,
		.len = sizeof(output),
		.confirm_cb = app_prop_confirm_cb,
		.ads_failure_cb = app_prop_ads_failure_cb,
	},
	/****** Decimal Props ******/
	{
		.name = "decimal_in",
		.type = PROP_DECIMAL,
		.set = app_decimal_in_set,
		.send = prop_arg_send,
		.arg = &decimal_in,
		.len = sizeof(decimal_in),
		.ads_failure_cb = app_prop_ads_failure_cb,
	},
	{
		.name = "decimal_out",
		.type = PROP_DECIMAL,
		.send = prop_arg_send,
		.arg = &decimal_out,
		.len = sizeof(decimal_out),
		.ads_failure_cb = app_prop_ads_failure_cb,
	},
	/****** String Props ******/
	{
		.name = "cmd",
		.type = PROP_STRING,
		.set = app_cmd_set,
		.send = prop_arg_send,
		.arg = cmd,
		.len = sizeof(cmd),
		.ads_failure_cb = app_prop_ads_failure_cb,
	},
	{
		.name = "log",
		.type = PROP_STRING,
		.send = prop_arg_send,
		.arg = log,
		.len = sizeof(log),
		.ads_failure_cb = app_prop_ads_failure_cb,
	},
	/****** File Props ******/
	{
		.name = "file_down",
		.type = PROP_FILE,
		.set = prop_arg_set,
		.arg = file_down_path,
		.len = sizeof(file_down_path),
		.confirm_cb = app_file_down_confirm_cb,
		.ads_failure_cb = app_prop_ads_failure_cb,
	},
	{
		.name = "file_up",
		.type = PROP_FILE,
		.send = prop_arg_send,
		.arg = file_up_path,
		.len = sizeof(file_up_path),
		.confirm_cb = app_file_up_confirm_cb,
		.ads_failure_cb = app_prop_ads_failure_cb,
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
	/*
	 * Helper prop for demo'ing batching. When 'batch_hold' is set to 1,
	 * 'decimal_out' and 'output' datapoints will be batched until
	 * 'batch_hold' is set back to zero.
	 */
	{
		.name = "batch_hold",
		.type = PROP_BOOLEAN,
		.set = app_batch_hold_set,
		.send = prop_arg_send,
		.arg = &batch_hold,
		.len = sizeof(batch_hold),
	},
};

static void app_poll(void)
{
	/* execute app functionality here */
	/* i.e. determine if properties need to be sent or recvd */
	return;
}

static void app_cloud_changed(bool connected)
{
	static bool first_connection = true;

	log_info("cloud connection %s", connected ? "UP" : "DOWN");

	if (connected && first_connection) {
		/*
		 * Send all from-device properties to update the service.
		 *
		 * NOTE: oem_host_version is a required property and MUST
		 * be sent first, as the service uses
		 * it to associate the device's template.
		 */
		prop_send_from_dev(true);

		/* Request all to-device properties from the cloud */
		prop_request_to_dev();

		first_connection = false;
	}
}

void app_start(void)
{
	int next_timeout;

	/* Begin processing scheduled events */
	sched_start();

	/* Allow updates in cloud to be fetched and sent to appd */
	ops_app_ready_for_cloud_updates();

	for (;;) {
		next_timeout = timer_advance(&timers);
		/* Poll occasionally if no timers are scheduled */
		if (next_timeout < 0) {
			next_timeout = DATA_POLL_INTERVAL;
		}
		/* Handle pending ops */
		if (ops_poll() < 0) {
			if (next_timeout > DATA_POLL_INTERVAL) {
				next_timeout = DATA_POLL_INTERVAL;
			}
		}
		/* Wait for file event or timer timeout */
		if (file_event_poll(&file_events, next_timeout) < 0) {
			return;
		}
		/* Application defined poll function */
		app_poll();
	}
}

void app_exit(void)
{
	log_info("exiting");
}

int app_init(void)
{
	/* Initialize appd operations queue (single-threaded) */
	ops_init(0, NULL);

	/* Initialize property handling library */
	prop_initialize();
	/* Load property table */
	prop_add(app_prop_table, ARRAY_LEN(app_prop_table));

	/* Initialize schedule handling subsystem */
	sched_init(&timers);

	/* Set event callbacks */
	prop_batch_confirm_handler_set(app_batch_confirm_handler);
	ops_set_cloud_connectivity_handler(app_cloud_changed);

	/* Open socket connection to devd */
	return data_client_init(&file_events);
}
