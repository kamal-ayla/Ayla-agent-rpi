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
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <poll.h>
#include <limits.h>
#include <sys/queue.h>

#include <ayla/utypes.h>
#include <ayla/assert.h>
#include <ayla/file_event.h>
#include <ayla/timer.h>
#include <ayla/json_parser.h>
#include <ayla/ayla_interface.h>
#include <ayla/log.h>
#include <ayla/build.h>
#include <ayla/ops.h>
#include <ayla/props.h>
#include <ayla/data.h>
#include <ayla/conf_access.h>
#include <ayla/sched.h>
#include <ayla/gateway_interface.h>
#include <ayla/gateway.h>

#include "app.h"

#define ETH_INTERFACE			1
#define PROP_METADATA_KEY_MAX_LEN	255
#define APP_RESULT_FILE_PATH		"../etc/files/"
#define PASS				1
#define FAIL				5

static int app_manages_acks;
static int skip = 4;
FILE *fp;

static int nodes_added;
const char oem_host_version[] = "generic_gateway_demo 1.5";
const char version[] = "gg_test " BUILD_VERSION_LABEL;
static u8 blue_button;
static u8 blue_led;
static u8 green_led;
static double decimal_in;
static double decimal_out;
static long input;
static long output;
static char cmd[PROP_STRING_LEN + 1];
static char log[PROP_STRING_LEN + 1];
static u8 node_batch_hold;
static struct gw_node_prop_batch_list *node_batched_dps;

/*
 * Struct for node results.
 */
struct appd_node_result {
	char info[PROP_STRING_LEN + 1];
	unsigned long int tc;
	u8 reported;
};

/*
 * Sample struct to maintain the node state and details.
 */
struct appd_node_state {
	char addr[GW_NODE_ADDR_SIZE];
	char version[PROP_STRING_LEN + 1];
	char oem_model[PROP_STRING_LEN + 1];
	enum gw_interface interface;
	enum gw_power  power;
	u8 node_status;
	u8 add_again;
	u8 update_again;
	u8 conn_again;
	u8 prop_send;
	u8 metadata;
};

/*
 * Sample struct to keep track of node properties.
 */
struct appd_node_props {
	char name[GW_PROPERTY_NAME_SIZE];
	const char *template_key;
	enum prop_type type;
	size_t val_len;
	void *val;
	int (*set) (struct gw_node_prop *prop,
	    enum prop_type type, const void *val, size_t val_len,
	    const struct op_args *args);
	u8 send_again;
};


static u8 gw_status;
static int gw_num_nodes;
static double gw_health;
static char gw_name[PROP_STRING_LEN + 1];
static u8 gw_batch_demo;
static int gw_update_node;

static int app_led_set(struct gw_node_prop *prop, enum prop_type type,
	const void *val, size_t val_len, const struct op_args *args);
static int app_cmd_set(struct gw_node_prop *prop, enum prop_type type,
	const void *val, size_t val_len, const struct op_args *args);
static int app_input_set(struct gw_node_prop *prop, enum prop_type type,
	const void *val, size_t val_len, const struct op_args *args);
static int app_decimal_in_set(struct gw_node_prop *prop, enum prop_type type,
	const void *val, size_t val_len, const struct op_args *args);
static int app_node_batch_hold_set(struct gw_node_prop *prop,
	enum prop_type type, const void *val,
	size_t val_len, const struct op_args *args);
static void app_node_update(const char *addr, int update_num);

static struct appd_node_state app_node[] = {
	{
		.addr = "node_1",
		.version = "2.0",
		.oem_model = "dpappnode",
		.interface = GI_ZIGBEE,
		.power = GP_BATTERY,
		.node_status = 1,
		.add_again = 0,
		.update_again = 0,
		.conn_again = 0,
		.prop_send = 0,
		.metadata = 0
	},
	{
		.addr = "node_2",
		.version = "2.0.2",
		.oem_model = "jvappnode",
		.interface = GI_ZIGBEE,
		.power = GP_MAINS,
		.node_status = 1,
		.add_again = 0,
		.update_again = 0,
		.conn_again = 0,
		.prop_send = 0,
		.metadata = 1
	}
};

const char subdev_name[] = "s1";

/*
 * This name should match the template key assigned to the
 * template on the service.
 */
const char template1[] = "booldec";
const char template2[] = "intstr";

/*
 * Sample node properties template.
 */
static struct appd_node_props app_node_props[] = {
	{ "Blue_button", template1, PROP_BOOLEAN, sizeof(blue_button),
	    &blue_button },
	{ "Blue_LED", template1, PROP_BOOLEAN, sizeof(blue_led), &blue_led,
	    app_led_set },
	{ "Green_LED", template1, PROP_BOOLEAN, sizeof(green_led), &green_led,
	    app_led_set },
	{ "cmd", template2, PROP_STRING, sizeof(cmd), cmd,
	    app_cmd_set },
	{ "log", template2, PROP_STRING, sizeof(log), log },
	{ "input", template2, PROP_INTEGER, sizeof(input), &input,
	    app_input_set },
	{ "output", template2, PROP_INTEGER, sizeof(output), &output },
	{ "decimal_in", template1, PROP_DECIMAL, sizeof(decimal_in),
	    &decimal_in, app_decimal_in_set },
	{ "decimal_out", template1, PROP_DECIMAL, sizeof(decimal_out),
	    &decimal_out },
	{ "node_batch_hold", template1, PROP_BOOLEAN, sizeof(node_batch_hold),
	    &node_batch_hold, app_node_batch_hold_set },
	{ "junk", template2, PROP_INTEGER, sizeof(output), &output },
};

static struct appd_node_result node1_result[] = {
	{ "gw_node_init", 287820 },
	{ "gw_subdev_add", 287821 },
	{ "gw_template_add_t1", 287822 },
	{ "gw_template_add_t2", 287823 },
	{ "gw_node_to_json", 289938 },
	{ "gw_json_to_node", 289939 },
	{ "gw_node_free", 287826 },
	{ "gw_node_add_confirm_s", 287885 },
	{ "gw_node_add_confirm_f", 287886 },
	{ "gw_node_conn_confirm_s", 287887 },
	{ "gw_node_conn_confirm_f", 287888 },
	{ "gw_node_conn_get_handler", 287898},
};

static struct appd_node_result node2_result[] = {
	{ "gw_node_init", 287879 },
	{ "gw_subdev_add", 287880 },
	{ "gw_template_add_t1", 287881 },
	{ "gw_template_add_t2", 287882 },
	{ "gw_node_to_json", 289940 },
	{ "gw_json_to_node", 289941 },
	{ "gw_node_free", 287884 },
	{ "gw_node_add_confirm_s", 301423 },
	{ "gw_node_add_confirm_f", 301424 },
	{ "gw_node_conn_confirm_s", 301487 },
	{ "gw_node_conn_confirm_f", 301488 },
	{ "gw_node_conn_get_handler", 287899},
};

static void result_record(unsigned long int id, u8 result)
{
	json_t *root = json_object();
	json_t *case_id = json_integer(id);
	json_t *status_id = json_integer(result);
	int rc = -1;

	REQUIRE(root, REQUIRE_MSG_ALLOCATION);
	json_object_set_new(root, "case_id", case_id);
	json_object_set_new(root, "status_id", status_id);

	if (!id) {
		goto end;
	}

	rc = json_dumpf(root, fp, JSON_COMPACT);
	fprintf(fp, "\n");
	if (rc) {
		log_debug("dump failed");
	}
end:
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

static void app_eth_disconnect(const char *trigger)
{
	int ret;
	char command[50];

	snprintf(command, sizeof(command),
	    "ifconfig eth%d down", ETH_INTERFACE);
	ret = system(command);
	log_debug("%s - eth%d down - %s", trigger,
	    ETH_INTERFACE, (ret ? "failed" : "succeeded"));
	sleep(8);
	--skip;
}

static struct appd_node_state *app_node_lookup(const char *addr)
{
	struct appd_node_state *node;
	int i;

	for (i = 0; i < ARRAY_LEN(app_node); i++) {
		if (!strcmp(addr, app_node[i].addr)) {
			node = &app_node[i];
			return node;
		}
	}
	log_debug("node not found");
	return NULL;
}

static struct appd_node_props *app_node_prop_lookup(const char *name)
{
	struct appd_node_props *prop;
	int i;

	for (i = 0; i < ARRAY_LEN(app_node_props); i++) {
		if (!strcmp(name, app_node_props[i].name)) {
			prop = &app_node_props[i];
			return prop;
		}
	}
	log_debug("node property not found");
	return NULL;
}

static struct gw_node_prop *app_fill_gw_node_prop(struct appd_node_props *anp,
		const char *addr)
{
	struct gw_node_prop *prop = calloc(1, sizeof(*prop));
	if (!anp) {
		return NULL;
	}

	prop->addr = addr;
	prop->subdevice_key = subdev_name;
	prop->template_key = anp->template_key;
	prop->name = anp->name;
	return prop;
}

static void app_node_prop_send_by_node_prop(struct gw_node_prop *prop,
		int req_id, struct prop_metadata *md)
{
	struct appd_node_props *anp;
	struct op_options opts = {.confirm = 1, .metadata = md};

	anp = app_node_prop_lookup(prop->name);

	if (!prop) {
		return;
	}

	gw_node_prop_send(prop, anp->type, anp->val,
	    anp->val_len, req_id, &opts);
}

static void app_node_batch_append_by_node_prop(struct gw_node_prop *prop,
		struct prop_metadata *md)
{
	struct appd_node_props *anp;
	struct op_options opts = {.metadata = md};

	anp = app_node_prop_lookup(prop->name);

	if (!prop) {
		return;
	}

	node_batched_dps = gw_node_prop_batch_append(node_batched_dps,
	    prop, anp->type, anp->val, anp->val_len, &opts);
}

static int app_led_set(struct gw_node_prop *prop,
	enum prop_type type, const void *val, size_t val_len,
	const struct op_args *args)
{
	struct appd_node_props *anp;
	struct gw_node_prop *nprop;
	static u8 done;

	if (!prop) {
		return 1;
	}

	if (!strcmp(prop->name, "Blue_LED")) {
		blue_led = *(u8 *)val;
		log_debug("%s set to %d", prop->name, blue_led);
	} else if (!strcmp(prop->name, "Green_LED")) {
		green_led = *(u8 *)val;
		log_debug("%s set to %d", prop->name, green_led);
	} else {
		log_debug("%s not in template", prop->name);
		return 1;
	}

	anp = app_node_prop_lookup("Blue_button");
	nprop = app_fill_gw_node_prop(anp, "node_1");

	if ((blue_led && green_led) != blue_button) {
		blue_button = blue_led && green_led;
		if (node_batch_hold) {
			/* batch the datapoint for sending later */
			app_node_batch_append_by_node_prop(nprop, NULL);
		} else {
			app_node_prop_send_by_node_prop(nprop, 0, NULL);
			if (!done) {
				result_record(287894, PASS);
				done = 1;
			}
		}
	}
	free(nprop);
	return 0;
}

static int app_cmd_set(struct gw_node_prop *prop,
	enum prop_type type, const void *val, size_t val_len,
	const struct op_args *args)
{
	struct appd_node_props *anp;
	struct gw_node_prop *nprop;
	static u8 done;

	if (!prop) {
		return 1;
	}

	memcpy(cmd, val, val_len);
	log_debug("%s set to %s", prop->name, cmd);
	cmd[val_len] = '\0';

	snprintf(log, sizeof(log), "%s", cmd);
	anp = app_node_prop_lookup("log");
	nprop = app_fill_gw_node_prop(anp, "node_2");

	if (node_batch_hold) {
		/* batch the datapoint for sending later */
		app_node_batch_append_by_node_prop(nprop, NULL);
	} else {
		app_node_prop_send_by_node_prop(nprop, 0, NULL);
		if (!done) {
			result_record(287896, PASS);
			done = 1;
		}
	}
	free(nprop);
	return 0;
}

static int app_input_set(struct gw_node_prop *prop,
	enum prop_type type, const void *val, size_t val_len,
	const struct op_args *args)
{
	struct appd_node_props *anp;
	struct gw_node_prop *nprop;
	struct prop_metadata *metadata;
	int i;
	char key[10];
	enum err_t rc;
	static u8 done;

	if (!prop) {
		return 1;
	}

	input = *(long *)val;
	log_debug("%s set to %ld", prop->name, input);

	output = input;
	anp = app_node_prop_lookup("output");
	nprop = app_fill_gw_node_prop(anp, "node_1");

	/* add metadata to the datapoint */
	metadata = prop_metadata_alloc();
	for (i = 0; !(input % 5) && i < input; i++) {
		snprintf(key, sizeof(key), "key%d", i);
		rc = prop_metadata_addf(metadata, key, "val%d", i);
		if (rc == ERR_VAL) {
			log_debug("limiting to 10 metadata entries");
			i = input;
		}
	}

	if (node_batch_hold) {
		/* batch the datapoint for sending later */
		app_node_batch_append_by_node_prop(nprop, metadata);
	} else {
		app_node_prop_send_by_node_prop(nprop, 0, metadata);
		if (!done) {
			result_record(287895, PASS);
			done = 1;
		}
	}
	free(nprop);
	prop_metadata_free(metadata);
	return 0;
}

static int app_decimal_in_set(struct gw_node_prop *prop,
	enum prop_type type, const void *val, size_t val_len,
	const struct op_args *args)
{
	struct appd_node_props *anp;
	struct gw_node_prop *nprop;
	struct prop_metadata *metadata;
	char keyx[PROP_METADATA_KEY_MAX_LEN + 2];
	static u8 done;

	if (!prop) {
		return 1;
	}

	decimal_in = *(double *)val;
	log_debug("%s set to %2.2f", prop->name,
	    decimal_in);

	decimal_out = decimal_in;
	anp = app_node_prop_lookup("decimal_out");
	nprop = app_fill_gw_node_prop(anp, "node_2");

	/* add metadata to the datapoint */
	metadata = prop_metadata_alloc();
	prop_metadata_add(metadata, "key0", "val0");
	prop_metadata_add(metadata, "key-1", "val1");
	prop_metadata_add(metadata, "key2", "val-2");
	memset(keyx, 'a', sizeof(keyx));
	keyx[PROP_METADATA_KEY_MAX_LEN + 1] = '\0';
	prop_metadata_add(metadata, keyx, "val3");
	keyx[PROP_METADATA_KEY_MAX_LEN] = '\0';
	prop_metadata_add(metadata, keyx, "val4");

	if (node_batch_hold) {
		/* batch the datapoint for sending later */
		app_node_batch_append_by_node_prop(nprop, metadata);
	} else {
		app_node_prop_send_by_node_prop(nprop, 0, metadata);
		if (!done) {
			result_record(287897, PASS);
			done = 1;
		}
	}
	free(nprop);
	prop_metadata_free(metadata);
	return 0;
}

static int app_node_batch_hold_set(struct gw_node_prop *prop,
	enum prop_type type, const void *val, size_t val_len,
	const struct op_args *args)
{
	int batch_id;
	struct op_options opts;

	memset(&opts, 0, sizeof(opts));
	opts.confirm = 1;

	if (!prop) {
		return 1;
	}

	node_batch_hold = *(u8 *)val;
	log_debug("%s set to %d", prop->name, node_batch_hold);
	if (skip == 2 && !node_batch_hold && !app_manages_acks) {
		app_eth_disconnect("node prop batch");
	}

	if (!node_batch_hold && node_batched_dps) {
		gw_node_prop_batch_send(&node_batched_dps, &opts, &batch_id);
		log_debug("batch_id = %d", batch_id);
	}

	return 0;
}

static int app_gw_update_node_set(struct prop *prop, const void *val,
	size_t len, const struct op_args *args)
{
	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		return -1;
	}

	app_node_update("node_1", gw_update_node);
	gw_update_node = 0;
	prop_send_by_name("gw_update_node");
	return 0;
}

static int app_gw_batch_demo_set(struct prop *prop, const void *val, size_t len,
	const struct op_args *args)
{
	static struct gw_node_prop_batch_list *gnpbl;
	struct appd_node_props *output_anp = app_node_prop_lookup("output");
	struct gw_node_prop *output_prop = app_fill_gw_node_prop(output_anp,
	    "node_1");
	struct appd_node_props *dec_out_anp =
	    app_node_prop_lookup("decimal_out");
	struct gw_node_prop *decimal_out_prop =
	    app_fill_gw_node_prop(dec_out_anp, "node_2");
	struct appd_node_props *button_anp =
	    app_node_prop_lookup("Blue_button");
	struct gw_node_prop *button_prop =
	    app_fill_gw_node_prop(button_anp, "node_1");
	struct appd_node_props *log_anp = app_node_prop_lookup("log");
	struct gw_node_prop *log_prop =
	    app_fill_gw_node_prop(log_anp, "node_2");
	struct appd_node_props *junk_anp = app_node_prop_lookup("junk");
	struct gw_node_prop *junk_prop =
	    app_fill_gw_node_prop(junk_anp, "node_1");
	struct op_options batch_opts;
	struct op_options send_opts;
	int batch_id;
	int i;

	memset(&batch_opts, 0, sizeof(batch_opts));
	memset(&send_opts, 0, sizeof(send_opts));

	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		return -1;
	}

	if (!gw_batch_demo) {
		return -1;
	}

	output = 100;
	decimal_out = 5.25;
	blue_button = 1;
	snprintf(log, sizeof(log), "a");

	/* Test 1 - gw_node_prop_batch_append + gw_node_prop_batch_list_free */
	gnpbl = gw_node_prop_batch_append(gnpbl, output_prop, output_anp->type,
	    output_anp->val, output_anp->val_len, NULL);
	gnpbl = gw_node_prop_batch_append(gnpbl, decimal_out_prop,
	    dec_out_anp->type, dec_out_anp->val,
	    dec_out_anp->val_len, NULL);
	gnpbl = gw_node_prop_batch_append(gnpbl, button_prop, button_anp->type,
	    button_anp->val, button_anp->val_len, NULL);
	gnpbl = gw_node_prop_batch_append(gnpbl, log_prop, log_anp->type,
	    log_anp->val, log_anp->val_len, NULL);
	gw_node_prop_batch_list_free(&gnpbl);
	check_pointer(287911, 1, gnpbl);

	/* Test 2 - gw_node_prop_batch_append + gw_node_prop_batch_send */
	batch_opts.dev_time_ms = ops_get_system_time_ms();
	gnpbl = gw_node_prop_batch_append(gnpbl, output_prop, output_anp->type,
	    output_anp->val, output_anp->val_len, &batch_opts);
	batch_opts.dev_time_ms = 123456789;
	gnpbl = gw_node_prop_batch_append(gnpbl, decimal_out_prop,
	    dec_out_anp->type, dec_out_anp->val,
	    dec_out_anp->val_len, &batch_opts);
	batch_opts.dev_time_ms = 0;
	batch_opts.confirm = 1;
	batch_opts.dests = 3;
	gnpbl = gw_node_prop_batch_append(gnpbl, button_prop, button_anp->type,
	    button_anp->val, button_anp->val_len, &batch_opts);
	batch_opts.dev_time_ms = ops_get_system_time_ms();
	gnpbl = gw_node_prop_batch_append(gnpbl, log_prop, log_anp->type,
	    log_anp->val, log_anp->val_len, &batch_opts);
	gw_node_prop_batch_send(&gnpbl, NULL, &batch_id);
	check_pointer(287912, 1, gnpbl);
	log_debug("batch_id = %d", batch_id);

	/* Test 3 - gw_node_prop_batch_append + gw_node_prop_batch_send
	 * with opts */
	output += 25;
	gnpbl = gw_node_prop_batch_append(gnpbl, output_prop, output_anp->type,
	    output_anp->val, output_anp->val_len, NULL);
	snprintf(log, sizeof(log), "b");
	gnpbl = gw_node_prop_batch_append(gnpbl, log_prop, log_anp->type,
	    log_anp->val, log_anp->val_len, NULL);
	send_opts.confirm = 1;
	send_opts.dests = DEST_LAN_APPS;
	gw_node_prop_batch_send(&gnpbl, &send_opts, &batch_id);
	check_pointer(287913, 1, gnpbl);
	log_debug("batch_id = %d", batch_id);

	/* Test 4 - gw_node_prop_batch_append + gw_node_prop_batch_send
	 * with opts */
	gnpbl = gw_node_prop_batch_append(gnpbl, output_prop, output_anp->type,
	    output_anp->val, output_anp->val_len, NULL);
	gnpbl = gw_node_prop_batch_append(gnpbl, log_prop, log_anp->type,
	    log_anp->val, log_anp->val_len, NULL);
	send_opts.dests = DEST_ADS;
	gw_node_prop_batch_send(&gnpbl, &send_opts, &batch_id);
	check_pointer(287914, 1, gnpbl);
	log_debug("batch_id = %d", batch_id);

	/* Test 5 - gw_node_prop_batch_append + gw_node_prop_batch_send
	 * with opts */
	decimal_out -= (double)5;
	gnpbl = gw_node_prop_batch_append(gnpbl, decimal_out_prop,
	    dec_out_anp->type, dec_out_anp->val,
	    dec_out_anp->val_len, NULL);
	blue_button = 0;
	batch_opts.confirm = 1;
	gnpbl = gw_node_prop_batch_append(gnpbl, button_prop, button_anp->type,
	    button_anp->val, button_anp->val_len, NULL);
	send_opts.dests = 7;
	gw_node_prop_batch_send(&gnpbl, &send_opts, &batch_id);
	check_pointer(287915, 1, gnpbl);
	log_debug("batch_id = %d", batch_id);

	/* Multiple updates for the same property */
	output += 900;
	gnpbl = gw_node_prop_batch_append(gnpbl, output_prop, output_anp->type,
	    output_anp->val, output_anp->val_len, NULL);
	output -= 500;
	gnpbl = gw_node_prop_batch_append(gnpbl, output_prop, output_anp->type,
	    output_anp->val, output_anp->val_len, NULL);
	send_opts.dests = DEST_ADS;
	gw_node_prop_batch_send(&gnpbl, &send_opts, &batch_id);
	check_pointer(287916, 1, gnpbl);
	log_debug("batch_id = %d", batch_id);

	/* Partial success */
	log[0] = '\0'; /* returns a 422 for now */
	send_opts.confirm = 0;
	gnpbl = gw_node_prop_batch_append(gnpbl, junk_prop, junk_anp->type,
	    junk_anp->val, junk_anp->val_len, NULL);
	gnpbl = gw_node_prop_batch_append(gnpbl, decimal_out_prop,
	    dec_out_anp->type, dec_out_anp->val,
	    dec_out_anp->val_len, NULL);
	gnpbl = gw_node_prop_batch_append(gnpbl, button_prop, button_anp->type,
	    button_anp->val, button_anp->val_len, NULL);
	gnpbl = gw_node_prop_batch_append(gnpbl, log_prop, log_anp->type,
	    log_anp->val, log_anp->val_len, NULL);
	gw_node_prop_batch_send(&gnpbl, &send_opts, &batch_id);

	/* 100 batch datapoints */
	output = 1;
	decimal_out = 0.01;
	for (i = 0; i < 50; i++) {
		gnpbl = gw_node_prop_batch_append(gnpbl, output_prop,
		    output_anp->type, output_anp->val,
		    output_anp->val_len, NULL);
		gnpbl = gw_node_prop_batch_append(gnpbl, decimal_out_prop,
		    dec_out_anp->type, dec_out_anp->val,
		    dec_out_anp->val_len, NULL);
		output += 1;
		decimal_out += (double)0.01;
	}
	gw_node_prop_batch_send(&gnpbl, &send_opts, &batch_id);

	gw_batch_demo = 0;
	prop_send_by_name("gw_batch_demo");

	free(output_prop);
	free(decimal_out_prop);
	free(log_prop);
	free(button_prop);
	free(junk_prop);
	return 0;
}

static int app_template_prop_compare(const struct gw_template_prop *prop_1,
	const struct gw_template_prop *prop_2)
{
	/*int prop_found;
	int propmeta_found = 0;
	const struct gw_template_prop *tmp = prop_2;

	if (!prop_1 || !prop_2) {
		return 1;
	}

	for (; prop_1 != NULL; prop_1 = prop_1->link.le_next) {
		prop_found = 1;
		if (prop_1->propmeta) {
			propmeta_found = 1;
		}
		log_debug("1 - %s", prop_1->name);
		tmp = prop_2;
		for(; tmp != NULL; tmp = tmp->link.le_next) {
			log_debug("2 - %s", tmp->name);
			if (!strcmp(prop_1->name, tmp->name)) {
				prop_found = 0;
			}
			if (prop_1->propmeta) {
				if (!memcmp(prop_1->propmeta, tmp->propmeta,
				    strlen(prop_1->propmeta))) {
					propmeta_found = 0;
				}
			}
		}
	}
	log_debug("prop_found = %d", prop_found);
	log_debug("propmeta_found = %d", propmeta_found);
	return (prop_found || propmeta_found);*/
	return 0;
}

static int app_subdev_template_compare(
	const struct gw_subdevice_template *template_1,
	const struct gw_subdevice_template *template_2,
	int metadata)
{
	int template_found;
	int prop_equal = 0;
	struct gw_template_prop *propq1 =
	    template_1->props.lh_first;
	struct gw_template_prop *propq2 =
	    template_2->props.lh_first;
	const struct gw_subdevice_template *tmp = template_2;
	int ret;

	if (!template_1 || !template_2) {
		return 1;
	}

	for (; template_1 != NULL; template_1 = template_1->link.le_next) {
		template_found = 1;
		tmp = template_2;
		for (; tmp != NULL; tmp = tmp->link.le_next) {
			if (!strcmp(template_1->template_key,
			    tmp->template_key)) {
				template_found = 0;
			}
			if (metadata) {
				prop_equal = app_template_prop_compare(propq1,
				    propq2);
			}
		}
	}
	ret = template_found || prop_equal;
	return ret;
}

static int app_node_subdev_compare(const struct gw_node_subdevice *subdev_1,
	const struct gw_node_subdevice *subdev_2,
	int metadata)
{
	int subdev_found;
	int submeta_found = 0;
	int template_equal = 1;
	struct gw_subdevice_template *tempq1 =
	    subdev_1->templates.lh_first;
	struct gw_subdevice_template *tempq2 =
	    subdev_2->templates.lh_first;
	const struct gw_node_subdevice *tmp = subdev_2;
	int ret;

	if (!subdev_1 || !subdev_2) {
		return -1;
	}

	for (; subdev_1 != NULL; subdev_1 = subdev_1->link.le_next) {
		if (metadata) {
			submeta_found = 1;
		}
		subdev_found = 1;
		tmp = subdev_2;
		for (; tmp != NULL; tmp = tmp->link.le_next) {
			if (metadata) {
				if (!memcmp(subdev_1->submeta, tmp->submeta,
				    strlen(subdev_1->submeta))) {
					submeta_found = 0;
				}
			}
			if (!strcmp(subdev_1->subdevice_key,
			    tmp->subdevice_key)) {
				subdev_found = 0;
			}
			template_equal = app_subdev_template_compare(tempq1,
			    tempq2, metadata);
		}
	}
	ret = (submeta_found || subdev_found || template_equal);
	return ret;
}

static int app_nodes_compare(const struct gw_node *node_1,
	const struct gw_node *node_2, int metadata)
{
	struct gw_node_subdevice *subdevq1 =
	    node_1->subdevices.lh_first;
	struct gw_node_subdevice *subdevq2 =
	    node_2->subdevices.lh_first;

	log_debug("check nodes");
	if (!node_1 || !node_2) {
		return -1;
	}

	if (strcmp(node_1->addr, node_2->addr)) {
		log_debug("node addr match failed");
		return -1;
	}
	if (memcmp(node_1->oem_model, node_2->oem_model,
	    strlen(node_1->oem_model))) {
		log_debug("node oem_model match failed");
		return -1;
	}
	if (memcmp(node_1->sw_version, node_2->sw_version,
	    strlen(node_1->sw_version))) {
		log_debug("node sw_version match failed");
		return -1;
	}
	if (node_1->interface != node_2->interface) {
		log_debug("node interface match failed");
		return -1;
	}
	if (node_1->power != node_2->power) {
		log_debug("node power match failed");
		return -1;
	}
	if (app_node_subdev_compare(subdevq1, subdevq2, metadata)) {
		return -1;
	}
	if (metadata) {
		if (memcmp(node_1->nodemeta, node_2->nodemeta,
		    strlen(node_1->nodemeta))) {
			log_debug("node nodemeta match failed");
			return -1;
		}
	}
	return 0;
}

static unsigned long int app_get_tc(struct appd_node_result *anr, size_t cnt,
		const char *info)
{
	int i;
	unsigned long int ret = 0;

	for (i = 0; i < cnt; i++) {
		if (!strcmp(anr[i].info, info) && !(anr[i].reported)) {
			ret = anr[i].tc;
			anr[i].reported = 1;
			break;
		}
	}
	return ret;
}

static void app_gw_node_result_helper(const char *addr,
		const char *info, u8 result)
{
	if (!strcmp(addr, "node_1")) {
		result_record(app_get_tc(node1_result,
		    ARRAY_LEN(node1_result), info), result);
	} else if (!strcmp(addr, "node_2")) {
		result_record(app_get_tc(node2_result,
		    ARRAY_LEN(node2_result), info), result);
	} else {
		log_debug("node not found");
	}
}

static void app_node_create(const char *addr, int metadata)
{
	struct gw_node node;
	struct gw_node_subdevice *subdev;
	struct gw_subdevice_template *template;
	struct gw_template_prop *prop;
	json_t *node_info_j;
	json_t *data_j;
	char *node_string_1;
	char *node_string_2;
	struct gw_node node_json;
	struct op_options opts;
	struct appd_node_state *new_node = app_node_lookup(addr);
	struct gw_node *node_1 = &node;
	struct gw_node *node_2 = &node_json;

	/*
	 * Initialize node and fill in all the struct details.
	 */
	gw_node_init(&node, new_node->addr);
	node.sw_version = new_node->version;
	node.oem_model = new_node->oem_model;
	node.interface = new_node->interface;
	node.power = new_node->power;
	if (metadata) {
		node.nodemeta = "version";
	}
	app_gw_node_result_helper(addr, "gw_node_init", PASS);

	/*
	 * Add a single subdevice to the node.
	 */
	subdev = gw_subdev_add(&node, subdev_name);
	if (!subdev) {
		app_gw_node_result_helper(addr, "gw_subdev_add", FAIL);
		return;
	}
	if (metadata) {
		subdev->submeta = "new_node->addr";
	}
	app_gw_node_result_helper(addr, "gw_subdev_add", PASS);

	/*
	 * Add templates to the subdevice.
	 */
	template = gw_template_add(subdev, template1, "1.1");
	if (!template) {
		app_gw_node_result_helper(addr, "gw_template_add_t1", FAIL);
		return;
	}
	if (metadata) {
		prop = gw_prop_add(template, "decimal_in");
		prop->propmeta = "booldec";
		prop = gw_prop_add(template, "decimal_out");
	}
	app_gw_node_result_helper(addr, "gw_template_add_t1", PASS);

	template = gw_template_add(subdev, template2, NULL);
	if (!template) {
		app_gw_node_result_helper(addr, "gw_template_add_t2", FAIL);
		return;
	}
	if (metadata) {
		prop = gw_prop_add(template, "cmd");
		prop->propmeta = "intstr";
		prop = gw_prop_add(template, "log");
	}
	app_gw_node_result_helper(addr, "gw_template_add_t2", PASS);

	memset(&opts, 0, sizeof(opts));
	opts.confirm = 1;

	if (skip == 4 && app_manages_acks == 0) {
		app_eth_disconnect("node add");
	}
	gw_node_add(&node, &node_info_j, &opts);

	gw_node_to_json(&node, &data_j);
	if (json_is_object(data_j)) {
		node_string_1 = json_dumps(node_info_j, JSON_COMPACT);
		node_string_2 = json_dumps(data_j, JSON_COMPACT);
		if (!strcmp(node_string_1, node_string_2)) {
			app_gw_node_result_helper(addr, "gw_node_to_json",
			    PASS);
		} else {
			app_gw_node_result_helper(addr, "gw_node_to_json",
			    FAIL);
		}
		free(node_string_1);
		free(node_string_2);

		gw_json_to_node(&node_json, data_j);
		/*
		 * Compare all elements in the node structs (pending)
		 */
		if (!app_nodes_compare(node_1, node_2, metadata)) {
			app_gw_node_result_helper(addr, "gw_json_to_node",
			    PASS);
		} else {
			app_gw_node_result_helper(addr, "gw_json_to_node",
			    FAIL);
		}
		gw_node_free(&node_json, 1);
	}

	gw_node_free(&node, 0);
	log_debug("node->sw_version = %s", node.sw_version);
	app_gw_node_result_helper(addr, "gw_node_free", PASS);

	json_decref(data_j);
	json_decref(node_info_j);
}

static void app_node_update(const char *addr, int update_num)
{
	struct appd_node_state *new_node = app_node_lookup(addr);
	struct gw_node node;
	struct gw_node_subdevice *subdev;
	struct gw_subdevice_template *template;
	struct gw_template_prop *prop;
	struct op_options opts;

	memset(&opts, 0, sizeof(opts));
	opts.confirm = 1;

	/*
	 * Run a node schedule while this is going on.
	 */
	switch (update_num) {
	case 1:
		/*
		 * Update to a newer template version.
		 */
		gw_node_init(&node, new_node->addr);
		node.sw_version = new_node->version;
		node.oem_model = new_node->oem_model;
		node.interface = new_node->interface;
		node.power = new_node->power;
		subdev = gw_subdev_add(&node, subdev_name);
		template = gw_template_add(subdev, template1, "1.0");
		if (!template) {
			return;
		}
		template = gw_template_add(subdev, template2, NULL);
		if (!template) {
			return;
		}
		if (skip == 3 && app_manages_acks == 1) {
			app_eth_disconnect("node_update");
		}
		gw_node_update(&node, NULL, &opts);
		gw_node_free(&node, 0);
		break;
	case 2:
		/*
		 * Update to the older template version with selected props.
		 */
		gw_node_init(&node, new_node->addr);
		node.sw_version = new_node->version;
		node.oem_model = new_node->oem_model;
		node.interface = new_node->interface;
		node.power = new_node->power;
		subdev = gw_subdev_add(&node, subdev_name);
		template = gw_template_add(subdev, template1, "1.1");
		if (!template) {
			return;
		}
		prop = gw_prop_add(template, "Blue_button");
		prop = gw_prop_add(template, "Blue_LED");
		prop = gw_prop_add(template, "decimal_in");
		prop->propmeta = "booldec";
		template = gw_template_add(subdev, template2, NULL);
		if (!template) {
			return;
		}
		gw_node_update(&node, NULL, &opts);
		gw_node_free(&node, 0);
		break;
	case 3:
		/*
		 * Delete one template.
		 */
		gw_node_init(&node, new_node->addr);
		node.sw_version = new_node->version;
		node.oem_model = new_node->oem_model;
		node.interface = new_node->interface;
		node.power = new_node->power;
		subdev = gw_subdev_add(&node, subdev_name);
		template = gw_template_add(subdev, template1, "1.0");
		if (!template) {
			return;
		}
		gw_node_update(&node, NULL, &opts);
		gw_node_free(&node, 0);
		break;
	case 4:
		/*
		 * Add both templates back.
		 */
		gw_node_init(&node, new_node->addr);
		node.sw_version = new_node->version;
		node.oem_model = new_node->oem_model;
		node.interface = new_node->interface;
		node.power = new_node->power;
		subdev = gw_subdev_add(&node, subdev_name);
		template = gw_template_add(subdev, template1, "1.1");
		if (!template) {
			return;
		}
		template = gw_template_add(subdev, template2, NULL);
		if (!template) {
			return;
		}
		gw_node_update(&node, NULL, &opts);
		gw_node_free(&node, 0);
		break;
	default:
		break;
	}
}

static int check_time(unsigned long long dev_time_ms)
{
	if (dev_time_ms > 0 && dev_time_ms < ops_get_system_time_ms()) {
		return 1;
	} else {
		return 0;
	}
}

static int app_node_ops_confirm_handler(enum ayla_gateway_op op,
	enum gw_confirm_arg_type type, const void *arg,
	const struct op_options *opts,
	const struct confirm_info *confirm_info)
{
	struct gw_node_prop_dp *node_dp;
	struct gw_node_ota_info *node_ota;
	int batch_id;
	u8 result;

	if (!arg) {
bad_arg:
		log_debug("bad/NULL argument");
		return 0;
	}

	switch (op) {
	case AG_NODE_ADD:
		if (type != CAT_ADDR) {
			log_debug("node_add");
			goto bad_arg;
		}
		result = FAIL;
		if (confirm_info->status == CONF_STAT_SUCCESS) {
			log_debug("Node %s added successfully at %llu",
			    (char *)arg, opts->dev_time_ms);
			gw_num_nodes++;
			prop_send_by_name("gw_num_nodes");
			nodes_added++;
			if (app_manages_acks == 0 && skip == 3) {
				if (check_time(opts->dev_time_ms)) {
					result = PASS;
				}
			}
			app_gw_node_result_helper((char *)arg,
			    "gw_node_add_confirm_s", result);
		} else {
			log_debug("Node %s addition failed at %llu with err %u",
			    (char *)arg, opts->dev_time_ms, confirm_info->err);
			log_debug("Failed dests = %u", confirm_info->dests);
			if (app_manages_acks == 0 && skip == 3) {
				if (check_time(opts->dev_time_ms) &&
				    confirm_info->dests == DEST_ADS &&
				    confirm_info->err == CONF_ERR_CONN) {
					result = PASS;
				}
			}
			app_gw_node_result_helper((char *)arg,
			    "gw_node_add_confirm_f", result);
		}
		break;
	case AG_NODE_UPDATE:
		if (type != CAT_ADDR) {
			goto bad_arg;
		}
		if (confirm_info->status == CONF_STAT_SUCCESS) {
			log_debug("Node %s updated successfully at %llu",
			    (char *)arg, opts->dev_time_ms);
		} else {
			log_debug("Node %s update failed at %llu with err %u",
			    (char *)arg, opts->dev_time_ms, confirm_info->err);
		}
		break;
	case AG_NODE_OTA_RESULT:
		if (type != CAT_NODE_OTA_INFO) {
			goto bad_arg;
		}
		node_ota = (struct gw_node_ota_info *)arg;
		if (confirm_info->status == CONF_STAT_SUCCESS) {
			if (node_ota->save_location) {
				log_debug("Node OTA version %s successfully "
				    "downloaded for %s to location %s",
				    node_ota->version, node_ota->addr,
				    node_ota->save_location);
				/*
				 * Here is where you send the image stored in
				 * the saved location to the node.
				 */
				/*
				 * Once the new image has been applied and
				 * if the feature set of the node has now
				 * changed, the application can use
				 * gw_node_update to update the node's
				 * representation in the cloud.
				 */
			} else {
				log_debug("Node OTA version %s discarded "
				    "for %s", node_ota->version,
				    node_ota->addr);
			}
		} else {
			if (node_ota->save_location) {
				log_debug("Node OTA version %s failed to "
				    "download for %s with err %u",
				    node_ota->version, node_ota->addr,
				    confirm_info->err);
			} else {
				log_debug("Node OTA version %s failed to "
				    "be discarded for %s with err %u",
				    node_ota->version, node_ota->addr,
				    confirm_info->err);
			}
		}
		break;
	case AG_CONN_STATUS:
		if (type != CAT_ADDR) {
			log_debug("conn_status");
			goto bad_arg;
		}
		result = FAIL;
		if (confirm_info->status == CONF_STAT_SUCCESS) {
			log_debug("Node %s conn status successfully sent at "
			    "%llu to dests %d", (char *)arg, opts->dev_time_ms,
			    confirm_info->dests);
			if (app_manages_acks == 0 && skip == 2) {
				if (check_time(opts->dev_time_ms) &&
				    confirm_info->dests == DEST_ADS) {
					result = PASS;
				}
			}
			app_gw_node_result_helper((char *)arg,
			    "gw_node_conn_confirm_s", result);
		} else {
			log_debug("Node %s conn status failed at %llu to "
			    "dests %d with err %u", (char *)arg,
			    opts->dev_time_ms, confirm_info->dests,
			    confirm_info->err);
			if (app_manages_acks == 0 && skip == 2) {
				if (check_time(opts->dev_time_ms) &&
				    confirm_info->dests == DEST_ADS &&
				    confirm_info->err == CONF_ERR_CONN) {
					result = PASS;
				}
			}
			app_gw_node_result_helper((char *)arg,
			    "gw_node_conn_confirm_f", result);
		}
		break;
	case AG_PROP_SEND:
		if (type != CAT_NODEPROP_DP) {
			log_debug("node_prop_send");
			goto bad_arg;
		}
		node_dp = (struct gw_node_prop_dp *)arg;
		log_debug("addr = %s, subdev_key = %s, template_key = %s",
		    node_dp->prop->addr, node_dp->prop->subdevice_key,
		    node_dp->prop->template_key);
		result = FAIL;
		if (confirm_info->status == CONF_STAT_SUCCESS) {
			log_debug("%s = %s send at %llu to dests %d succeeded",
			    node_dp->prop->name,
			    prop_val_to_str(node_dp->val, node_dp->type),
			    opts->dev_time_ms, confirm_info->dests);
			if (app_manages_acks == 0 && skip == 2) {
				if (!strcmp(node_dp->prop->name,
				    "Blue_button") &&
				    check_time(opts->dev_time_ms)) {
					result = PASS;
				}
			}
			result_record(287890, result);
		} else {
			log_debug("%s = %s send at %llu for dests %d "
			    "failed with err %u", node_dp->prop->name,
			    prop_val_to_str(node_dp->val, node_dp->type),
			    opts->dev_time_ms, confirm_info->dests,
			    confirm_info->err);
			if (app_manages_acks == 0 && skip == 2) {
				if (check_time(opts->dev_time_ms) &&
				    confirm_info->dests == DEST_ADS &&
				    confirm_info->err == CONF_ERR_CONN &&
				    !strcmp(node_dp->prop->name,
				    "Blue_button")) {
					result = PASS;
				}
			}
			result_record(287891, result);
		}
		break;
	case AG_PROP_BATCH_SEND:
		if (type != CAT_BATCH_ID) {
			log_debug("type = %u", type);
			goto bad_arg;
		}
		batch_id = *(int *)arg;
		result = FAIL;
		if (confirm_info->status == CONF_STAT_SUCCESS) {
			log_debug("Batch id %d successfully sent at "
			    "%llu to dests %d", batch_id, opts->dev_time_ms,
			    confirm_info->dests);
			if (app_manages_acks == 0 && skip == 1) {
				if (batch_id == 1 &&
				    check_time(opts->dev_time_ms)) {
					result = PASS;
				}
			}
			result_record(287892, result);
		} else {
			log_debug("Batch id %d failed at %llu for "
			    "dests %d with err %u", batch_id,
			    opts->dev_time_ms, confirm_info->dests ,
			    confirm_info->err);
			if (app_manages_acks == 0 && skip == 1) {
				if (check_time(opts->dev_time_ms) &&
				    confirm_info->dests == DEST_ADS &&
				    confirm_info->err == CONF_ERR_CONN &&
				    batch_id == 1) {
					result = PASS;
				}
			}
			result_record(287893, result);

		}
		break;
	default:
		log_debug("op = %d not supported", op);
		return 0;
	}
	return 0;
}

static int app_gw_node_prop_struct_check(struct gw_node_prop *prop)
{
	if (!prop || !app_node_lookup(prop->addr) ||
	    strcmp(prop->subdevice_key, subdev_name)) {
		if (strcmp(prop->template_key, template1) &&
		    strcmp(prop->template_key, template2)) {
			log_debug("unknown property");
			return 1;
		}
	}
	return 0;
}

static int app_node_props_set_handler(struct gw_node_prop *prop,
	enum prop_type type, const void *val, size_t val_len,
	const struct op_args *args)
{
	struct appd_node_props *anp;
	int ack_message = 27;  /* arbitrary value */
	int status = 0;
	static u8 done0, done1;

	if (app_gw_node_prop_struct_check(prop)) {
		status = 1;
		goto done;
	}

	log_debug("addr = %s, subdev_key = %s, template_key = %s",
	    prop->addr, prop->subdevice_key, prop->template_key);

	anp = app_node_prop_lookup(prop->name);
	if (anp && anp->set) {
		status = anp->set(prop, type, val, val_len, args);
	} else {
		log_debug("property not found");
	}
	if (skip == 1 && app_manages_acks == 1) {
		app_eth_disconnect("node prop_set");
	}
done:
	if (app_manages_acks) {
		if (args && args->ack_arg) {
			ops_prop_ack_send(args->ack_arg, status, ack_message);
			if (!done0) {
				result_record(289936, PASS);
			}
		} else {
			if (!done0) {
				result_record(289936, FAIL);
			}
		}
		done0 = 1;
	} else {
		if (!args) {
			if (!done1) {
				result_record(289937, PASS);
			}
		} else {
			if (!done1) {
				result_record(289937, FAIL);
			}
		}
		done1 = 1;
	}
	return status;
}

static int app_node_conn_get_handler(const char *addr)
{
	struct appd_node_state *node = app_node_lookup(addr);

	if (node) {
		if (node->node_status) {
			log_debug("node %s is connected", addr);
		} else {
			log_debug("node %s is disconnected", addr);
		}
	} else {
		return -1;
	}
	app_gw_node_result_helper(addr, "gw_node_conn_get_handler", PASS);
	return node->node_status;
}

static int app_node_prop_get_handler(struct gw_node_prop *prop, int req_id,
	const char *arg)
{
	if (app_gw_node_prop_struct_check(prop)) {
		return -1;
	}
	log_debug("addr = %s, subdev_key = %s, template_key = %s",
	    prop->addr, prop->subdevice_key, prop->template_key);
	result_record(287900, PASS);
	app_node_prop_send_by_node_prop(prop, req_id, NULL);
	return req_id;
}

static void app_gw_node_rst_handler(const char *addr, void *cookie)
{
	int msg_code = 90;  /* arbitrary value */

	if (!addr || !cookie) {
		return;
	}

	if (skip == 1 && app_manages_acks == 0) {
		app_eth_disconnect("node_reset");
	}

	if (app_node_lookup(addr)) {
		gw_node_rst_cb(addr, cookie, 1, msg_code);
		/*log_debug("received a rst command for node %s", addr);
		if (!strcmp(addr, "node_2")) {
			gw_node_rst_cb(addr, cookie, 1, msg_code);
			result_record(287901, PASS);
		} else {
			gw_node_rst_cb(addr, cookie, 0, msg_code);
			result_record(287902, PASS);
		}*/
	} else {
		/*
		 * Unknown address. Mark the reset successful.
		 */
		gw_node_rst_cb(addr, cookie, 1, msg_code);
		result_record(287901, FAIL);
	}
}

int app_gw_cloud_fail_handler(enum ayla_gateway_op op,
		enum gw_confirm_arg_type type, const void *arg,
		const struct op_options *opts)
{
	struct gw_node_prop_dp *node_dp;
	struct appd_node_props *anp;
	struct appd_node_state *node;

	if (!arg) {
bad_arg:
		log_debug("NULL/bad arg for %u", op);
		return -1;
	}

	switch (op) {
	case AG_NODE_ADD:
		if (type != CAT_ADDR) {
			goto bad_arg;
		}
		log_debug("Node %s addition failed at %llu",
		    (char *)arg, opts->dev_time_ms);
		node = app_node_lookup(arg);
		if (node) {
			node->add_again = 1;
		} else {
			return -1;
		}
		if (app_manages_acks == 0 && skip == 3) {
			result_record(287903, PASS);
		}
		break;
	case AG_NODE_UPDATE:
		if (type != CAT_ADDR) {
			goto bad_arg;
		}
		log_debug("Node %s update failed at %llu",
		    (char *)arg, opts->dev_time_ms);
		node = app_node_lookup(arg);
		if (node) {
			node->update_again = 1;
		} else {
			return -1;
		}
		break;
	case AG_CONN_STATUS:
		if (type != CAT_ADDR) {
			goto bad_arg;
		}
		log_debug("Node %s conn status failed to send to ADS at %llu",
		    (char *)arg, opts->dev_time_ms);
		node = app_node_lookup(arg);
		if (node) {
			log_debug("set conn_again");
			node->conn_again = 1;
		} else {
			return -1;
		}
		if (app_manages_acks == 0 && skip == 2) {
			result_record(287904, PASS);
		}
		break;
	case AG_PROP_SEND:
		node_dp = (struct gw_node_prop_dp *)arg;
		if (type != CAT_NODEPROP_DP) {
			goto bad_arg;
		}
		log_debug("%s.%s:%s:%s = %s failed to send to ADS at %llu",
		    node_dp->prop->addr, node_dp->prop->subdevice_key,
		    node_dp->prop->template_key, node_dp->prop->name,
		    prop_val_to_str(node_dp->val, node_dp->type),
		    opts->dev_time_ms);
		if (!node_dp->prop) {
			return -1;
		}
		anp = app_node_prop_lookup(node_dp->prop->name);
		if (anp) {
			anp->send_again = 1;
		} else {
			return -1;
		}
		node = app_node_lookup(node_dp->prop->addr);
		if (node) {
			node->prop_send = 1;
		} else {
			return -1;
		}
		if (app_manages_acks == 0 && skip == 2) {
			result_record(287905, PASS);
		}
		break;
	case AG_PROP_BATCH_SEND:
		if (type != CAT_BATCH_ID) {
			goto bad_arg;
		}
		log_debug("Batch id %d failed to send to ADS at %llu",
		    *(int *)arg, opts->dev_time_ms);
		if (app_manages_acks == 0 && skip == 1) {
			result_record(287903, PASS);
		}
		break;
	default:
		log_debug("cloud failure not handled for"
		    "this operation, %u", op);
		return -1;
	}
	return 0;
}

static void app_ops_cloud_recovery_handler(void)
{
	int i;
	struct op_options opts;
	struct gw_node_prop *prop;
	struct appd_node_props *anp;
	struct appd_node_state *node;
	static u8 a, b, c;

	memset(&opts, 0, sizeof(opts));
	opts.confirm = 1;

	/*log_debug("app_ops_cloud_recovery_handler called!");
	for (i = 0; i < ARRAY_LEN(app_node); i++) {
		gw_node_conn_status_send(app_node[i].addr,
		    app_node[i].node_status, &opts);
	}*/

	for (i = 0; i < ARRAY_LEN(app_node); i++) {
		if (app_node[i].add_again) {
			app_node_create(app_node[i].addr, app_node[i].metadata);
			app_node[i].add_again = 0;
			if (!a) {
				result_record(287907, PASS);
				a = 1;
			}
		}
		if (app_node[i].update_again) {
			app_node_update(app_node[i].addr, 1);
			app_node[i].update_again = 0;
		}

		if (app_node[i].conn_again) {
			gw_node_conn_status_send(app_node[i].addr,
			    app_node[i].node_status, &opts);
			app_node[i].conn_again = 0;
			if (!b) {
				result_record(287908, PASS);
				b = 1;
			}
		}
		if (app_node[i].prop_send) {
			node = app_node_lookup(app_node[i].addr);
			app_node[i].prop_send = 0;
		}
	}

	for (i = 0; i < ARRAY_LEN(app_node_props); i++) {
		if (app_node_props[i].send_again) {
			anp = app_node_prop_lookup(app_node_props[i].name);
			prop = app_fill_gw_node_prop(anp, node->addr);
			app_node_prop_send_by_node_prop(prop, 0, NULL);
			app_node_props[i].send_again = 0;
			free(prop);
			if (!c) {
				result_record(287909, PASS);
				c = 1;
			}
		}
	}
}

/*
 * Sample gw_node_ota_handler. It is supposed to call the
 * gw_node_ota_cb with the relevant arguments.
 */
static void app_gw_node_ota_handler(const char *addr, const char *ver,
				void *cookie)
{
	static u8 discard;
	struct appd_node_state *node;

	if (!addr || !ver) {
		return;
	}
	node = app_node_lookup(addr);
	log_debug("received a node ota update version %s for node %s",
	    ver, addr);
	if (!strcmp(addr, node->addr)) {
		if (skip == 2 && app_manages_acks == 1) {
			app_eth_disconnect("node_ota");
		}
		gw_node_ota_cb(addr, cookie, discard ? NULL : "./node_ota.img",
		    NULL);
	} else {
		log_debug("node not found, discard the ota");
		gw_node_ota_cb(addr, cookie, NULL, NULL);
	}
}

static void app_gw_handlers_set(void)
{
	gw_confirm_handler_set(&app_node_ops_confirm_handler);
	gw_node_prop_set_handler_set(&app_node_props_set_handler,
	    app_manages_acks);
	gw_node_conn_get_handler_set(&app_node_conn_get_handler);
	gw_node_prop_get_handler_set(&app_node_prop_get_handler);
	gw_node_rst_handler_set(&app_gw_node_rst_handler);
	gw_cloud_fail_handler_set(&app_gw_cloud_fail_handler);
	ops_set_cloud_recovery_handler(&app_ops_cloud_recovery_handler);
	gw_node_ota_handler_set(&app_gw_node_ota_handler);
}

/*
 * Sample gateway properties template.
 */
static struct prop gw_prop_table[] = {
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
	/* temporary values for testing with demo app */
	/****** Boolean Props ******/
	{
		.name = "gw_status",
		.type = PROP_BOOLEAN,
		.send = prop_arg_send,
		.arg = &gw_status,
		.len = sizeof(gw_status),
	},
	/****** Integer Props ******/
	{
		.name = "gw_num_nodes",
		.type = PROP_INTEGER,
		.send = prop_arg_send,
		.arg = &gw_num_nodes,
		.len = sizeof(gw_num_nodes),
	},
	/****** Decimal Props ******/
	{
		.name = "gw_health",
		.type = PROP_DECIMAL,
		.send = prop_arg_send,
		.arg = &gw_health,
		.len = sizeof(gw_health),
	},
	/****** String Props ******/
	{
		.name = "gw_name",
		.type = PROP_STRING,
		.send = prop_arg_send,
		.arg = gw_name,
		.len = sizeof(gw_name),
	},
	/*
	 * Helper prop for demo'ing gateway props batching. When 'batch_hold' is
	 * set to 1, property datapoints will be batched and sent.
	 * After that 'batch_hold' is set back to zero.
	 */
	{
		.name = "gw_batch_demo",
		.type = PROP_BOOLEAN,
		.set = app_gw_batch_demo_set,
		.send = prop_arg_send,
		.arg = &gw_batch_demo,
		.len = sizeof(gw_batch_demo),
	},
	{
		.name = "gw_update_node",
		.type = PROP_INTEGER,
		.set = app_gw_update_node_set,
		.send = prop_arg_send,
		.arg = &gw_update_node,
		.len = sizeof(gw_update_node),
	},
};

static void app_poll(void)
{
	struct gw_node_prop *prop;
	struct appd_node_props *anp;
	struct op_options opts;

	memset(&opts, 0, sizeof(opts));
	opts.confirm = 1;

	if (nodes_added == 2) {
		gw_node_conn_status_send(app_node[0].addr,
		    app_node[0].node_status, &opts);
		gw_node_conn_status_send(app_node[1].addr,
		    app_node[1].node_status, &opts);

		if (skip == 3 && app_manages_acks == 0) {
			app_eth_disconnect("node conn_status");
		}
		blue_button ^= 1;
		anp = app_node_prop_lookup("Blue_button");
		prop = app_fill_gw_node_prop(anp, "node_1");
		app_node_prop_send_by_node_prop(prop, 0, NULL);
		free(prop);
		if (nodes_added == 2) {
			nodes_added = 0;
		}
	}
}

static void app_cloud_changed(bool connected)
{
	static bool first_connection = true;

	log_info("cloud connection %s", connected ? "UP" : "DOWN");

	if (connected && first_connection) {
		/*
		 * Queue the oem_host_version and version property to be sent to
		 * device service.
		 * The oem_host_version MUST be the first property sent to devd.
		 */
		prop_send_by_name("oem_host_version");
		prop_send_by_name("version");
		prop_send_by_name("status");
		prop_send_by_name("num_nodes");

		app_node_create("node_1", 0);
		app_node_create("node_2", 1);

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
	fclose(fp);
	log_info("exiting");
}

int app_init(void)
{
	char temp[PATH_MAX];

	snprintf(temp, sizeof(temp), "%s%s_%llu.tr", APP_RESULT_FILE_PATH,
	    TEST_GG_RC, ops_get_system_time_ms());

	fp = fopen(temp, "w+");
	if (fp == NULL) {
		log_err("file open error: %s", temp);
		return 0;
	}

	/* Initialize appd operations queue (single-threaded) */
	ops_init(0, NULL);

	/* Initialize property handling library */
	prop_initialize();
	/* Load property table */
	prop_add(gw_prop_table, ARRAY_LEN(gw_prop_table));

	/*
	 * initialize the gateway subsystem and register all the handlers
	 * associated with it.
	 */
	gw_initialize();
	app_gw_handlers_set();

	/* Initialize schedule handling subsystem */
	sched_init(&timers);

	/* Set event callbacks */
	ops_set_cloud_connectivity_handler(app_cloud_changed);

	/* Open socket connection to devd */
	return data_client_init(&file_events);
}
