/*
 * Copyright 2013-2018 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <poll.h>
#include <sys/queue.h>
#include <limits.h>
#include <unistd.h>
#include <libgen.h>
#include <signal.h>
#include <wiringPi.h>
#include <sys/wait.h>

#include <ayla/utypes.h>
#include <ayla/assert.h>
#include <ayla/log.h>
#include <ayla/build.h>
#include <ayla/ayla_interface.h>
#include <ayla/time_utils.h>
#include <ayla/timer.h>
#include <ayla/json_parser.h>

#include <app/app.h>
#include <app/msg_client.h>
#include <app/ops.h>
#include <app/props.h>

#include "appd.h"

const char *appd_version = "appd " BUILD_VERSION_LABEL;
const char *appd_template_version = "appd_demo 1.4";

#define APP_FILE_UP_PATH "etc/files/ayla_solution.png"
#define APP_FILE_DOWN_PATH "etc/files/file_down"

#define DOOR_BELL_BUTTON 6

static u8 blue_button;
static u8 door_bell_button;
static u8 blue_led;
static u8 green_led;
static u8 enable_kvs_streaming;
static u8 enable_webrtc_streaming;
static u8 batch_hold;
static struct prop_batch_list *batched_dps; /* to demo batching */
static u8 file_up_test;
static int input;
static int output;
static double decimal_in;
static double decimal_out;
static char cmd[PROP_STRING_LEN + 1];	/* add 1 for \0 */
static char log[PROP_STRING_LEN + 1];	/* add 1 for \0 */
static char aws_sec_key[PROP_STRING_LEN + 1];	/* add 1 for \0 */
static char *region=NULL;
static char *key_id = NULL;
static char *secret = NULL;
static char hls_stream_name[PROP_STRING_LEN + 1];
static char webrtc_stream_name[PROP_STRING_LEN + 1];

static u8 large_msg_down[PROP_MSG_LEN];
static u8 large_msg_up[PROP_MSG_LEN];
static char large_msg_up_test[PROP_STRING_LEN + 1];	/* add 1 for \0 */

static int hls_storage_size;
static int hls_streaming_time;
static int kvs_streaming_pid;
static int webrtc_streaming_pid;
static bool started_kvs_streaming;
static bool started_webrtc_streaming;
static struct timer kvs_streaming_timer;
static struct timer webrtc_streaming_timer;

/* install path of agent */
static char install_root[PATH_MAX];

/* file location of the latest value of file_down */
static char file_down_path[PATH_MAX];

/* file location of the latest value of file_up */
static char file_up_path[PATH_MAX];

struct webrtc_data {
        char * webrtc_channel_name;
        char * arn;
        char * region;
        char * access_key_id;
        char * secret_access_key;
        char * session_token;
        int expiration_time;
};

struct kvs_data {
        char * kvs_channel_name;
        char * arn;
        char * region;
        char * access_key_id;
        char * secret_access_key;
        char * session_token;
        int expiration_time;
        int retention_days;
};

/*
 * Send the appd software version.
 */
static enum err_t appd_send_version(struct prop *prop, int req_id,
	const struct op_options *opts)
{
	return prop_val_send(prop, req_id, appd_version, 0, NULL);
}

/*
 * File download complete callback
 */
static int appd_file_down_confirm_cb(struct prop *prop, const void *val,
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
static int appd_file_up_confirm_cb(struct prop *prop, const void *val,
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
static int appd_prop_confirm_cb(struct prop *prop, const void *val, size_t len,
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
static int appd_batch_confirm_handler(int batch_id,
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
static int appd_prop_ads_failure_cb(struct prop *prop, const void *val,
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

static int appd_hls_storage_size_set(struct prop *prop, const void *val, size_t len,
			const struct op_args *args)
{

	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		return -1;
	}
	return 0;
}

static int appd_hls_streaming_time_set(struct prop *prop, const void *val, size_t len,
			const struct op_args *args)
{

	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		return -1;
	}
	return 0;
}

/*
 * Sample set handler for "input" property.  Squares "input" and sends result
 * as the "output" property.
 */
static int appd_input_set(struct prop *prop, const void *val, size_t len,
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
static int appd_cmd_set(struct prop *prop, const void *val, size_t len,
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
static int appd_decimal_in_set(struct prop *prop, const void *val, size_t len,
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
static int appd_batch_hold_set(struct prop *prop, const void *val, size_t len,
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
static int appd_led_set(struct prop *prop, const void *val, size_t len,
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

#define KVS_STREAMING_NAME "gst-launch-1.0" 
//#define WEBRTC_STREAMING_NAME "/home/pi/amazon-kinesis-video-streams-webrtc-sdk-c/build/samples/kvsWebrtcClientMasterGstSample" 
#define WEBRTC_STREAMING_NAME "kvsWebrtcClientMasterGstSample" 
static void fork_and_start_webrtc_streaming(void);

/*
 * Terminate kvs_streaming, if managed by kvs_streaming.
 */
void kill_kvs_streaming(void)
{
        started_kvs_streaming = false;
        if (kvs_streaming_pid) {
                kill(kvs_streaming_pid, SIGTERM);
        }
	system(" pkill -9 gst-launch-1.0");
	enable_kvs_streaming = 0;
	prop_send_by_name("Enable_KVS_Streaming");
}

struct kvs_data kvs_ds;
static int kvs_streams_json(struct prop *prop, const void *val, size_t len,
			const struct op_args *args)
{
	json_t *dev_node_a, *dev_node, *credentials;
        void * itr;
        int retention_days , expiration_time;
        struct kvs_data *kvsdata = &kvs_ds;
	json_t *info = (json_t *)val;

	log_err("we have received the kvs streams json");

	itr = json_object_iter(info);
        if(itr)
        {
                log_err("info has iterations");
                dev_node_a = json_object_iter_value(itr);

        dev_node = json_array_get(dev_node_a,0);
        //ds_json_dump(__func__, dev_node);
        if (!dev_node || !json_is_object(dev_node)) {
                log_err("no kvs streaming object");
                return -1;
        }
        credentials = json_object_get(dev_node,"credentials");
        if (!credentials|| !json_is_object(credentials)) {
                log_err("credentials is not object");
                return -1;
        }

        //free(kvsdata->kvs_channel_name);
        kvsdata->kvs_channel_name = json_get_string_dup(dev_node, "name");
        log_debug2("kvs_channel_name '%s'",kvsdata->kvs_channel_name);
        //free(kvsdata->arn);
        kvsdata->arn = json_get_string_dup(dev_node, "arn");
        log_debug2("arn '%s'", kvsdata->arn);
        //free(kvsdata->region);
        kvsdata->region = json_get_string_dup(dev_node, "region");
        log_debug2("region '%s'",kvsdata->region);
        //free(kvsdata->access_key_id);
        kvsdata->access_key_id = json_get_string_dup(credentials, "access_key_id");
        log_debug2("access_key_id '%s'",kvsdata->access_key_id);
        //free(kvsdata->secret_access_key);
        kvsdata->secret_access_key= json_get_string_dup(credentials, "secret_access_key");
        log_debug2("secret_access_key '%s'",kvsdata->secret_access_key);
        //free(kvsdata->session_token);
        kvsdata->session_token = json_get_string_dup(credentials, "session_token");
        json_get_int(dev_node, "retention_days", &retention_days);
        kvsdata->retention_days = retention_days;
        log_debug2("retention days '%d' and '%d' ", retention_days , kvsdata->retention_days);
        json_get_int(credentials, "expiration", &expiration_time);
        kvsdata->expiration_time= expiration_time;
        log_debug2("expiration time '%d' and '%d' ", expiration_time , kvsdata->expiration_time);

        }
        log_debug("kvs streaming channel info is parsed ");
        return 0;

}

struct webrtc_data webrtc_ds;
static int webrtc_signaling_channels_json (struct prop *prop, const void *val, size_t len,
			const struct op_args *args)
{
	log_err("we have received the webrtc signalling channel json");
	json_t *info = (json_t *)val;
	json_t *dev_node_a, *dev_node, *credentials;
        void * itr;
        int expiration_time;
        struct webrtc_data *webrtcdata = &webrtc_ds;

	itr = json_object_iter(info);
        if(itr)
        {
                log_err("info has iterations");
                dev_node_a = json_object_iter_value(itr);

        dev_node = json_array_get(dev_node_a,0);
        //ds_json_dump(__func__, dev_node);
        if (!dev_node || !json_is_object(dev_node)) {
                log_err("no signalling channel object");
                return -1;
        }
        credentials = json_object_get(dev_node,"credentials");
        if (!credentials|| !json_is_object(credentials)) {
                log_err("credentials is not object");
                return -1;
        }

        //free(webrtcdata->webrtc_channel_name);
        webrtcdata->webrtc_channel_name = json_get_string_dup(dev_node,
            "name");
        log_debug2("webrtc_channel_name '%s'",webrtcdata->webrtc_channel_name);
        //free(webrtcdata->arn);
        webrtcdata->arn = json_get_string_dup(dev_node, "arn");
        log_debug2("arn '%s'", webrtcdata->arn);
        //free(webrtcdata->region);
        webrtcdata->region = json_get_string_dup(dev_node, "region");
        log_debug2("region '%s'",webrtcdata->region);
        //free(webrtcdata->access_key_id);
        webrtcdata->access_key_id = json_get_string_dup(credentials, "access_key_id");
        log_debug2("access_key_id '%s'",webrtcdata->access_key_id);
        //free(webrtcdata->secret_access_key);
        webrtcdata->secret_access_key= json_get_string_dup(credentials, "secret_access_key");
        log_debug2("secret_access_key '%s'",webrtcdata->secret_access_key);
        //free(webrtcdata->session_token);
        webrtcdata->session_token = json_get_string_dup(credentials, "session_token");
        json_get_int(credentials, "expiration", &expiration_time);
        webrtcdata->expiration_time = expiration_time;
        log_debug2("expiration time '%d' and '%d' ", expiration_time , webrtcdata->expiration_time);

        }
        log_debug("webrtc signalling channel info is parsed ");

	/* this is for telus demo, where we need to start the webrtc master, as soon as we received the aws keys & aws secrets */
	fork_and_start_webrtc_streaming();

	/* update property stating webrtc is enabled */
	enable_webrtc_streaming = 1;
	prop_send_by_name("Enable_WebRTC_Streaming");

	return 0;
}

/*
 * Handle kvs streaming timer timeout
 */
static void appd_kvs_streaming_timeout(struct timer *timer)
{
	log_warn("got timeout for streaming, killing the KVS Stream");
	timer_cancel(app_get_timers(), timer);	
	kill_kvs_streaming();
}

static void start_kvs_streaming()
{       
	char storage_size[16];
        char *argv[12];
	char *env[12];
	char aws_key_id[80],aws_secret[80],aws_region[40];
	char aws_session_token[2048];
        int i = 0;
        
	if( hls_storage_size == 0 )
	//if(key_id == NULL || secret == NULL || region == NULL || (strlen(hls_stream_name) == 0) || hls_storage_size == 0 )
	{
		log_err("did not set the stroage size so not starting HLS-Streaming");
        	exit(1);
	}

	snprintf(storage_size,sizeof(storage_size),"%d",hls_storage_size);

	snprintf(aws_key_id,sizeof(aws_key_id),"AWS_ACCESS_KEY_ID=%s",kvs_ds.access_key_id);
	snprintf(aws_secret,sizeof(aws_secret),"AWS_SECRET_ACCESS_KEY=%s",kvs_ds.secret_access_key);
	snprintf(aws_region,sizeof(aws_region),"AWS_DEFAULT_REGION=%s",kvs_ds.region);
	snprintf(aws_session_token,sizeof(aws_session_token),"AWS_SESSION_TOKEN=%s",kvs_ds.session_token);

        argv[i++] = "/usr/bin/sh";
	argv[i++] = "/home/pi/ayla/bin/kvs_streaming.sh";
	argv[i++] = kvs_ds.kvs_channel_name;
	argv[i++] = storage_size;
        argv[i] = NULL;

        ASSERT(i <= ARRAY_LEN(argv));
        //if (debug) 
	{
		int j = 0;
                log_debug("Starting %s using args: ", "/usr/bin/sh");
                for (j = 0; j < i; j++) {
                        log_debug("%s", argv[j]);
                }
        }

	log_warn("now setting the env list");
        i = 0;
	env[i++]="GST_PLUGIN_PATH=/home/pi/amazon-kinesis-video-streams-producer-sdk-cpp/build";
	env[i++]="LD_LIBRARY_PATH=/home/pi/amazon-kinesis-video-streams-producer-sdk-cpp/open-source/local/lib";
	env[i++]=aws_key_id;
	env[i++]=aws_secret;
	env[i++]=aws_region;
	env[i++]=aws_session_token;
	env[i]=NULL;
	{
		int j = 0;
                log_debug("Starting %s using env : ", "/usr/bin/sh");
                for (j = 0; j < i; j++) {
                        log_debug("%s", env[j]);
                }
        }
	log_warn("now executing the KVS Scripts");

        if( execve("/usr/bin/sh", argv, env) == -1)
		perror("Could not execve");
        
        /* perhaps running locally on VM */
        log_warn("executing %s failed, trying %s", KVS_STREAMING_NAME, "/usr/bin/sh");
        execve("/usr/bin/sh", argv, env);
        log_err("unable to start %s", KVS_STREAMING_NAME);
        sleep(2);
        exit(1);
}


static void fork_and_start_kvs_streaming(void)
{
        pid_t pid;

        if (started_kvs_streaming) {
                return;
        }
        log_debug("starting KVS Streaming fork");
        pid = fork();
        if (pid < 0) {
                log_err("fork failed");
                return;
        }
        started_kvs_streaming = true;
        if (pid == 0) {
                start_kvs_streaming();
        } else {
                kvs_streaming_pid = pid;
		timer_set(app_get_timers(), &kvs_streaming_timer, (hls_streaming_time * 1000));
	}
}


static int appd_enable_kvs_streaming(struct prop *prop, const void *val, size_t len,
			const struct op_args *args)
{
	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		return -1;
	}

	if(enable_kvs_streaming)
	{
		fork_and_start_kvs_streaming();
	}
	else
	{
		timer_cancel(app_get_timers(), &kvs_streaming_timer);
		kill_kvs_streaming();
	}
	
	return 0;
}

static int appd_enable_kvs_streaming_send(struct prop *prop, int req_id,
        const struct op_options *opts)
{
	return prop_val_send(prop, req_id,
            &enable_kvs_streaming, sizeof(enable_kvs_streaming), opts);
}



/*
 * Terminate webrtc_streaming, if managed by webrtc_streaming.
 */
void kill_webrtc_streaming(void)
{
        started_webrtc_streaming = false;
        if (webrtc_streaming_pid) {
                kill(webrtc_streaming_pid, SIGTERM);
        }
	enable_webrtc_streaming = 0;
	prop_send_by_name("Enable_WebRTC_Streaming");
}

/*
 * Handle kvs streaming timer timeout
 */
static void appd_webrtc_streaming_timeout(struct timer *timer)
{
	int wait_status;
        pid_t pid;
	
	pid = waitpid(-1, &wait_status, WNOHANG);
	if (pid != webrtc_streaming_pid ) {
                return;
        }
	if (WIFEXITED(wait_status)) {
		log_debug("webrtc streaming exited with status: %d",
                                    WEXITSTATUS(wait_status));
		timer_cancel(app_get_timers(), timer);	
		enable_webrtc_streaming = 0;
		started_webrtc_streaming = false;
		prop_send_by_name("Enable_WebRTC_Streaming");
		return;
	}	
	log_warn("got timeout for streaming, killing the WEBRTC Stream");
	timer_cancel(app_get_timers(), timer);	
	kill_webrtc_streaming();
}


static void start_webrtc_streaming()
{       
        char webrtc_streaming_loc[160];
	char aws_key_id[80],aws_secret[80],aws_region[40];
	char aws_session_token[2048];
        //char config_dir[PATH_MAX];
        char *argv[12];
	char *env[6];
        int i = 0;
        int j;
        
	/*if(key_id == NULL || secret == NULL || region == NULL || (strlen(webrtc_stream_name) == 0) )
	{
		log_err("did not set the aws key_id, secret or region, not starting WebrtcStreaming");
        	exit(1);
	}*/

	argv[i++] = WEBRTC_STREAMING_NAME;
	argv[i++] = webrtc_ds.webrtc_channel_name;
        argv[i] = NULL;

        ASSERT(i <= ARRAY_LEN(argv));
        //if (debug) {
                log_debug("Starting %s using args: ", WEBRTC_STREAMING_NAME);
                for (j = 0; j < i; j++) {
                        log_debug("%s", argv[j]);
                }
        //}

	snprintf(aws_key_id,sizeof(aws_key_id),"AWS_ACCESS_KEY_ID=%s",webrtc_ds.access_key_id);
	snprintf(aws_secret,sizeof(aws_secret),"AWS_SECRET_ACCESS_KEY=%s",webrtc_ds.secret_access_key);
	snprintf(aws_region,sizeof(aws_region),"AWS_DEFAULT_REGION=%s",webrtc_ds.region);
	snprintf(aws_session_token,sizeof(aws_session_token),"AWS_SESSION_TOKEN=%s",webrtc_ds.session_token);
	i=0;
	env[i++]=aws_key_id;
	env[i++]=aws_secret;
	env[i++]=aws_region;
	env[i++]=aws_session_token;
	env[i] = NULL;

        snprintf(webrtc_streaming_loc, sizeof(webrtc_streaming_loc), "/home/pi/ayla/bin/%s", WEBRTC_STREAMING_NAME);
        argv[0] = webrtc_streaming_loc;
        execve( webrtc_streaming_loc, argv , env);
        
        /* perhaps running locally on VM */
        log_warn("executing %s failed, trying %s", WEBRTC_STREAMING_NAME, webrtc_streaming_loc);
        execve(webrtc_streaming_loc, argv, env);
        log_err("unable to start %s", WEBRTC_STREAMING_NAME);
        sleep(2);
        exit(1);
}


static void fork_and_start_webrtc_streaming(void)
{
        //int wait_status;
        pid_t pid;

        if (started_webrtc_streaming) {
		log_warn("WebRTC Streaming is already started, so not starting again");
                return;
        }
        log_debug("starting WEBRTC Streaming fork");
	/* Need to reset the "enable_webrtc_streaming" value to "0" if we failed to start the webrtc streaming, so fire the time for 10000 ms, and in timeout reset the value */
	timer_set(app_get_timers(), &webrtc_streaming_timer, 10000);

        pid = fork();
        if (pid < 0) {
                log_err("fork failed");
                return;
        }
        started_webrtc_streaming = true;
        if (pid == 0) {
                start_webrtc_streaming();
        } else {
		log_warn("Can we stop the timer here ?");
                webrtc_streaming_pid = pid;
	}
}


static int appd_enable_webrtc_streaming(struct prop *prop, const void *val, size_t len,
			const struct op_args *args)
{
	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		return -1;
	}

	if(enable_webrtc_streaming)
		fork_and_start_webrtc_streaming();
	else
		kill_webrtc_streaming();
	
	return 0;
}

static int appd_enable_webrtc_streaming_send(struct prop *prop, int req_id,
        const struct op_options *opts)
{
	return prop_val_send(prop, req_id,
            &enable_webrtc_streaming, sizeof(enable_webrtc_streaming), opts);
}

static int appd_hls_stream_name_set(struct prop *prop, const void *val, size_t len,
			const struct op_args *args)
{
	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		return -1;
	}
	return 0;
}

static int appd_webrtc_stream_name_set(struct prop *prop, const void *val, size_t len,
			const struct op_args *args)
{
	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		return -1;
	}
	return 0;
}

static void door_bell_button_isr(void)
{
	if(digitalRead(DOOR_BELL_BUTTON) == LOW)
	{
		// below special handling required due to RPi, as it gives repeated values
		if(door_bell_button == 1)
		{
			// already we set the door_bell_button value to 1 no need to do it again
			return;
		}
		door_bell_button = 1;
	}
	else
	{
		// below special handling required due to RPi, as it gives repeated values
		if(door_bell_button == 0)
		{
			// already we set the door_bell_button value to 0 no need to do it again
			return;
		}
		door_bell_button = 0;
	}
	log_debug("got the event in door bell '%d'",door_bell_button);
	prop_send_by_name("Door_Bell");
}

static int appd_aws_sec_key_set(struct prop *prop, const void *val, size_t len,
			const struct op_args *args)
{
	char *pos=NULL;
	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		return -1;
	}

	/* parse the string and copy it to the respected security keys */
	region = aws_sec_key;
	pos = strchr(aws_sec_key,';');
	log_warn("1 we got the pos '%s'",pos);
	*pos = '\0';
	pos++;
	log_warn("3 we got the pos '%s'",pos);
	key_id = pos;
	pos = strchr(key_id,';');
	log_warn("4 we got the pos '%s'",pos);
	*pos = '\0';
	pos++;
	log_warn("6 we got the pos '%s'",pos);
	secret = pos;

	log_warn("we have got the aws region as '%s'",region);
	log_warn("we have got the aws key_id as '%s'",key_id);
	log_warn("we have got the aws secret as '%s'",secret);

	return 0;
}
/*
 * Send up a FILE property
 */
static int appd_file_up_test_set(struct prop *prop, const void *val, size_t len,
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

static void debug_print_memory(const void *addr, uint32_t len)
{
	char buf[64];
	uint8_t *paddr = (uint8_t *)addr;
	int i, j, k;

	i = 0;
	while (i < len) {
		memset(buf, 0, sizeof(buf));
		for (j = 0; ((j < 20) && (i + j < len)); j++) {
			k = ((paddr[i + j] & 0xF0) >> 4);
			buf[j * 3 + 0] = ((k < 10)
			    ? (k + '0') : (k - 10 + 'A'));
			k = (paddr[i + j] & 0x0F);
			buf[j * 3 + 1] = ((k < 10)
			    ? (k + '0') : (k - 10 + 'A'));
			buf[j * 3 + 2] = ' ';
		}
		log_debug("%s", buf);
		i += j;
	}
}

/*
 * Sample set handler for "large message" property.
 */
static int appd_large_prop_set(struct prop *prop, const void *val, size_t len,
			const struct op_args *args)
{
	log_debug("name %s, len %zu", prop->name, len);
	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		log_err("prop_arg_set failed");
		return 0;
	}
	debug_print_memory(prop->arg, prop->len);
	return 0;
}

/*
 * Sample send handler for "large message" property.
 */
static int appd_large_prop_send(struct prop *prop, int req_id,
			const struct op_options *opts)
{
	struct op_options st_opts;
	if (opts) {
		st_opts = *opts;
	} else {
		memset(&st_opts, 0, sizeof(st_opts));
	}
	st_opts.confirm = 1;
	debug_print_memory(prop->arg, prop->len);
	return prop_arg_send(prop, req_id, &st_opts);
}

/*
 * Large message prop complete callback
 */
static int appd_large_prop_confirm_cb(struct prop *prop, const void *val,
	size_t len, const struct op_options *opts,
	const struct confirm_info *confirm_info)
{
	if (confirm_info->status == CONF_STAT_SUCCESS) {
		log_info("%s len %zu succeeded (requested at %llu)",
		    prop->name, prop->len, opts->dev_time_ms);
		debug_print_memory(prop->arg, prop->len);
	} else {
		log_info("%s len %zu from %d failed with err %u "
		    "(requested at %llu)", prop->name, prop->len, DEST_ADS,
		    confirm_info->err, opts->dev_time_ms);
	}

	return 0;
}

/*
 * Sample set handler for "large_msg_up_test" property.
 * Copies new value to "large_msg_up" property and sends it.
 */
static int appd_large_msg_up_test_set(struct prop *prop,
		const void *val, size_t len, const struct op_args *args)
{
	struct prop *large_msg_up_prop;

	if (prop_arg_set(prop, val, len, args) != ERR_OK) {
		log_err("set %s prop value failed", prop->name);
		return -1;
	}

	large_msg_up_prop = prop_lookup("large_msg_up");
	if (!large_msg_up_prop) {
		log_info("no large_msg_up prop");
		return 0;
	}

	/* for purposes of the demo, copy the value into large_msg_up */
	snprintf(large_msg_up_prop->arg, large_msg_up_prop->buflen,
	    "%s", large_msg_up_test);
	large_msg_up_prop->len = strlen(large_msg_up_test);
	prop_send(large_msg_up_prop);

	return 0;
}


static struct prop appd_prop_table[] = {
	/* Application software version property */
	{
		.name = "version",
		.type = PROP_STRING,
		.send = appd_send_version
	},
	{
		.name = "signaling_channels",
		.set = webrtc_signaling_channels_json,
		.type = PROP_JSON,
		.ads_failure_cb = appd_prop_ads_failure_cb,
	},
	{
		.name = "kvs_streams",
		.set = kvs_streams_json,
		.type = PROP_JSON,
		.ads_failure_cb = appd_prop_ads_failure_cb,
	},
	/* Sample properties for testing with demo app */
	/****** Boolean Props ******/
	{
		.name = "Green_LED",
		.type = PROP_BOOLEAN,
		.set = appd_led_set,
		.send = prop_arg_send,
		.arg = &green_led,
		.len = sizeof(green_led),
		.ads_failure_cb = appd_prop_ads_failure_cb,
	},
	{
		.name = "Blue_LED",
		.type = PROP_BOOLEAN,
		.set = appd_led_set,
		.send = prop_arg_send,
		.arg = &blue_led,
		.len = sizeof(blue_led),
		.ads_failure_cb = appd_prop_ads_failure_cb,
	},
	{
		.name = "Blue_button",
		.type = PROP_BOOLEAN,
		.send = prop_arg_send,
		.arg = &blue_button,
		.len = sizeof(blue_button),
		.ads_failure_cb = appd_prop_ads_failure_cb,
	},
	{
		.name = "Door_Bell",
		.type = PROP_BOOLEAN,
		.send = prop_arg_send,
		.arg = &door_bell_button,
		.len = sizeof(door_bell_button),
		.ads_failure_cb = appd_prop_ads_failure_cb,
	},

	{
		.name = "Enable_KVS_Streaming",
		.type = PROP_BOOLEAN,
		.set = appd_enable_kvs_streaming,
		.send = appd_enable_kvs_streaming_send,
		.arg = &enable_kvs_streaming,
		.len = sizeof(enable_kvs_streaming),
		.ads_failure_cb = appd_prop_ads_failure_cb,
	},
	{
		.name = "Enable_WebRTC_Streaming",
		.type = PROP_BOOLEAN,
		.set = appd_enable_webrtc_streaming,
		.send = appd_enable_webrtc_streaming_send,
		.arg = &enable_webrtc_streaming,
		.len = sizeof(enable_webrtc_streaming),
		.ads_failure_cb = appd_prop_ads_failure_cb,
	},

	/****** Integer Props ******/
	{
		.name = "input",
		.type = PROP_INTEGER,
		.set = appd_input_set,
		.send = prop_arg_send,
		.arg = &input,
		.len = sizeof(input),
		.ads_failure_cb = appd_prop_ads_failure_cb,
	},
	{
		.name = "HLS_Storage_Size",
		.type = PROP_INTEGER,
		.set = appd_hls_storage_size_set,
		.arg = &hls_storage_size,
		.len = sizeof(hls_storage_size),
		.ads_failure_cb = appd_prop_ads_failure_cb,
	},
	{
		.name = "HLS_Streaming_Time",
		.type = PROP_INTEGER,
		.set = appd_hls_streaming_time_set,
		.arg = &hls_streaming_time,
		.len = sizeof(hls_streaming_time),
		.ads_failure_cb = appd_prop_ads_failure_cb,
	},
	{
		.name = "output",
		.type = PROP_INTEGER,
		.send = prop_arg_send,
		.arg = &output,
		.len = sizeof(output),
		.confirm_cb = appd_prop_confirm_cb,
		.ads_failure_cb = appd_prop_ads_failure_cb,
	},
	/****** Decimal Props ******/
	{
		.name = "decimal_in",
		.type = PROP_DECIMAL,
		.set = appd_decimal_in_set,
		.send = prop_arg_send,
		.arg = &decimal_in,
		.len = sizeof(decimal_in),
		.ads_failure_cb = appd_prop_ads_failure_cb,
	},
	{
		.name = "decimal_out",
		.type = PROP_DECIMAL,
		.send = prop_arg_send,
		.arg = &decimal_out,
		.len = sizeof(decimal_out),
		.ads_failure_cb = appd_prop_ads_failure_cb,
	},
	/****** String Props ******/
	{
		.name = "cmd",
		.type = PROP_STRING,
		.set = appd_cmd_set,
		.send = prop_arg_send,
		.arg = cmd,
		.len = sizeof(cmd),
		.ads_failure_cb = appd_prop_ads_failure_cb,
	},
	{
		.name = "log",
		.type = PROP_STRING,
		.send = prop_arg_send,
		.arg = log,
		.len = sizeof(log),
		.ads_failure_cb = appd_prop_ads_failure_cb,
	},
	{
		.name = "AWS_Sec_Key",
		.type = PROP_STRING,
		.set = appd_aws_sec_key_set,
		.arg = aws_sec_key,
		.len = sizeof(aws_sec_key),
		.ads_failure_cb = appd_prop_ads_failure_cb,
	},
	{
		.name = "HLS_Stream_Name",
		.type = PROP_STRING,
		.set = appd_hls_stream_name_set,
		.arg = hls_stream_name,
		.len = sizeof(hls_stream_name),
		.ads_failure_cb = appd_prop_ads_failure_cb,
	},
	{
		.name = "WebRTC_Stream_Name",
		.type = PROP_STRING,
		.set = appd_webrtc_stream_name_set,
		.arg = webrtc_stream_name,
		.len = sizeof(webrtc_stream_name),
		.ads_failure_cb = appd_prop_ads_failure_cb,
	},

	/****** File Props ******/
	{
		.name = "file_down",
		.type = PROP_FILE,
		.set = prop_arg_set,
		.arg = file_down_path,
		.len = sizeof(file_down_path),
		.confirm_cb = appd_file_down_confirm_cb,
		.ads_failure_cb = appd_prop_ads_failure_cb,
	},
	{
		.name = "file_up",
		.type = PROP_FILE,
		.send = prop_arg_send,
		.arg = file_up_path,
		.len = sizeof(file_up_path),
		.confirm_cb = appd_file_up_confirm_cb,
		.ads_failure_cb = appd_prop_ads_failure_cb,
	},
	/* Helper props for demo'ing file props */
	{
		.name = "file_up_test",
		.type = PROP_BOOLEAN,
		.set = appd_file_up_test_set,
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
		.set = appd_batch_hold_set,
		.send = prop_arg_send,
		.arg = &batch_hold,
		.len = sizeof(batch_hold),
	},
	{
		.name = "large_msg_down",
		.type = PROP_MESSAGE,
		.set = appd_large_prop_set,
		.send = appd_large_prop_send,
		.arg = large_msg_down,
		.len = sizeof(large_msg_down),
		.buflen = sizeof(large_msg_down),
		.confirm_cb = appd_large_prop_confirm_cb,
		.ads_failure_cb = appd_prop_ads_failure_cb,
	},
	{
		.name = "large_msg_up",
		.type = PROP_MESSAGE,
		.send = appd_large_prop_send,
		.arg = large_msg_up,
		.len = sizeof(large_msg_up),
		.buflen = sizeof(large_msg_up),
		.confirm_cb = appd_large_prop_confirm_cb,
		.ads_failure_cb = appd_prop_ads_failure_cb,
	},
	{
		.name = "large_msg_up_test",
		.type = PROP_STRING,
		.set = appd_large_msg_up_test_set,
		.send = prop_arg_send,
		.arg = large_msg_up_test,
		.len = sizeof(large_msg_up_test),
		.ads_failure_cb = appd_prop_ads_failure_cb,
	},
};

/*
 * Hook for the app library to initialize the user-defined application.
 */
int appd_init(void)
{
	int ret = 0;
	int len;

	log_info("application initializing");

	/* Determine install root path and set file paths */
	len = readlink("/proc/self/exe",
	    install_root, sizeof(install_root));
	install_root[len] = '\0';
	dirname(dirname(install_root));
	len = snprintf(file_up_path, sizeof(file_up_path), "%s/%s",
	    install_root, APP_FILE_UP_PATH);
	if (len >= sizeof(file_up_path)) {
		log_err("file path %s was truncated", file_up_path);
		ret = -1;
	} else if (len < 0) {
		log_err("output error occured");
		ret = -1;
	}
	len = snprintf(file_down_path, sizeof(file_down_path), "%s/%s",
	    install_root, APP_FILE_DOWN_PATH);
	if (len >= sizeof(file_down_path)) {
		log_err("file path %s was truncated", file_down_path);
		ret = -1;
	} else if (len < 0) {
		log_err("output error occured");
		ret = -1;
	}
	/* Load property table */
	prop_add(appd_prop_table, ARRAY_LEN(appd_prop_table));

	/* Set property confirmation handlers */
	prop_batch_confirm_handler_set(appd_batch_confirm_handler);

	return ret;
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

	/*
	 * Perform any application-specific tasks needed prior to starting.
	 */

	wiringPiSetup();	
	pinMode(DOOR_BELL_BUTTON, INPUT);
	wiringPiISR(DOOR_BELL_BUTTON, INT_EDGE_BOTH, &door_bell_button_isr);

	timer_init(&kvs_streaming_timer, appd_kvs_streaming_timeout);
	timer_init(&webrtc_streaming_timer, appd_webrtc_streaming_timeout);

	return 0;
}

/*
 * Hook for the app library to notify the user-defined application that the
 * process is about to terminate.
 */
void appd_exit(int status)
{
	log_info("application exiting with status: %d", status);

	/* in case, app is exiting, we need to kill webrtc and HLS streaming as well */
	kill_webrtc_streaming();
	kill_kvs_streaming();

	/*
	 * Perform any application-specific tasks needed prior to exiting.
	 */
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
		prop_send_from_dev(true);

		/* Request all to-device properties from the cloud */
		prop_request_to_dev();

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

