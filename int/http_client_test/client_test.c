/*
 * Copyright 2016-2018 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <errno.h>

#include <curl/curl.h>

#include <ayla/utypes.h>
#include <ayla/assert.h>
#include <ayla/log.h>
#include <ayla/timer.h>
#include <ayla/file_event.h>
#include <ayla/file_io.h>
#include <ayla/nameval.h>
#include <ayla/http.h>
#include <ayla/http_client.h>


struct timer_head timers;
struct file_event_table file_events;

struct http_client *client;

DEF_NAMEVAL_TABLE(method_table, HTTP_METHODS);


struct context {
	unsigned id;
	struct http_client_context *context;
	FILE *in_file;
	FILE *out_file;
};


void server_parse_len(int argc, char **argv, void *arg)
{
	struct context *c = (struct context *)arg;
	unsigned i;

	for (i = 0; i < argc; ++i) {
		log_info("[%u] %s", c->id, argv[i]);
	}
}

void server_parse_content_type(int argc, char **argv, void *arg)
{
	struct context *c = (struct context *)arg;
	unsigned i;

	for (i = 0; i < argc; ++i) {
		log_info("[%u] %s", c->id, argv[i]);
	}
}

struct http_tag tags[] = {
	{ "Content-Length", server_parse_len },
	{ "Content-Type", server_parse_content_type },
	{ NULL }
};

ssize_t read_func(void *buf, size_t size, size_t offset, void *arg)
{
	struct context *c = (struct context *)arg;
	size_t len;

	ASSERT(c != NULL);

	if (!c->in_file) {
		return 0;
	}

	len = fread(buf, 1, size, c->in_file);
	log_info("[%u] read %zu of %zu bytes @ offset %zu", c->id, len, size,
	    offset);

	return len;
}

ssize_t write_func(const void *buf, size_t size, size_t offset, void *arg)
{
	struct context *c = (struct context *)arg;
	size_t len;

	ASSERT(c != NULL);

	len = fwrite(buf, 1, size, c->out_file);
	log_info("[%u] write %zu of %zu bytes @ offset %zu", c->id, len, size,
	    offset);

	return len != size ? -1 : len;
}

void resp_callback(enum http_client_err err,
	const struct http_client_req_info *info, void *arg)
{
	struct context *c = (struct context *)arg;

	if (err) {
		log_err("[%u] request error: %s", c->id,
		    http_client_err_string(err));
	} else {
		log_info("[%u] request complete: status %hu", c->id,
		    info->http_status);
	}
	log_debug("curl_error=%s recvd_bytes=%zu time=%ums up_speed=%ubps "
	    "down_speed=%ubps content_type=%s local_ip=%s remote_ip=%s",
	    curl_easy_strerror((CURLcode)info->curl_error),
	    info->received_bytes, info->time_ms,
	    info->upload_speed_bps, info->download_speed_bps,
	    info->content_type, info->local_ip, info->remote_ip);
}


static void signal_handler(int signal)
{
	log_info("caught signal %d", signal);

	http_client_cleanup(client);

	log_info("Ending client test");

	exit(signal);
}

int main(int argc, char **argv)
{
	const char *method_str;
	const char *url;
	const char *path;
	unsigned count;
	size_t file_size = 0;
	int rc;
	enum http_method method;
	unsigned i;
	char out_path[100];
	char context_name[100];

	struct context *contexts = NULL;

	log_init(argv[0], LOG_OPT_FUNC_NAMES | LOG_OPT_CONSOLE_OUT |
	    LOG_OPT_DEBUG | LOG_OPT_TIMESTAMPS | LOG_OPT_NO_SYSLOG);

	if (argc < 4 || argc > 5) {
		log_err("usage: %s <method> <url> <count> [send file path]",
		    argv[0]);
		return 1;
	}
	method_str = argv[1];
	url = argv[2];
	count = strtoul(argv[3], NULL, 10);
	path = argc == 5 ? argv[4] : NULL;

	rc = lookup_by_name(method_table, method_str);
	if (rc == -1) {
		log_err("invalid method: %s", method_str);
		return 1;
	}
	method = rc;
	if (!count) {
		log_err("invalid count: %s", argv[3]);
		return 1;
	}
	if (path) {
		file_size = file_get_size(path);
		if (file_size < 0) {
			return 1;
		}
	}

	log_info("Starting client test");
	log_info("method=%s url=%s count=%u file=%s",
	    http_method_names[method],
	    url, count, path ? path : "NONE");

	file_event_init(&file_events);

	/* Register exit signal handler */
	signal(SIGINT, signal_handler);

	/* Setup client */
	log_info("Initializing client");
	client = http_client_init(&file_events, &timers);
	ASSERT(client != NULL);

	/* Add contexts */
	contexts = calloc(count, sizeof(*contexts));
	for (i = 0; i < count; ++i) {
		contexts[i].id = i + 1;
		snprintf(out_path, sizeof(out_path),
		    "download_%u.txt", contexts[i].id);
		if (path) {
			contexts[i].in_file = fopen(path, "r+");
		}
		contexts[i].out_file = fopen(out_path, "w");

		log_info("[%u] add context", contexts[i].id);
		contexts[i].context = http_client_context_add(client);
		ASSERT(contexts[i].context != NULL);
		http_client_context_set_data_funcs(contexts[i].context,
		    read_func, write_func, &contexts[i]);
		snprintf(context_name, sizeof(context_name), "test %u",
		    contexts[i].id);
		/* Enable all debug */
		http_client_context_set_debug(contexts[i].context, 0xff,
		    context_name);
	}
	log_info("configure and send requests");
	for (i = 0; i < count; ++i) {
		http_client_add_header(contexts[i].context, "Content-Type",
		    "application/test%u", i);
		http_client_add_header(contexts[i].context, "Accept-Charset",
		    "utf-8");
		http_client_set_header_parsers(contexts[i].context, tags);

		log_info("[%u] sending %zu bytes", contexts[i].id, file_size);
		rc = http_client_send(contexts[i].context, method, url,
		    file_size, resp_callback, &contexts[i], 0);
		if (rc < 0) {
			log_err("start send failed");
		}
	}

	log_info("Starting poll loop");
	for (;;) {
		if (file_event_poll(&file_events, timer_advance(&timers)) < 0) {
			log_info("Ending poll loop");
			break;
		}
	}
	free(contexts);
	return 0;
}
