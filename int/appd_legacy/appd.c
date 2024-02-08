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
#include <unistd.h>
#include <getopt.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/stat.h>

#include <stddef.h>
#include <errno.h>

#include <ayla/utypes.h>
#include <ayla/socket.h>
#include <ayla/file_io.h>
#include <ayla/log.h>
#include <ayla/assert.h>
#include <ayla/conf_io.h>
#include <ayla/conf_access.h>
#include <ayla/timer.h>
#include <ayla/sched.h>

#include "app.h"

#define APPD_SOCK_SUBDIR	"appd"
#define APPD_CONF_DIR		"/config"
#define APPD_CONF_FILE		"appd.conf"

int debug;
char appd_conf_factory[PATH_MAX];
char app_sock_path[SOCKET_PATH_STR_LEN];
const char *appd_conf_startup_dir;
static char *cmdname;

/*
 * File descriptor listener and timer data structures.
 */
struct file_event_table file_events;
struct timer_head timers;

static const struct option options[] = {
	{ .name = "debug", .val = 'd'},
	{ .name = "foreground", .val = 'f'},
	{ .name = "sockdir", .has_arg = 1, .val = 'o'},
	{ .name = "factory_config", .has_arg = 1, .val = 'c'},
	{ .name = "startup_dir", .has_arg = 1, .val = 's'},
	{ .name = NULL }
};

/*
 * Shows usage information for running appd
 */
static void usage(void)
{
	fprintf(stderr, "Usage: %s\n", cmdname);
	fprintf(stderr, "  Options:\n");
	fprintf(stderr, "    -c --factory_config <file>		"
	    "Specify factory config directory\n");
	fprintf(stderr, "    -s --startup_dir <dir>		"
	    "Specify startup config directory\n");
	fprintf(stderr, "    -d --debug				"
	    "Run in debug mode\n");
	fprintf(stderr, "    -f --foreground			"
	    "Don't detach daemon process, run in foreground\n");
	fprintf(stderr, "    -o --sockdir	<dir>		"
	    "Specify socket directory\n");
	exit(EXIT_FAILURE);
}

/*
 * Parse the command line options passed into appd
 */
static void appd_opts(int argc, char **argv)
{
	int long_index = 0;
	int opt;
	int foreground = 0;
	char *socket_dir = SOCK_DIR_DEFAULT;
	const char *conf_path = APPD_CONF_DIR "/" APPD_CONF_FILE;

	cmdname = strrchr(argv[0], '/');
	if (cmdname) {
		cmdname++;
	} else {
		cmdname = argv[0];
	}
	optind = 0;
	while ((opt = getopt_long(argc, argv, "?dfo:c:s:",
	    options, &long_index)) != -1) {
		switch (opt) {
		case 'f':
			foreground = 1;
			break;
		case 'd':
			debug = 1;
			break;
		case 'o':
			socket_dir = file_clean_path(optarg);
			break;
		case 'c':
			conf_path = file_clean_path(optarg);
			break;
		case 's':
			appd_conf_startup_dir = file_clean_path(optarg);
			break;
		case '?':
		default:
			usage();
			break;
		}
	}
	if (optind < argc) {
		fprintf(stderr, "%s: unused arguments\n", cmdname);
		usage();
	}
	log_init(cmdname, LOG_OPT_FUNC_NAMES);
	if (foreground) {
		log_set_options(LOG_OPT_CONSOLE_OUT);
	}
	if (debug) {
		log_set_options(LOG_OPT_DEBUG | LOG_OPT_TIMESTAMPS);
	}
	log_set_subsystem(LOG_SUB_APP);
	if (!foreground && daemon(0, 0) < 0) {
		log_err("daemon failed: %m");
	}
	if (file_is_dir(conf_path)) {
		/* Config directory was specified, so use default file name */
		snprintf(appd_conf_factory, sizeof(appd_conf_factory),
		    "%s/%s", conf_path, APPD_CONF_FILE);
	} else {
		snprintf(appd_conf_factory, sizeof(appd_conf_factory),
		    "%s", conf_path);
	}

	/* Generate socket directory */
	snprintf(app_sock_path, sizeof(app_sock_path), "%s/%s/%s", socket_dir,
	    APPD_SOCK_SUBDIR, SOCKET_NAME);
}

static void appd_exit_handler(void)
{
	log_debug("inside exit handler");
	sched_destroy();
	app_exit();
	conf_cleanup();
}

/*
 * Main function
 */
int main(int argc, char **argv)
{
	/* Parse command line options */
	appd_opts(argc, argv);

	/* Initialize file event listener state */
	file_event_init(&file_events);

	/* Create a blank default config file, if none was provided */
	if (access(appd_conf_factory, R_OK) < 0) {
		log_info("creating new factory config: %s",
			appd_conf_factory);
		conf_save_empty(appd_conf_factory);
	}
	/* Initialize config file subsystem */
	if (conf_init(appd_conf_factory, appd_conf_startup_dir) < 0) {
		exit(EXIT_FAILURE);
	}
	/* Application initialization hook */
	if (app_init()) {
		exit(EXIT_FAILURE);
	}
	atexit(appd_exit_handler);
	/* Load config file and apply to application state */
	if (conf_load()) {
		exit(EXIT_FAILURE);
	}
	/* Application start hook */
	app_start();
	return 0;
}
