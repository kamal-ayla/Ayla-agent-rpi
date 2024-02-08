/*
 * Copyright 2013-2018 Ayla Networks, Inc.  All rights reserved.
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
#include <sys/un.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <signal.h>
#include <stddef.h>
#include <errno.h>

#include <ayla/utypes.h>
#include <ayla/assert.h>
#include <ayla/log.h>
#include <ayla/timer.h>
#include <ayla/file_event.h>
#include <ayla/amsg.h>


#define TEST_CLIENT_RECONNECT_MS	1000
#define TEST_ACTION_PERIOD_MS		500
#define TEST_DEFERRED_RESPONSE_MS	1500

#define TEST_INTERFACE		0x01

enum test_type {
	TEST_MSG		= 100,
	TEST_MSG_RESP		= 101
};

#define TEST_DATA_VALUE		12345
struct test_msg_data {
	int test_data;
};

struct timer_head timers;
struct file_event_table file_events;

struct timer reconnect_timer;
struct timer test_timer;

struct amsg_server server;
struct amsg_client client;

struct session_state {
	char label[64];
	struct timer response_timer;
	struct amsg_resp_info *response_info;
};

const char *path;
bool is_server;

static void test_async_response(struct timer *timer);

/*
 * Allocate a session state structure.
 */
static struct session_state *session_state_alloc(void)
{
	static uint32_t index;
	struct session_state *state;

	state = (struct session_state *)calloc(1, sizeof(struct session_state));
	REQUIRE(state, REQUIRE_MSG_ALLOCATION);
	snprintf(state->label, sizeof(state->label), "test client %u", ++index);
	timer_init(&state->response_timer, test_async_response);

	return state;
}

/*
 * Cleanup and free a session state structure.
 */
static void session_state_free(void *data)
{
	struct session_state *state = (struct session_state *)data;

	if (!state) {
		return;
	}
	/* Cancel possible outstanding deferred test message response */
	timer_cancel(&timers, &state->response_timer);
	/* Free the async response info, if it has not been sent */
	amsg_free_async_resp_info(&state->response_info);
	free(state);
}

static void reconnect_client(struct timer *timer)
{
	log_info("attempting to reconnect to %s", path);
	if (amsg_client_connect(&client, path) < 0) {
		timer_set(&timers, &reconnect_timer, TEST_CLIENT_RECONNECT_MS);
	}
}

/*
 * Handle client connectivity event.
 */
static void client_event(struct amsg_endpoint *endpoint,
	enum amsg_endpoint_event event)
{
	log_info("%s", event == AMSG_ENDPOINT_CONNECT ?
	    "connected" : "disconnected");

	/* Attempt to reconnect client automatically */
	if (event == AMSG_ENDPOINT_DISCONNECT) {
		timer_set(&timers, &reconnect_timer, TEST_CLIENT_RECONNECT_MS);
	}
}

/*
 * Handle server connectivity event.
 */
static void server_event(struct amsg_endpoint *endpoint,
	enum amsg_endpoint_event event)
{
	struct session_state *state;

	switch (event) {
	case AMSG_ENDPOINT_CONNECT:
		/* Associate some state with each new server session */
		state = session_state_alloc();
		amsg_set_user_data(endpoint, 0, state, session_state_free);
		log_info("%s: CONNECTED (%zu sessions)",
		    state->label, server.num_sessions);
		break;
	case AMSG_ENDPOINT_DISCONNECT:
		state = (struct session_state *)amsg_get_user_data(endpoint, 0);
		log_info("%s: DISCONNECTED (%zu sessions)",
		    state->label, server.num_sessions);
		break;
	}
}

/*
 * Message handler for test message.  Validates some test data and sends a
 * response later, if resources allow.  If not, we return an error and allow
 * the handler system to send a default response indicating the error.
 */
static enum amsg_err test_msg_handler(struct amsg_endpoint *endpoint,
	const struct amsg_msg_info *info,
	struct amsg_resp_info *resp_info)
{
	struct test_msg_data *msg = (struct test_msg_data *)info->payload;
	struct session_state *session_state;

	if (msg->test_data != TEST_DATA_VALUE) {
		log_err("test msg CORRUPT: %d", msg->test_data);
		return AMSG_ERR_DATA_CORRUPT;
	}
	log_info("test msg VALID: %d", msg->test_data);

	if (resp_info) {
		/* Only server tests deferred async response */
		if (!is_server) {
			return amsg_send_resp(&resp_info,
			    TEST_INTERFACE, TEST_MSG_RESP, NULL, 0);
		}
		session_state = (struct session_state *)
		    amsg_get_user_data(endpoint, 0);

		if (timer_active(&session_state->response_timer)) {
			log_warn("only able to defer a single async resp");
			return AMSG_ERR_APPLICATION;
		}
		log_info("scheduling async response in %ums",
		    TEST_DEFERRED_RESPONSE_MS);
		session_state->response_info = amsg_alloc_async_resp_info(
		    resp_info);
		timer_set(&timers, &session_state->response_timer,
		    TEST_DEFERRED_RESPONSE_MS);
	}
	return AMSG_ERR_NONE;
}

/*
 * Sends an asynchronous response at timer timeout.
 */
static void test_async_response(struct timer *timer)
{
	enum amsg_err err;
	struct session_state *state =
	    CONTAINER_OF(struct session_state, response_timer, timer);

	log_info("sending async response");
	err = amsg_send_resp(&state->response_info,
	    TEST_INTERFACE, TEST_MSG_RESP, NULL, 0);
	if (err) {
		log_err("error: %s", amsg_err_string(err));
	}
}

/*
 * Handle a ping response
 */
static void async_ping_callback(enum amsg_err err, uint32_t time_ms)
{
	if (err) {
		log_warn("PING error: %s", amsg_err_string(err));
	} else {
		log_info("PING time: %u ms", time_ms);
	}
}

/*
 * Message interface handler for the test interface.
 */
static enum amsg_err test_interface_handler(struct amsg_endpoint *endpoint,
	const struct amsg_msg_info *info, struct amsg_resp_info *resp_info)
{
	ASSERT(info->interface == TEST_INTERFACE);

	switch (info->type) {
	case TEST_MSG:
		/* Handle test messge */
		return test_msg_handler(endpoint, info, resp_info);
	case TEST_MSG_RESP:
		/*
		 * Demonstrate rejecting an unsupported message type.
		 * A default response message will be sent back to the
		 * sender indicating the error.
		 */
		log_info("TEST_MSG_RESP");
		return AMSG_ERR_TYPE_UNSUPPORTED;
	default:
		break;
	}
	return AMSG_ERR_TYPE_UNSUPPORTED;
}

/*
 * Custom response handler.
 */
static void msg_response_handler(struct amsg_endpoint *endpoint,
	enum amsg_err err, const struct amsg_msg_info *info, void *reply_arg)
{
	if (err) {
		log_err("message failed: %s", amsg_err_string(err));
		return;
	}
	AMSG_DEBUG_PRINT_MSG_INFO("received reply", *info);
}

/*
 * Send a test message synchronously with a custom response handler.
 */
static enum amsg_err send_test_msg(struct amsg_endpoint *endpoint)
{
	struct test_msg_data msg = { TEST_DATA_VALUE };

	log_info("Sending test message to server");
	return amsg_send_sync(endpoint, TEST_INTERFACE, TEST_MSG,
	    &msg, sizeof(msg), msg_response_handler, NULL, 0);
}

/*
 * Repeating test action.
 */
static void test_action(struct timer *timer)
{
	struct amsg_endpoint *endpoint;
	enum amsg_err err = AMSG_ERR_NONE;

	if (is_server) {
		/* Ping each connected client with 1s timeout */
		AMSG_SERVER_SESSION_FOREACH(endpoint, &server) {
			log_info("Sending ping to %s", ((struct session_state *)
			    amsg_get_user_data(endpoint, 0))->label);
			err = amsg_ping(endpoint, 1000, async_ping_callback);
			if (err) {
				log_err("ping error: %s", amsg_err_string(err));
			}
		}
	} else if (amsg_connected(&client.endpoint)) {
		/*
		 * Ping server, then synchronously send test msg.  Client will
		 * block until server responds to the test message, meaning it
		 * cannot immediately process the ping response. This delay
		 * will be revealed by the ping response time, once the ping
		 * response is received.
		 */
		log_info("Sending ping to server");
		err = amsg_ping(&client.endpoint, TEST_DEFERRED_RESPONSE_MS * 2,
		    async_ping_callback);
		if (err) {
			log_err("ping error: %s", amsg_err_string(err));
		}
		err = send_test_msg(&client.endpoint);
		if (err) {
			log_err("test msg error: %s", amsg_err_string(err));
		}
	}
	/* Reset timer */
	timer_set(&timers, &test_timer, TEST_ACTION_PERIOD_MS);
}

static void signal_handler(int signal)
{
	if (is_server) {
		log_info("stopping server");
		amsg_server_stop(&server);
	} else {
		log_info("disconnecting client");
		amsg_client_disconnect(&client);
	}
	exit(signal);
}

int main(int argc, char **argv)
{
	log_init(argv[0], LOG_OPT_FUNC_NAMES | LOG_OPT_CONSOLE_OUT |
	    LOG_OPT_DEBUG | LOG_OPT_TIMESTAMPS);

	if (argc != 3) {
		log_err("usage: %s <path> <{server,client}>", argv[0]);
		return 1;
	}
	path = argv[1];
	is_server = !strcmp(argv[2], "server");

	log_info("Starting amsg test");
	log_info("path=%s mode=%s", path, is_server ? "server" : "client");

	file_event_init(&file_events);
	timer_init(&test_timer, test_action);

	/* Register a handler for the test message interface */
	amsg_set_interface_handler(TEST_INTERFACE, test_interface_handler);

	if (is_server) {
		log_info("Initializing server");
		if (amsg_server_init(&server, &file_events, &timers) < 0) {
			log_err("amsg_server_init failed");
			exit(1);
		}
		log_info("done");
		amsg_server_set_session_event_callback(&server, server_event);
		amsg_server_set_max_sessions(&server, 10);
		log_info("Starting server");
		if (amsg_server_start(&server, path, 0777) < 0) {
			log_err("amsg_server_start failed");
			exit(1);
		}
		log_info("done");
	} else {
		log_info("Initializing client");
		timer_init(&reconnect_timer, reconnect_client);
		if (amsg_client_init(&client, &file_events, &timers) < 0) {
			log_err("amsg_client_init failed");
			exit(1);
		}
		log_info("done");
		amsg_client_set_event_callback(&client, client_event);
		log_info("Connecting");
		if (amsg_client_connect(&client, path) < 0) {
			log_err("amsg_client_connect failed");
			exit(1);
		}
		log_info("done");
	}

	/* Register exit signal handler */
	signal(SIGINT, signal_handler);

	/* Start test events */
	test_action(&test_timer);

	log_info("Starting poll loop");
	for (;;) {
		if (file_event_poll(&file_events, timer_advance(&timers)) < 0) {
			log_info("Ending poll loop");
			break;
		}
	}
	log_info("Ending amsg test");
	return 0;
}
