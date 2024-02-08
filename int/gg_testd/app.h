/*
 * Copyright 2013-2018 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __APP_H__
#define __APP_H__

#include <ayla/file_event.h>
#include <ayla/timer.h>

/*
 * Replace *eng* with hashtag details.
 */
#define TEST_GG_RC "Ayla_gateway-eng"

/*
 * File descriptor listener and timer data structures.
 */
extern struct file_event_table file_events;
extern struct timer_head timers;

/*
 * Functions provided by application.
 */
int app_init(void);
void app_start(void);
void app_exit(void);

#endif /* __APP_H__ */
