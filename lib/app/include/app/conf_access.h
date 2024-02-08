/*
 * Copyright 2011-2018 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __LIB_APP_CONF_ACCESS_H__
#define __LIB_APP_CONF_ACCESS_H__

/*
 * Register a handler for handling a factory reset. Lib will take care of
 * replacing the startup config with factory config and rebooting appd.
 */
void conf_factory_reset_handler_set(void (*handler)(void));

/*
 * Execute a factory reset on the appd side
 */
void conf_factory_reset_execute(void);

#endif /* __LIB_APP_CONF_ACCESS_H__ */
