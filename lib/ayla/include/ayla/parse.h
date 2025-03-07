/*
 * Copyright 2011-2018 Ayla Networks, Inc.  All rights reserved.
 *
 * Use of the accompanying software is permitted only in accordance
 * with and subject to the terms of the Software License Agreement
 * with Ayla Networks, Inc., a copy of which can be obtained from
 * Ayla Networks, Inc.
 */
#ifndef __AYLA_PARSE_H__
#define __AYLA_PARSE_H__

#include <unistd.h>
#include <string.h>
#include <ayla/utypes.h>

char *format_mac(const u8 *mac, char *buf, size_t len);

int parse_argv(char **argv, int argv_len, char *buf);
int parse_mac(u8 *mac, const char *val);
ssize_t parse_hex(void *buf, size_t len, const char *hex);
void parse_url(char *name, char **access, char **host, char **path);
int string_strip(char *src, char *dst, int maxlen);

int parse_http_date(u32 *timep, int argc, char **argv);

int hostname_valid(char *);

#endif /* __AYLA_PARSE_H__ */
