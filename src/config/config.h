#ifndef CONFIG_H
#define CONFIG_H

#include "str/str.h"
#include "log/log.h"
#include "list/list.h"
#include "mime/mime.h"
#include "rewrites/rewrites.h"
#include <errno.h>


typedef struct config {
	str file;
	str name;
	str port;
	int backlog;
	str root;
	str bundle;
	str cert;
	str key;
	uint secure : 1;
	uint ipv4 : 1;
	uint ipv6 : 1;
	str *files;
} config;


config read_config(char *filename);

str get_key(str file, str key);

void free_config(config *conf);

void print_config(config conf);

#endif