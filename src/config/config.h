#ifndef CONFIG_H
#define CONFIG_H

#include "str/str.h"
#include "log/log.h"
#include "list/list.h"
#include "mime/mime.h"
#include <errno.h>


typedef struct config_m {
	str file;
	str name;
	int port;
	int backlog;
} config_m;

typedef struct config_w {
	str file;
	str name;
	str root;
	str bundle;
	str cert;
	str key;
	uint secure : 1;
	uint ipv4 : 1;
	uint ipv6 : 1;
	str *files;
} config_w;


config_m master_config(char *filename);
config_w worker_config(char *filename);

void free_master_config(config_m *conf);
void free_worker_config(config_w *conf);

void print_master_config(config_m conf);
void print_worker_config(config_w conf);

#endif
