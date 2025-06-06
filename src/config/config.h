#ifndef CONFIG_H
#define CONFIG_H

#include "str/str.h"
#include "log/log.h"

typedef struct config {
	int port;
	int secure : 1;
	int ipv4 : 1;
	int ipv6 : 1;
	int workers;
	str root;
	
} config;

config read_config(str cfg);

#endif
