#ifndef DIR_H
#define DIR_H

#ifndef _LARGEFILE_SOURCE
#define _LARGEFILE_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <dirent.h>
#include <sys/stat.h>
#include "str/str.h"


struct file {
	struct str name;
	bool temp;
};


uint64_t get_fd_size(int fd);

uint64_t get_fp_size(FILE *fp);

uint64_t get_file_size(char *filename);

struct str get_file_format(struct str filename);

uint64_t getNEntries(const char *dir);

char **getFiles(const char *dir);

#endif
