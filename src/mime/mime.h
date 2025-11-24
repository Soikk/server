#ifndef MIME_H
#define MIME_H

#include "str/str.h"
#include "list/list.h"


typedef struct mime_type {
	str desc;
	str ext;
} mime_type;


void add_mime_type(mime_type mt);
void read_mime_types(str file);
str get_mime_type(str ext);
void free_mime_types(void);

void print_mime_types(void);

#endif