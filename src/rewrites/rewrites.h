#ifndef REWRITES_H
#define REWRITES_H

#include "str/str.h"
#include "list/list.h"


typedef struct url {
	str path;
	str query;
} url;

typedef struct rewrite {
	str pattern;
	url output;
} rewrite;


void read_url_rewrites(str file);
void free_url_rewrites(void);

int check_pattern(str text, str pattern, str tokens[9]);
str fill_blueprint(str bp, str tokens[9]);
url url_rewrite(str url, rewrite rwt);
url url_check(str url);

void print_url_rewrites(void);

#endif