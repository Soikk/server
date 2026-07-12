#include "config.h"


static inline void remove_blankspace(str file, int *i){
	while(*i < file.len && charisblank(file.ptr[*i])) (*i)++;
}

static inline void remove_whitespace(str file, int *i){
	while(*i < file.len && charisspace(file.ptr[*i])) (*i)++;
}

static inline void remove_line(str file, int *i){
	while(*i < file.len && !charislinebreak(file.ptr[(*i)++]));
}

static inline int remove_comment(str file, int *i){
	if(file.ptr[*i] == '#'){
		remove_line(file, i);
		return 1;
	}
	return 0;
}

static inline str read_string(str file, int *i){
	str s = sread_delim_f(file.ptr + *i, charisspace, true);
	*i += s.len;
	return s;
}

static inline str store_string(str file, int *i){
	str s = sread_delim_f(file.ptr + *i, charisspace, true);
	s.ptr[s.len] = '\0';
	*i += s.len;
	return s;
}

static inline int read_int(str file, int *i){
	str val = sread_delim_f(file.ptr + *i, charisspace, true);
	*i+= val.len;
	return strtou(val);
}

static inline str read_subconfig(config conf, int *i){
	str val = read_string(conf.file, i);
	str subconfig;
	if(val.ptr[0] == '{'){
		subconfig = sread_delim(conf.file.ptr + *i, '}');
		*i += subconfig.len;
	}else{
		str file = dup_str(val);
		subconfig = map_file(file.ptr);
		list_push(conf.files, subconfig);
		free_str(&file);
	}
	return subconfig;
}

static void read_logs(str logs){
	int off = 0;
	while(off < logs.len){
		remove_whitespace(logs, &off);
		if(remove_comment(logs, &off)) continue;
		int level = LOG_DEBUG;
		str slevel = read_string(logs, &off);
		if(streq(slevel, sstr("DEBUG"))){
			level = LOG_DEBUG;
		}else if(streq(slevel, sstr("INFO"))){
			level = LOG_INFO;
		}else if(streq(slevel, sstr("WARN"))){
			level = LOG_WARN;
		}else if(streq(slevel, sstr("ERROR"))){
			level = LOG_ERROR;
		}else{
			if(slevel.len != 0){
				log_warn("Unexpected logging level in 'log' configuration: '%.*s'", slevel.len, slevel.ptr);
			}
			remove_line(logs, &off);
			continue;
		}
		if(log_get_files(level) >= MAX_LOGFILES){
			log_warn("Cannot add any more files to logging level '%.*s'", slevel.len, slevel.ptr);
			remove_line(logs, &off);
			continue;
		}
		remove_blankspace(logs, &off);
		str file = read_string(logs, &off);
		remove_blankspace(logs, &off);
		str mode = read_string(logs, &off);
		if(streq(file, sstr("stderr"))){
			int set = strtou(mode);
			log_set_stderr(level, set);
		}else if(streq(mode, sstr("w")) || streq(mode, sstr("a"))){
			FILE *fp = fopen(file.ptr, mode.ptr);
			if(fp == NULL){
				log_warn("Error opening file '%.*s': %s", file.len, file.ptr, strerror(errno));
			}else{
				log_add_fp(level, fp);
			}
		}else{
			log_warn("Invalid read mode for logging file '%.*s': '%.*s'. Only 'w' or 'a' permitted",
				file.len, file.ptr, mode.len, mode.ptr);
		}
		remove_line(logs, &off);
	}
}

static void rotate_logs(str logs){
	for(int i = 0; i < LOG_LEVEL_COUNT; i++){
		log_remove_fps(i);
		log_set_stderr(i, 1);
	}
	read_logs(logs);
}

config read_config(char *filename){
	config conf = {0};
	conf.file = map_file(filename);
	if(conf.file.ptr == NULL){
		log_error("Unable to open config file '%s'", filename);
		return conf;
	}
	init_nlist(conf.files);
	int off = 0;
	while(off < conf.file.len){
		remove_whitespace(conf.file, &off);
		if(remove_comment(conf.file, &off)) continue;
		str key = read_string(conf.file, &off);
		remove_blankspace(conf.file, &off);

		if(streq(key, sstr("name"))){
			conf.name = store_string(conf.file, &off);
		}else if(streq(key, sstr("port"))){
			conf.port = store_string(conf.file, &off);
		}else if(streq(key, sstr("backlog"))){
			conf.backlog = read_int(conf.file, &off);
		}else if(streq(key, sstr("root"))){
			conf.root = store_string(conf.file, &off);
		}else if(streq(key, sstr("bundle"))){
			conf.bundle = store_string(conf.file, &off);
		}else if(streq(key, sstr("cert"))){
			conf.cert = store_string(conf.file, &off);
		}else if(streq(key, sstr("key"))){
			conf.key = store_string(conf.file, &off);
		}else if(streq(key, sstr("https"))){
			conf.secure = 1;
		}else if(streq(key, sstr("http"))){
			conf.secure = 0;
		}else if(streq(key, sstr("ipv4"))){
			conf.ipv4 = 1;
		}else if(streq(key, sstr("ipv6"))){
			conf.ipv6 = 1;
		}else if(streq(key, sstr("types"))){
			str types = read_subconfig(conf, &off);
			read_mime_types(types);
		}else if(streq(key, sstr("rewrites"))){
			str rewrites = read_subconfig(conf, &off);
			read_url_rewrites(rewrites);
		}else if(streq(key, sstr("logs"))){
			str logs = read_subconfig(conf, &off);
			rotate_logs(logs);
			logs = list_pop(conf.files);
			free_str(&logs);
		}
		remove_line(conf.file, &off);
	};

	return conf;
}

str get_key(str file, str key){
	int off = 0;
	while(off < file.len){
		remove_whitespace(file, &off);
		if(remove_comment(file, &off)) continue;
		str candidate = read_string(file, &off);
		remove_blankspace(file, &off);
		if(streq(key, candidate)){
			return read_string(file, &off);
		}
		remove_line(file, &off);
	}
	return (str){0};
}

void free_config(config *conf){
	conf->name = (str){0};
	conf->port = (str){0};
	conf->backlog = 0;
	conf->root = (str){0};
	conf->bundle = (str){0};
	conf->cert = (str){0};
	conf->key = (str){0};
	conf->secure = 0;
	conf->ipv4 = 0;
	conf->ipv6 = 0;
	free_mime_types();
	free_url_rewrites();
	for(int i = 0; i < list_size(conf->files); i++){
		unmap_file(&conf->files[i]);
	}
	list_free(conf->files);
	unmap_file(&conf->file);
}

void print_config(config conf){
	printf(
		"CONFIGURATION:\n"
		"\t- name:    %.*s\n"
		"\t- port:    %.*s\n"
		"\t- backlog: %d\n"
		"\t- root:    %.*s\n"
		"\t- bundle:  %.*s\n"
		"\t- cert:    %.*s\n"
		"\t- key:     %.*s\n"
		"\t- secure:  %s\n"
		"\t- ipv4:    %s\n"
		"\t- ipv6:    %s\n",
		conf.name.len, conf.name.ptr,
		conf.port.len, conf.name.ptr,
		conf.backlog,
		conf.root.len, conf.root.ptr,
		conf.bundle.len, conf.bundle.ptr,
		conf.cert.len, conf.cert.ptr,
		conf.key.len, conf.key.ptr,
		conf.secure ? "yes" : "no",
		conf.ipv4 ? "yes" : "no",
		conf.ipv6 ? "yes" : "no"
	);
	print_mime_types();
	print_url_rewrites();
	printf("\t- logs:    {\n");
	for(int i = 0; i < LOG_LEVEL_COUNT; i++){
		switch(i){
			case LOG_DEBUG: printf("\t\tDEBUG:\t"); break;
			case LOG_INFO: printf("\t\tINFO:\t"); break;
			case LOG_WARN: printf("\t\tWARN:\t"); break;
			case LOG_ERROR: printf("\t\tERROR:\t"); break;
		}
		printf("%d files%s\n", log_get_files(i), log_get_stderr(i) ? " + stderr" : "");
	}
	printf("\t}\n");
}
