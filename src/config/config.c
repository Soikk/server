#include "config.h"


static void read_logs(str logs){
	int off = 0;
	while(off < logs.len){
		while(off < logs.len && charisspace(logs.ptr[off])) off++;
		if(logs.ptr[off] == '#'){
			while(off < logs.len && !charislinebreak(logs.ptr[off])) off++;
			continue;
		}
		int level;
		str slevel = sread_delim_f(logs.ptr + off, charisspace, true);
		off += slevel.len;
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
			while(off < logs.len && !charislinebreak(logs.ptr[off])) off++;
			continue;
		}
		if(log_get_files(level) >= MAX_LOGFILES){
			log_warn("Cannot add any more files to logging level %.*s", slevel.len, slevel.ptr);
			while(off < logs.len && !charislinebreak(logs.ptr[off])) off++;
			continue;
		}
		while(off < logs.len && charisspace(logs.ptr[off])) off++;
		str file = read_delim_f(logs.ptr + off, charisspace, true);
		off += file.len;
		while(off < logs.len && charisspace(logs.ptr[off])) off++;
		str mode = read_delim_f(logs.ptr + off, charisspace, true);
		off += mode.len;
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
		free_str(&file);
		free_str(&mode);
		while(off < logs.len && !charislinebreak(logs.ptr[off])) off++;
	}
}

void rotate_logs(str logs){
	for(int i = 0; i < LOG_LEVEL_COUNT; i++){
		log_remove_fps(i);
		log_set_stderr(i, 1);
	}
	read_logs(logs);
}

config_m master_config(char *filename){
	config_m conf = {0};
	conf.file = map_file(filename);
	int off = 0;
	while(off < conf.file.len){
		while(off < conf.file.len && charisspace(conf.file.ptr[off])) off++;
		if(conf.file.ptr[off] == '#'){
			while(off < conf.file.len && !charislinebreak(conf.file.ptr[off])) off++;
			continue;
		}
		str key = sread_delim_f(conf.file.ptr + off, charisspace, true);
		off += key.len;
		while(off < conf.file.len && charisspace(conf.file.ptr[off]) && !charislinebreak(conf.file.ptr[off])) off++;

		if(streq(key, sstr("name"))){
			conf.name = sread_delim_f(conf.file.ptr + off, charisspace, true);
			off += conf.name.len;
		}else if(streq(key, sstr("port"))){
			str val = sread_delim_f(conf.file.ptr + off, charisspace, true);
			off += val.len;
			conf.port = (int)strtou(val);
		}else if(streq(key, sstr("backlog"))){
			str val = sread_delim_f(conf.file.ptr + off, charisspace, true);
			off += val.len;
			conf.backlog = (int)strtou(val);
		}else if(streq(key, sstr("logs"))){
			str val = sread_delim_f(conf.file.ptr + off, charisspace, true);
			off += val.len;
			str logs;
			if(val.ptr[0] != '{'){
				str logfile = dup_str(val);
				logs = file_to_str(logfile.ptr);
				free_str(&logfile);
			}else{
				logs = read_delim(conf.file.ptr + off, '}');
				off += logs.len;
			}
			rotate_logs(logs);
			free_str(&logs);
		}else if(streq(key, sstr("worker"))){
			int bcount = 1;
			while(off < conf.file.len && bcount > 0){
				if(conf.file.ptr[off] == '{') bcount++;
				if(conf.file.ptr[off] == '}') bcount--;
				off++;
			}
		}else if(key.len != 0){
			log_warn("Unexpected entry in configuration: '%.*s'", key.len, key.ptr);
		}
		while(off < conf.file.len && !charislinebreak(conf.file.ptr[off])) off++;
		off++;
	};

	return conf;
}

config_w worker_config(char *filename){
	config_w conf = {0};
	conf.file = map_file(filename);
	init_nlist(conf.files);
	int off = 0;
	while(off < conf.file.len){
		while(off < conf.file.len && charisspace(conf.file.ptr[off])) off++;
		if(conf.file.ptr[off] == '#'){
			while(off < conf.file.len && !charislinebreak(conf.file.ptr[off])) off++;
			continue;
		}
		str key = sread_delim_f(conf.file.ptr + off, charisspace, true);
		off += key.len;
		while(off < conf.file.len && charisspace(conf.file.ptr[off]) && !charislinebreak(conf.file.ptr[off])) off++;

		if(streq(key, sstr("name"))){
			conf.name = sread_delim_f(conf.file.ptr + off, charisspace, true);
			off += conf.name.len;
		}else if(streq(key, sstr("root"))){
			str val = sread_delim_f(conf.file.ptr + off, charisspace, true);
			off += val.len;
			str trailslash = val.ptr[val.len-1] == '/' ? sstr("") : sstr("/");
			conf.root = dup_strs(val, trailslash);
		}else if(streq(key, sstr("bundle"))){
			conf.bundle = sread_delim_f(conf.file.ptr + off, charisspace, true);
			off += conf.bundle.len;
		}else if(streq(key, sstr("cert"))){
			conf.cert = sread_delim_f(conf.file.ptr + off, charisspace, true);
			off += conf.cert.len;
		}else if(streq(key, sstr("key"))){
			conf.key = sread_delim_f(conf.file.ptr + off, charisspace, true);
			off += conf.key.len;
		}else if(streq(key, sstr("https"))){
			conf.secure = 1;
		}else if(streq(key, sstr("http"))){
			conf.secure = 0;
		}else if(streq(key, sstr("ipv4"))){
			conf.ipv4 = 1;
		}else if(streq(key, sstr("ipv6"))){
			conf.ipv6 = 1;
		}else if(streq(key, sstr("types"))){
			str val = sread_delim_f(conf.file.ptr + off, charisspace, true);
			off += val.len;
			str types;
			if(val.ptr[0] != '{'){
				str typesfile = dup_str(val);
				types = map_file(typesfile.ptr);
				list_push(conf.files, types);
				free_str(&typesfile);
			}else{
				types = sread_delim(conf.file.ptr + off, '}');
				off += types.len;
			}
			read_mime_types(types);
		}else if(streq(key, sstr("logs"))){
			str val = sread_delim_f(conf.file.ptr + off, charisspace, true);
			off += val.len;
			str logs;
			if(val.ptr[0] != '{'){
				str logfile = dup_str(val);
				logs = file_to_str(logfile.ptr);
				free_str(&logfile);
			}else{
				logs = read_delim(conf.file.ptr + off, '}');
				off += logs.len;
			}
			rotate_logs(logs);
			free_str(&logs);
		}
		while(off < conf.file.len && !charislinebreak(conf.file.ptr[off])) off++;
		off++;
	};

	return conf;
}

void free_master_config(config_m *conf){
	conf->name = (str){0};
	conf->port = 0;
	conf->backlog = 0;
	unmap_file(&conf->file);
}

void free_worker_config(config_w *conf){
	conf->name = (str){0};
	conf->root = (str){0};
	conf->bundle = (str){0};
	conf->cert = (str){0};
	conf->key = (str){0};
	conf->secure = 0;
	conf->ipv4 = 0;
	conf->ipv6 = 0;
	free_mime_types();
	for(int i = 0; i < list_size(conf->files); i++){
		unmap_file(&conf->files[i]);
	}
	list_free(conf->files);
	unmap_file(&conf->file);
}

void print_master_config(config_m conf){
	printf(
		"MASTER CONFIGURATION:\n"
		"\t- name:    %.*s\n"
		"\t- port:    %d\n"
		"\t- backlog: %d\n"
		"\t- logs:   {\n",
		conf.name.len, conf.name.ptr,
		conf.port,
		conf.backlog
	);
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

void print_worker_config(config_w conf){
	printf(
		"WORKER CONFIGURATION:\n"
		"\t- name:    %.*s\n"
		"\t- root:    %.*s\n"
		"\t- bundle:  %.*s\n"
		"\t- cert:    %.*s\n"
		"\t- key:     %.*s\n"
		"\t- secure:  %s\n"
		"\t- ipv4:    %s\n"
		"\t- ipv6:    %s\n",
		conf.name.len, conf.name.ptr,
		conf.root.len, conf.root.ptr,
		conf.bundle.len, conf.bundle.ptr,
		conf.cert.len, conf.cert.ptr,
		conf.key.len, conf.key.ptr,
		conf.secure ? "yes" : "no",
		conf.ipv4 ? "yes" : "no",
		conf.ipv6 ? "yes" : "no"
	);
	print_mime_types();
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

