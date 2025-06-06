#include "config.h"


config read_config(str cfg){
	config conf = {0};
	int off = 0;
	while(off < cfg.len){
		while(charisspace(cfg.ptr[off])) off++;
		if(cfg.ptr[off] == '#'){
			while(!charislinebreak(cfg.ptr[off])) off++;
			continue;
		}
		str key = sread_delim_f(cfg.ptr + off, charisspace, true);
		off += key.len + 1;
		while(charisspace(cfg.ptr[off])) off++;

		if(streq(key, sstr("port"))){
			str val = sread_delim_f(cfg.ptr + off, charisspace, true);
			off += val.len;
			conf.port = (int)strtou(val);
		}else if(streq(key, sstr("ipv4"))){
			conf.ipv4 = 1;
		}else if(streq(key, sstr("ipv6"))){
			conf.ipv6 = 1;
		}else if(streq(key, sstr("root"))){
			str val = sread_delim_f(cfg.ptr + off, charisspace, true);
			str trailslash = val.ptr[val.len-1] == '/' ? sstr("") : sstr("/");
			conf.root = dup_strs(val, trailslash);
			off += conf.root.len;
		}else{
			log_warn("Unexpected entry in configuration: '%.*s'", key.len, key.ptr);
		}
		while(!charislinebreak(cfg.ptr[off])) off++;
		off++;
	};

	printf(
		"CONFIGURATION:\n"
		"\t- port:    %d\n"
		"\t- secure:  %s\n"
		"\t- ipv4:    %s\n"
		"\t- ipv6:    %s\n"
		"\t- workers: %d\n"
		"\t- root:    %s\n",
		conf.port,
		conf.secure ? "yes" : "no",
		conf.ipv4 ? "yes" : "no",
		conf.ipv6 ? "yes" : "no",
		conf.workers,
		conf.root.ptr
	);

	return conf;
}
