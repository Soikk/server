#include "mime.h"


// look into making this a BST or something more efficient
static mime_type *types;

void add_mime_type(mime_type mt){
	list_push(types, mt);
}

void read_mime_types(str file){
	if(types == NULL){
		init_nlist(types);
	}
	int off = 0;
	while(off < file.len){
		while(off < file.len && charisspace(file.ptr[off])) off++;
		if(file.ptr[off] == '#'){
			while(off < file.len && !charislinebreak(file.ptr[off])) off++;
			continue;
		}
		mime_type mt;
		mt.desc = sread_delim_f(file.ptr + off, charisspace, true);
		off += mt.desc.len;
		while(off < file.len && charisspace(file.ptr[off])) off++;
		mt.ext = sread_delim_f(file.ptr + off, charisspace, true);
		off += mt.ext.len;
		while(off < file.len && !charislinebreak(file.ptr[off])) off++;
		if(mt.desc.len == 0 || mt.ext.len == 0){
			continue;
		}
		add_mime_type(mt);
	}
}

str get_mime_type(str ext){
	int size = list_size(types);
	for(int i = 0; i < size; i++){
		if(streq(types[i].ext, ext)){
			return types[i].desc;
		}
	}
	return (str){0};
}

void free_mime_types(void){
	list_free(types);
}

void print_mime_types(void){
	int size = list_size(types);
	printf("\t- types:   {\n");
	for(int i = 0; i < size; i++){
		printf("\t\t%.*s\t%.*s\n",
			types[i].desc.len, types[i].desc.ptr, types[i].ext.len, types[i].ext.ptr);
	}
	printf("\t}\n");
}

