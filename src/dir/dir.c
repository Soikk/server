#include "dir.h"


uint64_t get_fd_size(int fd){
	struct stat st;
	if(fstat(fd, &st) == 0){
		return st.st_size;
	}
	return 0;
}

uint64_t get_fp_size(FILE *fp){
	if(fp != NULL){
		return get_fd_size(fileno(fp));
	}
	return 0;
}

uint64_t get_file_size(char *filename){
	struct stat st;
	if(stat(filename, &st) == 0){
		return st.st_size;
	}
	return 0;
}

struct str get_file_format(struct str filename){
	int i = 0;
	while(filename.len-i > 0){
		if(filename.ptr[filename.len-i-1] == '.') break;
		i++;
	}
	if(i == 0 || i == filename.len){
		return ((struct str){0});
	}
	struct str fmt;
	fmt.len = i;
	fmt.ptr = calloc(fmt.len+1, sizeof(char));
	if(fmt.ptr == NULL) return ((struct str){0});
	memcpy(fmt.ptr, filename.ptr+filename.len-i, fmt.len);
	return fmt;
}

uint64_t getNEntries(const char *dir){
	uint64_t r = 0;
	DIR *d = opendir(dir);
	if(d){
		seekdir(d, (unsigned)-1);
		r = telldir(d) - 2; // . and ..
		closedir(d);
	}
	return r;
}

char **getFiles(const char *dir){
	/*int i = 0, n = getNEntries(dir);
	if(n > 0){
		char **r = calloc(n, sizeof(char*));
		DIR *d = opendir(dir);
		readdir(d); readdir(d); // . and ..
		struct dirent *t;
		while((t = readdir(d)) != NULL){
			int l = len(t->d_name);
			r[i] = calloc(l+1, sizeof(char));
			memmove(r[i++], t->d_name, l);
		}
		closedir(d);
		return r;
	}*/
	return NULL;
}

