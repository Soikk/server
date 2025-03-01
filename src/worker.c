#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include "str/str.h"
#include "ipc/ipc.h"
#include "net/net.h"


ipc_listener *listener;
http_worker *worker;
str rewritesfile;


int init(char *argv[]){
	// replace signals with unix sockets
	// reinit
	// finish
	// toggle ssl

	str saddr = dstr(argv[1]);
	listener = setup_ipc_listener(saddr);
	free_str(&saddr);
	if(listener == NULL){
		log_error("cant set up ipc listener on worker %d", getpid());
		return 1;
	}

	// check key for value maybe idk
	ipc_message msg = receive_ipc_message(listener);
	int ssocket = strtou(msg.val);
	free_ipc_message(msg);	// v configurable certificate locations?
	worker = setup_http_worker(ssocket, 1, sstr("ssl/mkarchive.net/certificate.crt"), sstr("ssl/mkarchive.net/private.key"));
	if(worker == NULL){
		log_error("setting up http worker");
		return 1;
	}
	// this is disgusting and should be done elsewhere
	msg = receive_ipc_message(listener); // check for value
	rewritesfile = dup_str(msg.val);
	free_ipc_message(msg);
	int fsize = get_file_size(rewritesfile.ptr);
	int fd = open(rewritesfile.ptr, O_RDONLY | O_NONBLOCK);
	char *rewrites = mmap(NULL, fsize, PROT_READ, MAP_SHARED, fd, 0);
	if(rewrites == (void*)-1){
		log_error("cant mmap rewrites: %s", strerror(errno));
		return 1;
	}
	if(read_uri_rewrites(rewrites, fsize) != 0){
		log_error("init: read_uri_rewrites: %s", strerror(errno));
		return 1;
	}
	munmap(rewritesfile.ptr, fsize);

	return 0;
}

void deinit(void){
	destroy_ipc_listener(&listener);
	destroy_http_worker(&worker);
	free_str(&rewritesfile);
	free_uri_rewrites();
}


int main(int argc, char **argv){

	int return_value = 0;

	if(init(argv) != 0){
		return_value = 1;
		goto DEINIT;
	}
	log_info("init'd");

	bool end = false;
	str request = {.cap = 8192, .len = 0, .ptr = alloca(8192)};
	while(!end){
		char cip[INET_ADDRSTRLEN] = {0};
		return_value = accept_connection(worker, cip);
		switch(return_value){
			case -1: // couldnt accept, do something ig
				continue;
			case SSL_ERROR_SSL:
				reset_worker_ssl(worker);
				log_info("continuing\n");
				continue;
		}
		log_info("socket %d accepted with ip %s", worker->csocket, cip);
		return_value = receive_request(worker, &request);
		switch(return_value){
			case -1: // couldnt accept, do something ig
				continue;
			case SSL_ERROR_SSL:
				reset_worker_ssl(worker);
				log_info("continuing\n");
				continue;
		}

		printf("'%.*s'\n", request.len, request.ptr);

		struct http_message hm = {0};
		build_http_message(request.ptr, request.len, &hm);
		log_info("uri before: %.*s", hm.uri.len, hm.uri.ptr);
		struct uri suri = sanitize_uri(hm.uri);
		log_info("uri after: %.*s", suri.path.len, suri.path.ptr);
		enum http_method method = get_http_method(hm.method);

		switch(method){
			case GET:
				struct file resource = generate_resource(suri, hm.uri);
				send_file(worker, resource.name);
				//if(resource.temp == true) remove(resource.name.ptr);
				free_str(&resource.name);
				break;
			case POST:
				//handlePOST(request);
				send(worker->csocket, "HTTP/1.1 201 Created\r\n\r\n", len("HTTP/1.1 201 Created\r\n\r\n"), 0);
				break;
			case PUT:
				break;
			case DELETE:
				break;		
		}
		free_str(&suri.path);
		free_str(&suri.query);
		request.len = 0;

		SSL_clear(worker->ssl);
		close(worker->csocket);

		//SSL_shutdown(config.ssl); // look into SSL_clear()
	}

DEINIT:
	log_info("dieing :(");
	deinit();

	return return_value;
}

/*
struct timespec t_start, t_end;

#define start_timing() clock_gettime(CLOCK_MONOTONIC, &t_start)
#define end_timing() clock_gettime(CLOCK_MONOTONIC, &t_end)

double get_timing(void){
	uint64_t diff = (t_end.tv_sec*1000000000 + t_end.tv_nsec) - (t_start.tv_sec*1000000000 + t_start.tv_nsec);
	return diff/1000000000.0;
}
*/
