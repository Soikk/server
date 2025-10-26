#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include "str/str.h"
#include "ipc/ipc.h"
#include "net/net.h"
#include "config/config.h"


config_w config;
struct {
	str path;
	str ipc_addr;
	str self;
} dir;
ipc_listener *listener;
http_worker *worker;

// remove these or something
int secure;
str rewritesfile;
str rootdir;
str bundlefile;
str certfile;
str keyfile;
struct pollfd fds[2] = {0};


// make int for errors?
void handle_message(ipc_msg im){
	log_debug("received message: [%d] (%d) %s", im.type, im.msg.len, im.msg.ptr);
	switch(im.type){
		case NONE: break;
		case SOCKET:
			if(worker != NULL){
				destroy_http_worker(&worker);
			}
			int ssocket = strtou(im.msg);
			worker = setup_http_worker(ssocket, secure, certfile, keyfile);
			fds[1] = (struct pollfd){ .fd = worker->ssocket, .events = POLLIN };
			break;
		case REWRITES:
			int fsize = get_file_size(im.msg.ptr);
			int fd = open(im.msg.ptr, O_RDONLY | O_NONBLOCK);
			char *rewrites = mmap(NULL, fsize, PROT_READ, MAP_SHARED, fd, 0);
			if(rewrites == (void*)-1){
				log_error("cant mmap rewrites: %s", strerror(errno));
				return;
			}
			if(read_uri_rewrites(rewrites, fsize) != 0){
				log_error("init: read_uri_rewrites: %s", strerror(errno));
				return;
			}
			munmap(rewritesfile.ptr, fsize);
			close(fd);
			break;
		//case ROOT:
		//	free_str(&rootdir);
		//	rootdir = dup_str(im.msg);
		//	break;
		case BUNDLE:	// look into reinitializing the worker when receiving this
			free_str(&bundlefile);
			bundlefile = dup_str(im.msg);
			break;
		case CERT:	// look into reinitializing the worker when receiving this
			free_str(&certfile);
			certfile = dup_str(im.msg);
			break;
		case KEY:	// look into reinitializing the worker when receiving this
			free_str(&keyfile);
			keyfile = dup_str(im.msg);
			break;
		case RESTART:
			char *args[] = {"./worker.exe", listener->saddr.ptr, NULL};
			execv("./worker.exe", args);
			log_error("Cannot restart worker: %s", strerror(errno));
			return;
			break;
		case RELOAD:
			// re-reads config
			// re-requests entire config;
			break;
		case HTTP:
			log_info("received http signal");
			if(secure != 0){
				secure = 0;
				terminate_https(worker);
			}
			break;
		case HTTPS:
			log_info("received https signal");
			if(secure == 0){
				secure = 1;
				setup_https(worker, certfile, keyfile);
			}
			break;
		case LOG:
			break;
		case UNLOG:
			break;
		default:
			break;
	}
}

// possibly change name

int create_server_dir(str name){
	dir.path = dup_strs(sstr("/var/run/"), name, sstr("/"));
	if(!dir_exists(dir.path.ptr)){
		log_error("No server directory in '%.*s': %s", dir.path.len, dir.path.ptr);
		return 1;
	}
	dir.ipc_addr = dup_strs(dir.path, sstr("ipcserver"));
	str pid = utostr(getpid(), 10);
	dir.self = dup_strs(dir.path, sstr("workers/"), pid);
	printf("WE'RE GONNA CREATE THE FILE %s\n", dir.self.ptr);
	free_str(&pid);
	if(file_exists(dir.self.ptr)){
		log_error("Error creating PID record for self in '%.*s': it already exists", dir.self.len, dir.self.ptr);
		return 1;
	}
	if(creat(dir.self.ptr, 0777) == -1){
		log_error("Error creating PID record for self in '%.*s': %s", dir.self.len, dir.self.ptr, strerror(errno));
		return 1;
	}
	return 0;
}

int init(char *configfile){
	config = worker_config(configfile);
	if(config.name.len == 0){ // TODO: maybe check for this someway else
		log_error("Unable to read config from '%s'", configfile);
		return 1;
	}
	print_worker_config(config);
	log_info("Succesfully read worker config from '%s'", configfile);
	if(create_server_dir(config.name) != 0){
		return 1;
	}
	return 0;
}

// possibly change name
void remove_server_dir(void){
	if(remove(dir.self.ptr) != 0){
		log_error("Error removing PID record for self in '%.*s': %s", dir.self.len, dir.self.ptr, strerror(errno));
	}
	printf("%s IS NO MORE!", dir.self.ptr);
	free_str(&dir.self);
	free_str(&dir.ipc_addr);
	free_str(&dir.path);
}

void deinit(void){
	free_worker_config(&config);
	remove_server_dir();
}


int main(int argc, char **argv){

	int return_value = 0;

	init("config.example");

	listener = setup_ipc_listener((str){.cap = 0, .len = len(argv[1]), .ptr = argv[1]});
	if(listener == NULL){
		log_error("Can't set up ipc listener on worker %d", getpid());
		return_value = 1;
		goto DEINIT;
	}
	log_info("init'd");

	//bool end = false;
	log_debug("erm");
	str request = {.cap = 8192, .len = 0, .ptr = alloca(8192)};

	fds[0] = (struct pollfd){ .fd = listener->csocket, .events = POLLIN };

	int r;
	while((r = poll(fds, 2, 0)) != -1){
		if(r > 0){
			log_info("[%d] %d\t-\t%d", fds[1].fd, fds[1].events & POLLIN, fds[1].revents & POLLIN);
		}
		if(fds[0].revents & POLLHUP){
			log_info("RECEIVED POLLHUP!!!!!!");
			// end? or something idk
		}else if(fds[0].revents & POLLIN){
			ipc_msg msg = receive_ipc_message(listener);
			handle_message(msg);
			free_ipc_message(&msg);
			continue;
		}else if(fds[1].revents & POLLIN){
			log_info("ermmm");
			char cip[INET_ADDRSTRLEN] = {0};
			return_value = accept_connection(worker, cip);
			switch(return_value){
				case -1: // couldnt accept, do something ig
					continue;
				case SSL_ERROR_SSL:
					reset_https(worker);
					log_info("continuing\n");
					continue;
			}
			log_info("socket %d accepted with ip %s", worker->csocket, cip);
			return_value = receive_request(worker, &request);
			switch(return_value){
				case -1: // couldnt accept, do something ig
					continue;
				case SSL_ERROR_SSL:
					reset_https(worker);
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
					str resource = generate_resource(suri, hm.uri);
					send_file(worker, resource);
					//if(resource.temp == true) remove(resource.name.ptr);
					free_str(&resource);
					break;
				case POST:
					//handlePOST(request);
					send(worker->csocket, "HTTP/1.1 201 Created\r\n\r\n", len("HTTP/1.1 201 Created\r\n\r\n"), 0);
					break;
				case PUT:
					break;
				case DELETE:
					break;
				default:
					break;
			}
			free_str(&suri.path);
			free_str(&suri.query);
			log_debug("query freed");
			request.len = 0;

			if(worker->secure){
				SSL_clear(worker->ssl);
			}
			close(worker->csocket);

			//SSL_shutdown(config.ssl); // look into SSL_clear()

			log_debug("end of loop");
		}else if(fds[1].revents & POLLHUP){
			// like restart the worker
		}
	}

DEINIT:
	deinit();
	log_info("dieing :(");
	destroy_ipc_listener(&listener);
	destroy_http_worker(&worker);
	free_str(&rewritesfile);
	free_uri_rewrites();

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
