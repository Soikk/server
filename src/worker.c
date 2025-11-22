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
	str socket_path;
	str ipc_addr;
	str config_file;
	str self;
} dir;
ipc_listener *listener;
http_worker *worker;

// remove these or something
int secure = 0;
str rewritesfile;


// TODO: remove?
// make int for errors?
void handle_message(ipc_msg im){
	log_debug("received message: [%d] (%d) %s", im.type, im.msg.len, im.msg.ptr);
	switch(im.type){
		case NONE: break;
		case SOCKET:
			// if(worker != NULL){
			// 	destroy_http_worker(&worker);
			// }
			// int ssocket = strtou(im.msg);
			// worker = setup_http_worker(ssocket, secure, certfile, keyfile);
			// fds[1] = (struct pollfd){ .fd = worker->ssocket, .events = POLLIN };
			break;
		case REWRITES:
			//int fsize = get_file_size(im.msg.ptr);
			//int fd = open(im.msg.ptr, O_RDONLY | O_NONBLOCK);
			//char *rewrites = mmap(NULL, fsize, PROT_READ, MAP_SHARED, fd, 0);
			//if(rewrites == (void*)-1){
			//	log_error("cant mmap rewrites: %s", strerror(errno));
			//	return;
			//}
			//if(read_uri_rewrites(rewrites, fsize) != 0){
			//	log_error("init: read_uri_rewrites: %s", strerror(errno));
			//	return;
			//}
			//munmap(rewritesfile.ptr, fsize);
			//close(fd);
			break;
		//case ROOT:
		//	free_str(&rootdir);
		//	rootdir = dup_str(im.msg);
		//	break;
		case BUNDLE:	// look into reinitializing the worker when receiving this
			// free_str(&bundlefile);
			// bundlefile = dup_str(im.msg);
			// break;
		case CERT:	// look into reinitializing the worker when receiving this
			// free_str(&certfile);
			// certfile = dup_str(im.msg);
			// break;
		case KEY:	// look into reinitializing the worker when receiving this
			// free_str(&keyfile);
			// keyfile = dup_str(im.msg);
			// break;
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
			// TODO: revise this
			// log_info("received http signal");
			// if(secure != 0){
			// 	secure = 0;
			// 	terminate_https(worker);
			// }
			break;
		case HTTPS:
			// TODO: revise this
			// log_info("received https signal");
			// if(secure == 0){
			// 	secure = 1;
			// 	setup_https(worker, certfile, keyfile);
			// }
			break;
		case LOG:
			break;
		case UNLOG:
			break;
		default:
			break;
	}
}

void deinit(void);

void quit(int sig, siginfo_t *info, void *ucontext){
	log_info("Terminating due to SIG%s (%s)", sigabbrev_np(sig), sigdescr_np(sig));
	deinit();
	exit(0);
}

// possibly change name
int read_server_dir(str name){
	dir.path = dup_strs(sstr("/var/run/"), name, sstr("/"));
	if(!dir_exists(dir.path.ptr)){
		log_error("No server directory in '%.*s'", dir.path.len, dir.path.ptr);
		return 1;
	}
	dir.socket_path = dup_strs(dir.path, sstr("socket"));
	if(!file_exists(dir.socket_path.ptr)){
		log_error("No socket file in '%.*s'", dir.socket_path.len, dir.socket_path.ptr);
		return 1;
	}
	dir.ipc_addr = dup_strs(dir.path, sstr("ipcserver"));
	if(!file_exists(dir.ipc_addr.ptr)){
		log_error("No IPC socket in '%.*s'", dir.ipc_addr.len, dir.ipc_addr.ptr);
		return 1;
	}
	dir.config_file = dup_strs(dir.path, sstr("configfile"));
	if(!file_exists(dir.config_file.ptr)){
		log_error("No config file in '%.*s'", dir.config_file.len, dir.config_file.ptr);
		return 1;
	}
	// TODO: revise this
	str pid = utostr(getpid(), 10);
	dir.self = dup_strs(dir.path, sstr("workers/"), pid);
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

int init(str name){
	if(read_server_dir(name) != 0){
		log_error("Error reading server directory");
		return 1;
	}
	config = worker_config(dir.config_file.ptr);
	if(config.file.ptr == NULL){
		log_error("Unable to read config from '%.*s'", dir.config_file.len, dir.config_file.ptr);
		return 1;
	}
	//print_worker_config(config);
	// TODO: remove "successful" messages or add them all	
	log_info("Succesfully read worker config from '%.*s'", dir.config_file.len, dir.config_file.ptr);
	int ssocket;
	int sfd = open(dir.socket_path.ptr, O_RDONLY);
	read(sfd, &ssocket, sizeof(int));
	close(sfd);
	worker = setup_http_worker(ssocket, secure, config.cert, config.key);
	if(worker == NULL){
		log_error("Error setting up worker server");
		return 1;
	}
	listener = setup_ipc_listener(dir.ipc_addr);
	if(listener == NULL){
		log_error("Can't set up ipc listener on self");
		return 1;
	}
	struct sigaction qit = { .sa_sigaction = quit, .sa_flags = SA_SIGINFO };
	if(sigaction(SIGTERM, &qit, NULL) == -1){
		log_error("Error setting up SIGTERM signal handler: %s", strerror(errno));
		return 1;
	}
	if(sigaction(SIGQUIT, &qit, NULL) == -1){
		log_error("Error setting up SIGQUIT signal handler: %s", strerror(errno));
		return 1;
	}
	if(sigaction(SIGINT, &qit, NULL) == -1){
		log_error("Error setting up SIGINT signal handler: %s", strerror(errno));
		return 1;
	}
	return 0;
}

// possibly change name
void remove_server_dir(void){
	if(remove(dir.self.ptr) != 0){
		log_error("Error removing PID record for self in '%.*s': %s", dir.self.len, dir.self.ptr, strerror(errno));
	}
	free_str(&dir.self);
	free_str(&dir.ipc_addr);
	free_str(&dir.path);
}

void deinit(void){
	destroy_ipc_listener(&listener);
	destroy_http_worker(&worker);
	free_worker_config(&config);
	remove_server_dir();
}

void print_usage(void){
	printf("worker [server name]\n");
}


int main(int argc, char **argv){

	if(argc < 2){
		print_usage();
		return 1;
	}

	int return_value = 0;

	if(init(dsstr(argv[1])) != 0){
		return_value = 1;
		goto DEINIT;
	}
	log_info("init'd");

	//bool end = false;
	str request = {.cap = 8192, .len = 0, .ptr = alloca(8192)};

	while(1){
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
		log_debug("received %d from receive_request", return_value);
		switch(return_value){
			case -1: // couldnt accept, do something ig
				goto finish_request;
				break;
			case SSL_ERROR_SSL:
				reset_https(worker);
				log_info("continuing\n");
				continue;
		}

		printf("%d: '%.*s'\n", request.len, request.len, request.ptr);

		struct http_message hm = {0};
		build_http_message(request.ptr, request.len, &hm);
		log_info("url before: %.*s", hm.url.len, hm.url.ptr);
		url surl = sanitize_url(hm.url);
		log_info("uri after: '%.*s' ? '%.*s'", surl.path.len, surl.path.ptr, surl.query.len, surl.query.ptr);
		enum http_method method = get_http_method(hm.method);

		switch(method){
			case GET:
				str resource = generate_resource(surl, hm.url);
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

finish_request:
		free_str(&surl.path);
		free_str(&surl.query);
		log_debug("query freed");
		request.len = 0;

		if(worker->secure){
			SSL_clear(worker->ssl);
		}
		close(worker->csocket);

		//SSL_shutdown(config.ssl); // look into SSL_clear()

		log_debug("end of loop");
	}

DEINIT:
	deinit();
	free_str(&rewritesfile);
	log_info("dieing :(");

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
