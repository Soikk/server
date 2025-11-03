#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include "str/str.h"
#include "list/list.h"
#include "net/net.h"
#include "log/log.h"
#include "ipc/ipc.h"
#include "config/config.h"

#define IPC_BACKLOG 15

config_m config;
struct {
	str path;
	str sock_path;
	str sock_addr;
	str ipc_addr;
	str workers;
} dir;
http_server *server;
ipc_sender *sender;
struct worker {
	pid_t pid;
	int wsocket;
} *workers;


void worker_undertaker(int sig, siginfo_t *info, void *ucontext){
	if(sig == SIGCHLD && list_entry_exists(workers, info->si_pid)){
		list_remove_entry(workers, info->si_pid);
		log_warn("worker %d is dead. now workers size is %d", info->si_pid, list_size(workers));
	}
}

int create_server_dir(str name){
	dir.path = dup_strs(sstr("/var/run/"), name, sstr("/"));
	if(!dir_exists(dir.path.ptr)){
		if(mkdir(dir.path.ptr, 0777) != 0){
			log_error("Error creating server directory in '%.*s': %s", dir.path.len, dir.path.ptr, strerror(errno));
			return 1;
		}
	}
	dir.sock_path = dup_strs(dir.path, sstr("socket/"));
	log_info("creating sock path in %.*s", dir.sock_path.len, dir.sock_path.ptr);
	if(!dir_exists(dir.sock_path.ptr)){
	// TODO: else? how to reattach to socket? how to leave socket reattachable?
	// TODO: look at ptrace(2)
		if(mkdir(dir.sock_path.ptr, 0777) != 0){
			log_error("Error creating socket directory in '%.*s': %s", dir.sock_path.len, dir.sock_path.ptr, strerror(errno));
			return 1;
		}
	}
	str sssocket = utostr(server->ssocket, 10);
	dir.sock_addr = dup_strs(dir.sock_path, sssocket);
	free_str(&sssocket);
	log_info("creating sock in %.*s", dir.sock_addr.len, dir.sock_addr.ptr);
	if(creat(dir.sock_addr.ptr, 0777) == -1){
		log_error("Error creating socket file for server in '%.*s': %s", dir.sock_addr.len, dir.sock_addr.ptr, strerror(errno));
		return 1;
	}
	dir.ipc_addr = dup_strs(dir.path, sstr("ipcserver"));
	if(path_exists(dir.ipc_addr.ptr)){
		if(remove(dir.ipc_addr.ptr) != 0){
			log_error("Error removing existing IPC socket '%.*s': %s", dir.ipc_addr.len, dir.ipc_addr.ptr, strerror(errno));
			return 1;
		}
	}
	dir.workers = dup_strs(dir.path, sstr("workers/"));
	if(!dir_exists(dir.workers.ptr)){
		if(mkdir(dir.workers.ptr, 0777) != 0){
			log_error("Error creating workers directory in '%.*s': %s", dir.workers.len, dir.workers.ptr, strerror(errno));
			return 1;
		}
	}
	return 0;
}

int init(char *configfile){
	config = master_config(configfile);
	if(config.name.len == 0){ // TODO: maybe check for this someway else
		log_error("Unable to read config from '%s'", configfile);
		return 1;
	}
	print_master_config(config);
	log_info("Succesfully read master config from '%s'", configfile);
	// decouple so the whole net.c doesnt get linked?
	server = setup_http_server(config.port, config.backlog);
	if(server == NULL){
		log_error("Error setting up socket server");
		return 1;
	}
	if(create_server_dir(config.name) != 0){
		return 1;
	}
	// configurable name?
	sender = setup_ipc_sender(dir.ipc_addr, IPC_BACKLOG);
	if(sender == NULL){
		log_error("Error setting up IPC sender");
		return 1;
	}
	init_list(workers);
	struct sigaction chld = { .sa_sigaction = worker_undertaker, .sa_flags = SA_SIGINFO };
	if(sigaction(SIGCHLD, &chld, NULL) == -1){
		log_error("Error setting up SIGCHLD signal handler: %s", strerror(errno));
		return 1;
	}
	return 0;
}

void remove_server_dir(void){
	if(remove(dir.sock_addr.ptr) != 0){
		log_error("Error removing socket file in '%.*s': %s", dir.sock_addr.len, dir.sock_addr.ptr, strerror(errno));
	}
	if(remove(dir.sock_path.ptr) != 0){
		log_error("Error removing socket path in '%.*s': %s", dir.sock_path.len, dir.sock_path.ptr, strerror(errno));
	}
	// remove workers entries first
	if(remove(dir.workers.ptr) != 0){
		log_error("Error removing workers directory in '%.*s': %s", dir.workers.len, dir.workers.ptr, strerror(errno));
	}
	free_str(&dir.workers);
	if(remove(dir.ipc_addr.ptr) != 0){
		log_error("Error removing IPC socket '%.*s': %s", dir.ipc_addr.len, dir.ipc_addr.ptr, strerror(errno));
	}
	free_str(&dir.ipc_addr);
	if(remove(dir.path.ptr) != 0){
		log_error("Error removing server directory in '%.*s': %s", dir.path.len, dir.path.ptr, strerror(errno));
	}
	free_str(&dir.path);
}

void deinit(void){
	free_master_config(&config);
	remove_server_dir();
	destroy_http_server(&server);
	destroy_ipc_sender(&sender);
	list_free(workers);
}

void print_usage(void){
	printf("server [config]\n");
}

void show_commands(void){
	printf(
		"(case insensitive)\n"
		"f: fork\n"
		"s: signal\n"
		"l: list\n"
		"c: clear\n"
		"[0-9]: turn off ssl for worker\n"
		"h: help\n"
		"q: quit\n"
	);
}


int main(int argc, char *argv[]){

	if(argc < 2){
		print_usage();
		return 1;
	}

	int return_value = 0;

	if(init(argv[1]) != 0){
		return_value = 1;
		goto DEINIT;
	}
	log_debug("test");
	log_info("test");
	log_warn("test");
	log_error("test");

#ifdef SHOW_IP
	system("curl -s http://ipinfo.io/ip && echo");
#endif


/*
	sqlite3 *db = setupDatabase("src/db/db.db");
	if(db == NULL){
		fprintf(stderr, "error setting up database\n");
		return 1;
	}

	if(getNEntries("archive") != getCount(db, FILE_TABLE)){
		int n = getNEntries("archive");
		char **entries = getFiles("archive"); // getFiles deprecated btw
		for(int i = 0; i < n; ++i){
			insertName(db, FILE_TABLE, entries[i]);
		}
		printf("%d, %d\n", getNEntries("archive"), getCount(db, FILE_TABLE));
	}
*/

	// TODO: lookup shutdown() for sockets
	printf("press h for help\n");
	bool end = false;
	while(!end){
		char c = getchar();
		switch(c){
			case 'f': case 'F':
				pid_t nw = fork();
				if(nw == 0){
					char *args[] = {"./worker.exe", dir.ipc_addr.ptr, NULL};
					execv("./worker.exe", args);
					log_error("Cannot exec worker: %s", strerror(errno));
					return 1;
				}
				struct worker w = { .pid = nw, .wsocket = accept(sender->ssocket, NULL, NULL) };
				list_push(workers, w);
				send_ipc_message(w.wsocket, CERT, sstr("ssl/cert.pem"));
				send_ipc_message(w.wsocket, KEY, sstr("ssl/key.pem"));
				str ss = utostr(server->ssocket, 10);
				send_ipc_message(w.wsocket, SOCKET, ss);
				free_str(&ss);
				send_ipc_message(w.wsocket, REWRITES, sstr("urirewrites"));
				//send_ipc_message(w.wsocket, HTTPS, sstr(""));
				break;
			case 's':
				for(int i = 0; i < list_size(workers); i++){
					send_ipc_message(workers[i].wsocket, HTTPS, sstr(""));
				}
				break;
			case 'S':
				for(int i = 0; i < list_size(workers); i++){
					send_ipc_message(workers[i].wsocket, HTTP, sstr(""));
				}
				break;
			case 'R':
				for(int i = 0; i < list_size(workers); i++){
					send_ipc_message(workers[i].wsocket, RESTART, sstr(""));
				}
				break;
			case 'l': case 'L':
				printf("|-%3d workers working for us rn-|\n", list_size(workers));
				char *faces[] = {
					"(^__^)", "(·__·)", "(>__>)", "(~ _~)", "(T__T)", "(º__º)"
				};
				for(int i = 0; i < list_size(workers); i++){
					int index = rand()%sizeof(faces)/sizeof(faces[0]);
					printf("| %d %s\t\t\t|\n", workers[i].pid, faces[index]);
				}
				printf("|-------------------------------|\n");
				break;
			case 'c': case 'C':
				system("clear");
				break;
			case 'h': case 'H':
				show_commands();
				break;
			case 'q': case 'Q':
				while(list_size(workers) > 0){
					shutdown(workers[0].wsocket, SHUT_RDWR);
					//kill(workers[0].pid, SIGQUIT); // redo this PLEASE
					waitpid(workers[0].pid, NULL, 0);
				}
				while(wait(NULL) > 0);
				close(server->ssocket);
				end = true;
				log_info("%d children remaining alive (lie)", list_size(workers));
				break;
			case '0': case '1': case '2': case '3': case '4':
			case '5': case '6': case '7': case '8': case '9':
				if(list_size(workers) > c-'0'){
					log_info("signaling worker[%d] %d to turn off ssl", c-'0', workers[c-'0'].pid);
					sigqueue(workers[c-'0'].pid, SIGRTMIN, (union sigval){.sival_int = 0});
				}
				break;
		}
	}

DEINIT:
	deinit();
	log_info("Finished cleaning up");

	return return_value;
}

// inspiration: https://www.youtube.com/watch?v=cEH_ipqHbUw (https://github.com/infraredCoding/cerveur)
// thanks to
/*
	https://beej.us/guide/bgnet/
	https://dev.to/lloyds-digital/how-you-can-host-websites-from-home-4pke
	https://developer.mozilla.org/en-US/docs/Web/HTTP/Messages
	https://www.favicon.cc
	https://www.cssscript.com/demo/animated-snowfall-effect/
		https://www.cssscript.com/demo/animated-snowfall-effect/PureSnow.js
	https://www.tutorialspoint.com/http/http_requests.htm
	https://codepen.io/afarrar/pen/JRaEjP
*/

