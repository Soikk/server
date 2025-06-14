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

#define BACKLOG 15

config_m config;
str server_dir;
str ipc_addr;
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

int init(char *configfile){
	config = master_config(configfile);
	server_dir = dup_strs(sstr("/var/run/"), config.name, sstr("/"));
	if(!dir_exists(server_dir.ptr)){
		if(mkdir(server_dir.ptr, 0770) != 0){
			log_error("Error creating server directory in '%.*s': %s", server_dir.len, server_dir.ptr, strerror(errno));
			return 1;
		}
	}
	ipc_addr = dup_strs(server_dir, sstr("ipcserver"));
	if(path_exists(ipc_addr.ptr)){
		if(remove(ipc_addr.ptr) != 0){
			log_error("Error removing existing IPC socket '%.*s': %s", ipc_addr.len, ipc_addr.ptr, strerror(errno));
			return 1;
		}
	}
	// decouple so the whole net.c doesnt get linked?
	str port = utostr(config.port, 10);
	server = setup_http_server(port, BACKLOG);
	free_str(&port);
	if(server == NULL){
		log_error("Error setting up socket server");
		return 1;
	}
	// configurable name?
	sender = setup_ipc_sender(ipc_addr, BACKLOG);
	if(sender == NULL){
		log_error("Error setting up ipc sender");
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

void deinit(void){
	free_master_config(&config);
	// clean up server dir
	free_str(&server_dir);
	free_str(&ipc_addr);
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
	print_master_config(config);
	log_info("Config done");

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
					char *args[] = {"./worker.exe", ipc_addr.ptr, NULL};
					execv("./worker.exe", args);
					log_error("Cannot exec worker: %s", strerror(errno));
					return 1;
				}
				struct worker w = { .pid = nw, .wsocket = accept(sender->ssocket, NULL, NULL) };
				list_push(workers, w);
				send_ipc_message(w.wsocket, CERT, sstr("ssl/cert.pem"));
				send_ipc_message(w.wsocket, KEY, sstr("ssl/key.pem"));
				send_ipc_message(w.wsocket, SOCKET, utostr(server->ssocket, 10));
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
					kill(workers[0].pid, SIGKILL); // redo this PLEASE
					waitpid(workers[0].pid, NULL, 0);
				}
				while(wait(NULL) > 0);
				close(server->ssocket);
				end = true;
				log_info("%d children remaining alive (lie)\n", list_size(workers));
				break;
			case '0': case '1': case '2': case '3': case '4':
			case '5': case '6': case '7': case '8': case '9':
				if(list_size(workers) > c-'0'){
					log_info("signaling worker[%d] %d to turn off ssl\n", c-'0', workers[c-'0'].pid);
					sigqueue(workers[c-'0'].pid, SIGRTMIN, (union sigval){.sival_int = 0});
				}
				break;
		}
	}

DEINIT:
	deinit();

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

