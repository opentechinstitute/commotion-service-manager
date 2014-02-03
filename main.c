#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>

#include <avahi-common/error.h>
#include <avahi-core/core.h>
#include <avahi-core/lookup.h>
#ifdef CLIENT
#include <avahi-client/client.h>
#include <avahi-client/lookup.h>
#endif

#include "commotion.h"

#include "commotion-service-manager.h"
#include "browse.h"
#include "debug.h"

struct arguments arguments;
static int pid_filehandle;

AvahiSimplePoll *simple_poll = NULL;
#ifndef CLIENT
AvahiServer *server = NULL;
#endif

/** Parse commandline options */
static error_t parse_opt (int key, char *arg, struct argp_state *state) {
  struct arguments *arguments = state->input;
  
  switch (key) {
    case 'b':
      arguments->co_sock = arg;
      break;
#ifdef USE_UCI
    case 'u':
      arguments->uci = 1;
      break;
#endif
    case 'o':
      arguments->output_file = arg;
      break;
    case 'n':
      arguments->nodaemon = 1;
      break;
    case 'p':
      arguments->pid_file = arg;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

static void shutdown(int signal) {
      DEBUG("Received %s, goodbye!", signal == SIGINT ? "SIGINT" : "SIGTERM");
      avahi_simple_poll_quit(simple_poll);
}

/**
 * Starts the daemon
 * @param pidfile name of lock file (stores process id)
 * @warning ensure that there is only one copy 
 * @note if compiled with Syslog support, sets up syslog logging log
 */
static void daemon_start(char *pidfile) {
  int pid, sid, i;
  char str[10];
  
  /*
   * Check if parent process id is set
   * 
   * If PPID exists, we are already a daemon
   */
  if (getppid() == 1) {
    return;
  }
  
  pid = fork(); /* Fork parent process */
  
  if (pid < 0) {
    exit(EXIT_FAILURE);
  }
  
  if (pid > 0) {
    /* Child created correctly */
    printf("Child process created: %d\n", pid);
    exit(EXIT_SUCCESS); /* exit parent process */
  }
  
  /* Child continues from here */
  
  /* 
   * Set file permissions to 750 
   * -- Owner may read/write/execute
   * -- Group may read/write
   * -- World has no permissions
   */
  umask(027);
  
#ifdef USESYSLOG
  openlog("Commotion",LOG_PID,LOG_USER); 
#endif
  
  /* Get a new process group */
  sid = setsid();
  
  if (sid < 0) {
    exit(EXIT_FAILURE);
  }
  
  /* Close all descriptors */
  for (i = getdtablesize(); i >=0; --i) {
    close(i);
  }
  
  /* Route i/o connections */
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
  
  if ((chdir("/")) < 0) {
    exit(EXIT_FAILURE);
  }
  
  /*
   * Open lock file
   * Ensure that there is only one copy
   */
  pid_filehandle = open(pidfile, O_RDWR|O_CREAT, 0644);
  
  if(pid_filehandle == -1) {
    /* Couldn't open lock file */
    ERROR("Could not lock PID lock file %s, exiting", pidfile);
    exit(EXIT_FAILURE);
  }
  
  /* Get and format PID */
  sprintf(str, "%d\n", getpid());
  
  /* Write PID to lockfile */
  write(pid_filehandle, str, strlen(str));
  
}

#ifdef CLIENT
static void client_callback(AvahiClient *c, AvahiClientState state, AVAHI_GCC_UNUSED void * userdata) {
    assert(c);

    /* Called whenever the client or server state changes */

    if (state == AVAHI_CLIENT_FAILURE) {
        ERROR("Server connection failure: %s", avahi_strerror(avahi_client_errno(c)));
        avahi_simple_poll_quit(simple_poll);
    }
}
#endif

int main(int argc, char*argv[]) {
#ifdef CLIENT
    AvahiClient *client = NULL;
#else
    AvahiServerConfig config;
#endif
    TYPE_BROWSER *stb = NULL;
    int error;
    int ret = 1;

    argp_program_version = "1.0";
    static char doc[] = "Commotion Service Manager";
    static struct argp_option options[] = {
      {"bind", 'b', "URI", 0, "commotiond management socket"},
      {"nodaemon", 'n', 0, 0, "Do not fork into the background" },
      {"out", 'o', "FILE", 0, "Output file to write services to when USR1 signal is received" },
      {"pid", 'p', "FILE", 0, "Specify PID file"},
#ifdef USE_UCI
      {"uci", 'u', 0, 0, "Store service cache in UCI" },
#endif
      { 0 }
    };
    
    /* Set defaults */
    arguments.co_sock = DEFAULT_CO_SOCK;
#ifdef USE_UCI
    arguments.uci = 0;
#endif
    arguments.nodaemon = 0;
    arguments.output_file = DEFAULT_FILENAME;
    arguments.pid_file = PIDFILE;
    
    static struct argp argp = { options, parse_opt, NULL, doc };
    
    argp_parse (&argp, argc, argv, 0, 0, &arguments);
    //fprintf(stdout,"uci: %d, out: %s\n",arguments.uci,arguments.output_file);
    
    if (!arguments.nodaemon)
      daemon_start(arguments.pid_file);
    
    CHECK(co_init(),"Failed to initialize Commotion client");
    
    struct sigaction sa = {{0}};
    sa.sa_handler = print_services;
    CHECK(sigaction(SIGUSR1,&sa,NULL) == 0, "Failed to set signal handler");
    sa.sa_handler = shutdown;
    CHECK(sigaction(SIGINT,&sa,NULL) == 0, "Failed to set signal handler");
    CHECK(sigaction(SIGTERM,&sa,NULL) == 0, "Failed to set signal handler");

    /* Initialize the psuedo-RNG */
    srand(time(NULL));

    /* Allocate main loop object */
    CHECK((simple_poll = avahi_simple_poll_new()),"Failed to create simple poll object.");

#ifdef CLIENT
    /* Allocate a new client */
    client = avahi_client_new(avahi_simple_poll_get(simple_poll), 0, client_callback, NULL, &error);
    CHECK(client,"Failed to create client: %s", avahi_strerror(error));
#else
    /* Do not publish any local records */
    avahi_server_config_init(&config);
    CHECK_MEM((config.host_name = calloc(HOST_NAME_MAX,sizeof(char))));
    CHECK(gethostname(config.host_name,HOST_NAME_MAX) == 0, "Failed to fetch hostname");
    config.publish_workstation = 0;

    /* Allocate a new server */
    server = avahi_server_new(avahi_simple_poll_get(simple_poll), &config, NULL, NULL, &error);

    /* Free the configuration data */
    avahi_server_config_free(&config);

    /* Check wether creating the server object succeeded */
    CHECK(server,"Failed to create server: %s", avahi_strerror(error));
#endif

    /* Create the service browser */
    CHECK((stb = TYPE_BROWSER_NEW(AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, "mesh.local", 0, browse_type_callback)),
        "Failed to create service browser: %s", AVAHI_ERROR);
    
    /* Run the main loop */
    avahi_simple_poll_loop(simple_poll);
    
    ret = 0;

error:

    co_shutdown();

    /* Cleanup things */
    if (stb)
        TYPE_BROWSER_FREE(stb);

    FREE_AVAHI();

    if (simple_poll)
        avahi_simple_poll_free(simple_poll);

    return ret;
}