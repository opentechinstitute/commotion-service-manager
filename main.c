#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <avahi-common/error.h>

#include "commotion.h"

#include "commotion-service-manager.h"
#include "debug.h"

extern struct arguments arguments;
static int pid_filehandle;

extern AvahiSimplePoll *simple_poll;
extern AvahiServer *server;
co_obj_t *co_conn = NULL;

/** Parse commandline options */
static error_t parse_opt (int key, char *arg, struct argp_state *state) {
  struct arguments *arguments = state->input;
  
  switch (key) {
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
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
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

int main(int argc, char*argv[]) {
    AvahiServerConfig config;
    AvahiSServiceTypeBrowser *stb = NULL;
    int error;
    int ret = 1;

    argp_program_version = "1.0";
    static char doc[] = "Commotion Service Manager";
    static struct argp_option options[] = {
#ifdef USE_UCI
      {"uci", 'u', 0, 0, "Store service cache in UCI" },
#endif
      {"out", 'o', "FILE", 0, "Output file to write services to when USR1 signal is received" },
      {"nodaemon", 'n', 0, 0, "Do not fork into the background" },
      { 0 }
    };
    
    /* Set defaults */
#ifdef USE_UCI
    arguments.uci = 0;
#endif
    arguments.nodaemon = 0;
    arguments.output_file = DEFAULT_FILENAME;
    
    static struct argp argp = { options, parse_opt, NULL, doc };
    
    argp_parse (&argp, argc, argv, 0, 0, &arguments);
    //fprintf(stdout,"uci: %d, out: %s\n",arguments.uci,arguments.output_file);
    
    if (!arguments.nodaemon)
      daemon_start(PIDFILE);
    
    CHECK(co_init(),"Failed to initialize Commotion client");
    CHECK((co_conn = co_connect(CO_SOCK,sizeof(CO_SOCK))),"Failed to connect to Commotion socket");
    
    signal(SIGUSR1, sig_handler);

    /* Initialize the psuedo-RNG */
    srand(time(NULL));

    /* Allocate main loop object */
    CHECK((simple_poll = avahi_simple_poll_new()),"Failed to create simple poll object.");

    /* Do not publish any local records */
    avahi_server_config_init(&config);
    config.publish_hinfo = 0;
    config.publish_addresses = 0;
    config.publish_workstation = 0;
    config.publish_domain = 0;

    /* Set a unicast DNS server for wide area DNS-SD */
    avahi_address_parse("192.168.50.1", AVAHI_PROTO_UNSPEC, &config.wide_area_servers[0]);
    config.n_wide_area_servers = 1;
    config.enable_wide_area = 1;

    /* Allocate a new server */
    server = avahi_server_new(avahi_simple_poll_get(simple_poll), &config, NULL, NULL, &error);

    /* Free the configuration data */
    avahi_server_config_free(&config);

    /* Check wether creating the server object succeeded */
    CHECK(server,"Failed to create server: %s", avahi_strerror(error));

    /* Create the service browser */
    CHECK((stb = avahi_s_service_type_browser_new(server, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, "mesh.local", 0, browse_type_callback, server)),
        "Failed to create service browser: %s", avahi_strerror(avahi_server_errno(server)));
    
    /* Run the main loop */
    avahi_simple_poll_loop(simple_poll);
    
    ret = 0;

error:

    co_shutdown();

    /* Cleanup things */
    if (stb)
        avahi_s_service_type_browser_free(stb);

    if (server)
        avahi_server_free(server);

    if (simple_poll)
        avahi_simple_poll_free(simple_poll);

    return ret;
}