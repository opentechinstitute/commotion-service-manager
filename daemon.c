/**
 *       @file  daemon.c
 *      @brief  Entry point and commands for CSM daemon
 *
 *     @author  Dan Staples (dismantl), danstaples@opentechinstitute.org
 *
 * This file is part of Commotion, Copyright (c) 2013, Josh King 
 * 
 * Commotion is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published 
 * by the Free Software Foundation, either version 3 of the License, 
 * or (at your option) any later version.
 * 
 * Commotion is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Commotion.  If not, see <http://www.gnu.org/licenses/>.
 *
 * =====================================================================================
 */

#include <argp.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <time.h>
#include <sys/socket.h>

#include <avahi-common/error.h>
#include <avahi-common/malloc.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/alternative.h>

#include <commotion/debug.h>
#include <commotion/cmd.h>
#include <commotion/msg.h>
#include <commotion/list.h>
#include <commotion/tree.h>
#include <commotion/socket.h>
#include <commotion/util.h>
#include <commotion/profile.h>
#include <commotion.h>

#include "defs.h"
#include "util.h"
#include "service.h"
#include "service_list.h"
#include "browse.h"
#include "publish.h"
#include "schema.h"
#include "cmd.h"
#if USE_UCI
#include "uci-utils.h"
#endif
#include "commotion-service-manager.h"

#define REQUEST_MAX 1024
#define RESPONSE_MAX 1024

extern co_socket_t unix_socket_proto;

struct csm_config csm_config;
static int pid_filehandle;
static co_socket_t *csm_socket = NULL;

AvahiSimplePoll *simple_poll = NULL;
co_obj_t *service_proto = NULL;

#if 0
#define SCHEMA_ADD(K, V) co_tree_insert(self, K, sizeof(K), co_str8_create(V, sizeof(V), 0))

SCHEMA(service_proto)
{
  co_obj_t *first = co_tree16_create();
  co_tree_insert(first, "second", sizeof("second"), co_str8_create("foo",sizeof("foo"),0));
  CHECK_MEM(first);
  co_tree_insert(self, "first", sizeof("first"), first);
  return 1;
error:
  return 0;
}
#endif

static void socket_send(int fd, char const *str, size_t len) {
  unsigned int sent = 0;
  unsigned int remaining = len;
  int n;
  while(sent < len) {
    n = send(fd, str+sent, remaining, 0);
    if (n < 0) break;
    sent += n;
    remaining -= n;
  }
  DEBUG("Sent %d bytes.", sent);
}

static void request_handler(AvahiWatch *w, int fd, AvahiWatchEvent events, void *userdata) {
  assert(userdata);
  csm_ctx *ctx = (csm_ctx*)userdata;
  
  char reqbuf[REQUEST_MAX], respbuf[RESPONSE_MAX];
  ssize_t reqlen = 0;
  size_t resplen = 0;
  co_obj_t *request = NULL, *ret = NULL, *nil = co_nil_create(0);
  uint8_t *type = NULL;
  uint32_t *id = NULL;
  
  memset(reqbuf, '\0', sizeof(reqbuf));
  memset(respbuf, '\0', sizeof(respbuf));
  
  if (events & AVAHI_WATCH_HUP) {
    close(fd);
    avahi_simple_poll_get(simple_poll)->watch_free(w);
    DEBUG("HUP from %d",fd);
    return;
  }
  
  INFO("Received connection from %d", fd);
  if (csm_socket->fd->fd == fd) {
    int rfd;
    DEBUG("Accepting connection (fd=%d).", fd);
    CHECK((rfd = accept(fd, NULL, NULL)) != -1, "Failed to accept connection.");
    DEBUG("Accepted connection (fd=%d).", rfd);
    co_obj_t *new_rfd = co_fd_create((co_obj_t*)csm_socket,rfd);
    CHECK(co_list_append(csm_socket->rfd_lst,new_rfd),"Failed to append rfd");
    int flags = fcntl(rfd, F_GETFL, 0);
    fcntl(rfd, F_SETFL, flags | O_NONBLOCK); //Set non-blocking.
    avahi_simple_poll_get(simple_poll)->watch_new(avahi_simple_poll_get(simple_poll), 
						  rfd, 
						  AVAHI_WATCH_IN | AVAHI_WATCH_IN, 
						  request_handler, 
						  ctx);
    return;
  }
  reqlen = recv(fd,reqbuf,sizeof(reqbuf),0);
  DEBUG("Received %d bytes from %d", (int)reqlen,fd);
  if (reqlen < 0) {
    INFO("Connection recvd() -1");
    close(fd);
    avahi_simple_poll_get(simple_poll)->watch_free(w);
    return;
  }
  
  /* If it's a commotion message type, parse the header, target and payload */
  CHECK(co_list_import(&request, reqbuf, reqlen) > 0, "Failed to import request.");
  co_obj_data((char **)&type, co_list_element(request, 0));
  CHECK(*type == 0, "Not a valid request.");
  CHECK(co_obj_data((char **)&id, co_list_element(request, 1)) == sizeof(uint32_t), "Not a valid request ID.");
  
  /* Run command */
  // prepend CSM context to command paramaters, in order to send it to command handlers
  co_obj_t *params = co_list_element(request, 3);
  co_obj_t *ctx_obj = co_ctx_create(ctx);
  CHECK_MEM(ctx_obj);
  CHECK(co_list_prepend(params, ctx_obj), "Failed to prepend ctx to command params");
  if(co_cmd_exec(co_list_element(request, 2), &ret, params)) {
    resplen = co_response_alloc(respbuf, sizeof(respbuf), *id, nil, ret);
    socket_send(fd,respbuf,resplen);
  } else {
    if(ret == NULL) {
      ret = co_tree16_create();
      co_tree_insert(ret, "error", sizeof("error"), co_str8_create("Incorrect command.", sizeof("Incorrect command."), 0));
    }
    resplen = co_response_alloc(respbuf, sizeof(respbuf), *id, ret, nil);
    socket_send(fd,respbuf,resplen);
  }
  
error:
  if (request) co_obj_free(request);
}

static void csm_shutdown(int signal) {
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

static int
create_service_browser(csm_ctx *ctx)
{
#ifdef CLIENT
  AvahiClient *client = ctx->client;
#else
  AvahiServer *server = ctx->server;
#endif
  
  /* Create the service browser */
  CHECK((ctx->stb = TYPE_BROWSER_NEW(AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, "mesh.local", 0, browse_type_callback, ctx)),
	"Failed to create service browser: %s", AVAHI_ERROR);
  return 1;
error:
  return 0;
}

#ifdef CLIENT
static void client_callback(AvahiClient *c, AvahiClientState state, void *userdata) {
    assert(userdata);
    csm_ctx *ctx = (csm_ctx*)userdata;
    assert(c);
    ctx->client = c;

    /* Called whenever the client or server state changes */
    switch (state) {
      case AVAHI_CLIENT_S_RUNNING:
	INFO("CSM client started successfully, publishing services");
	/* The server has startup successfully and registered its host
	 * name on the network, so it's time to create our services */
	if (!ctx->stb) {
	  if (!create_service_browser(ctx)) {
	    ERROR("Failed to create service type browser");
	    avahi_simple_poll_quit(simple_poll);
	  }
	}
	csm_publish_all(ctx);
	break;
      case AVAHI_CLIENT_CONNECTING:
	/* Avahi daemon is not currently running */
	// make sure nothing registers apps during this state
	// see: avahi-commotion/defs.h
	sleep(1);
	break;
      case AVAHI_CLIENT_S_COLLISION:
	/* Let's drop our registered services. When the server is back
	 * in AVAHI_CLIENT_S_RUNNING state we will register them
	 * again with the new host name. */
	
	/* drop through */
      case AVAHI_CLIENT_S_REGISTERING:
	/* The server records are now being established. This
	 * might be caused by a host name change. We need to wait
	 * for our own records to register until the host name is
	 * properly esatblished. */
	csm_unpublish_all(ctx);
	break;
      case AVAHI_CLIENT_FAILURE:
	if (avahi_client_errno(c) == AVAHI_ERR_DISCONNECTED) {
	  /* Remove all local services */
	  csm_unpublish_all(ctx);
	  
	  /* Free service type browser */
	  if (ctx->stb)
	    TYPE_BROWSER_FREE(ctx->stb);
	  
	  /* Free client */
	  FREE_AVAHI(ctx);
	  
	  /* Create new client */
	  int error;
	  ctx->client = avahi_client_new(avahi_simple_poll_get(simple_poll), AVAHI_CLIENT_NO_FAIL, client_callback, ctx, &error);
	  if (!ctx->client) {
	    ERROR("Failed to create client: %s", avahi_strerror(error));
	    avahi_simple_poll_quit(simple_poll);
	  }
	} else {
	  ERROR("Server connection failure: %s", avahi_strerror(avahi_client_errno(c)));
	  avahi_simple_poll_quit(simple_poll);
	}
	break;
      default:
	;
    }
}
#else
static void server_callback(AvahiServer *s, AvahiServerState state, AVAHI_GCC_UNUSED void * userdata) {
  assert(userdata);
  csm_ctx *ctx = (csm_ctx*)userdata;
  assert(s);

  /* Called whenever the server state changes */
  switch (state) {
    case AVAHI_SERVER_RUNNING:
      INFO("CSM server started successfully, publishing services");
      /* The serve has startup successfully and registered its host
       * name on the network, so it's time to create our services */
      csm_publish_all(ctx);
      break;
    case AVAHI_SERVER_COLLISION: {
      /* A host name collision happened. Let's pick a new name for the server */
      char *new_host_name = avahi_alternative_host_name(avahi_server_get_host_name(s));
      ERROR("Host name collision, retrying with '%s'", new_host_name);
      int r = avahi_server_set_host_name(s, new_host_name);
      avahi_free(new_host_name);
      if (r < 0) {
	ERROR("Failed to set new host name: %s", avahi_strerror(r));
	avahi_simple_poll_quit(simple_poll);
	return;
      }
    }
      /* Fall through */
    case AVAHI_SERVER_REGISTERING:
      /* Let's drop our registered services. When the server is back
       * in AVAHI_SERVER_RUNNING state we will register them
       * again with the new host name. */
      csm_unpublish_all(ctx);
      break;
    case AVAHI_SERVER_FAILURE:
      /* Terminate on failure */
      ERROR("Server failure: %s", avahi_strerror(avahi_server_errno(s)));
      avahi_simple_poll_quit(simple_poll);
      break;
    default:
      ;
  }
}
#endif

/** Parse commandline options */
static error_t parse_opt (int key, char *arg, struct argp_state *state) {
  switch (key) {
    case 'b':
      csm_config.co_sock = arg;
      break;
#ifdef USE_UCI
    case 'u':
      csm_config.uci = 1;
      break;
#endif
    case 'n':
      csm_config.nodaemon = 1;
      break;
    case 'p':
      csm_config.pid_file = arg;
      break;
    case 's':
      csm_config.schema_dir = arg;
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }
  return 0;
}

int main(int argc, char*argv[]) {
    csm_ctx ctx = {0};
    ctx.service_list = csm_services_init();
//     ctx.schema = csm_schema_new();
#ifndef CLIENT
    AvahiServerConfig avahi_config;
#endif
    int error;
    int ret = 1;

    argp_program_version = "1.0";
    static char doc[] = "Commotion Service Manager";
    static struct argp_option options[] = {
      {"bind", 'b', "URI", 0, "commotiond management socket"},
      {"nodaemon", 'n', 0, 0, "Do not fork into the background" },
      {"schema", 's', "DIR", 0, "Directory including schema files for service announcements" },
      {"pid", 'p', "FILE", 0, "Specify PID file"},
#ifdef USE_UCI
      {"uci", 'u', 0, 0, "Store service cache in UCI" },
#endif
      { 0 }
    };
    static struct argp argp = { options, parse_opt, NULL, doc };
    
    /* Set defaults */
    csm_config.co_sock = COMMOTION_MANAGESOCK;
#ifdef USE_UCI
    csm_config.uci = 0;
#endif
    csm_config.nodaemon = 0;
    csm_config.pid_file = CSM_PIDFILE;
    csm_config.schema_dir = CSM_SCHEMA_DIR;
    
    /* Set Avahi allocator to use halloc */
#if 0
    static AvahiAllocator hallocator = {
      .malloc = h_malloc,
      .free = h_free,
      .realloc = h_realloc,
      .calloc = h_calloc
    };
    avahi_set_allocator(&hallocator);
#endif
    
    argp_parse (&argp, argc, argv, 0, 0, &csm_config);
    
    if (!csm_config.nodaemon)
      daemon_start(csm_config.pid_file);
    
    /* Initialize socket pool for connecting to commotiond */
    CHECK(co_init(),"Failed to initialize Commotion client");
    
    // parse service announcement schema
    CHECK(csm_import_schemas(&ctx, csm_config.schema_dir), "Failed to import service schema");
    
    /* Register signal handlers */
    struct sigaction sa = {{0}};
    sa.sa_handler = csm_shutdown;
    CHECK(sigaction(SIGINT,&sa,NULL) == 0, "Failed to set signal handler");
    CHECK(sigaction(SIGTERM,&sa,NULL) == 0, "Failed to set signal handler");

    /* Initialize the psuedo-RNG */
    srand(time(NULL));

    /* Allocate main loop object */
    CHECK((simple_poll = avahi_simple_poll_new()),"Failed to create simple poll object.");
    
#ifdef USE_UCI
    // read in list of local services from UCI
    if (csm_config.uci) {
      struct timeval tv = {}; // timeout is zeroed so callback is called as soon as Avahi even loop is started
      avahi_simple_poll_get(simple_poll)->timeout_new(avahi_simple_poll_get(simple_poll),
						      &tv,
						      uci_read,
						      &ctx);
    }
#endif

#ifdef CLIENT
    /* Allocate a new client */
    ctx.client = avahi_client_new(avahi_simple_poll_get(simple_poll), AVAHI_CLIENT_NO_FAIL, client_callback, &ctx, &error);
    CHECK(ctx.client,"Failed to create client: %s", avahi_strerror(error));
#else
    /* Do not publish any local records */
    avahi_server_config_init(&avahi_config);
    CHECK_MEM((avahi_config.host_name = calloc(HOST_NAME_MAX,sizeof(char))));
    CHECK(gethostname(avahi_config.host_name,HOST_NAME_MAX) == 0, "Failed to fetch hostname");
    avahi_config.publish_workstation = 0;
    avahi_config.publish_hinfo = 0;
    avahi_config.publish_domain = 0;
    avahi_config.n_wide_area_servers = 0;
    avahi_config.enable_wide_area = 0;
    avahi_config.enable_reflector = 0;
    avahi_config.reflect_ipv = 0;

    /* Allocate a new server */
    ctx.server = avahi_server_new(avahi_simple_poll_get(simple_poll), &avahi_config, server_callback, &ctx, &error);

    /* Free the configuration data */
    avahi_server_config_free(&avahi_config);

    /* Check wether creating the server object succeeded */
    CHECK(ctx.server,"Failed to create server: %s", avahi_strerror(error));
    
    CHECK(create_service_browser(&ctx),"Failed to create service type browser");
#endif
    
    /*TODO*/
    /* Register commands */
    co_cmds_init(16);
    CMD_REGISTER(help, "help <none>", "Print list of commands and usage information.");
    CMD_REGISTER(commit_service, "commit_service ........", "Add or update local service.");
    CMD_REGISTER(remove_service, "remove_service <key>", "Remove local service.");
    CMD_REGISTER(list_services, "list_services <none>", "List services on local Commotion network.");
    
    /* Set up CSM management socket */
    csm_socket = (co_socket_t*)NEW(co_socket, unix_socket);
    csm_socket->bind((co_obj_t*)csm_socket, CSM_MANAGESOCK);
    AvahiWatch *csm_watch = avahi_simple_poll_get(simple_poll)->watch_new(avahi_simple_poll_get(simple_poll),
									  csm_socket->fd->fd, 
									  AVAHI_WATCH_IN | AVAHI_WATCH_HUP, 
									  request_handler, 
									  &ctx);
    
#if USE_UCI
    if (csm_config.uci)
      CHECK(csm_services_register_commit_hook(ctx.service_list, uci_service_updater),
	    "Failed to add UCI commit handler");
#endif
    
    /* Run the main loop */
    avahi_simple_poll_loop(simple_poll);
    
    ret = 0;

error:

    /* Close commotiond socket connection */
    co_shutdown();
    
    if (csm_socket)
      csm_socket->destroy((co_obj_t*)csm_socket);
    
    co_cmds_shutdown();
    
    /* Cleanup things */
    if (ctx.stb)
        TYPE_BROWSER_FREE(ctx.stb);

    /* Free server/client */
    csm_ctx *ctx_ptr = &ctx;
    FREE_AVAHI(ctx_ptr);
    
    /* Destroy services */
    csm_services_destroy(ctx.service_list);
    
    csm_destroy_schemas(&ctx);

    /* Free event loop */
    if (simple_poll) {
      /* Remove main socket watch */
      avahi_simple_poll_get(simple_poll)->watch_free(csm_watch);
      avahi_simple_poll_free(simple_poll);
    }
    
    return ret;
}