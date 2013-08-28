#!/bin/sh
### BEGIN INIT INFO
# Provides:          commotion-service-manager
# Required-Start:    $network $local_fs $remote_fs
# Required-Stop:     $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: commotion-service-manager
# Description:       commotion-service-manager
### END INIT INFO

# Author: Dan Staples <danstaples@opentechinstitute.org>

PATH=/sbin:/usr/sbin:/bin:/usr/bin
DESC=commotion-service-manager             # Introduce a short description here
NAME=commotion-service-manager             # Introduce the short server's name here
DEFAULTFILE=/etc/default/$NAME
DAEMON=/usr/sbin/commotion-service-manager # Introduce the server's location here
PIDFILE=/var/run/commotion/$NAME.pid
SCRIPTNAME=/etc/init.d/$NAME
USER=commotion
START_DAEMON=yes
UCI_INSTANCE_PATH=/opt/luci-commotion/etc/config
OUTPUT_FILE=/tmp/local-services.out

# Exit if the package is not installed
[ -x $DAEMON ] || exit 0

# Read configuration variable file if it is present
[ -r $DEFAULTFILE ] && . $DEFAULTFILE

DAEMON_ARGS="-u -o $OUTPUT_FILE"             # Arguments to run the daemon with

# Define LSB log_* functions.
# Depend on lsb-base (>= 3.0-6) to ensure that this file is present.
. /lib/lsb/init-functions

if [ ! "$START_DAEMON" = "yes" -a "$1" = "start" ]; then
    log_warning_msg "Not starting $DESC, disabled via $DEFAULTFILE"
    exit 0
fi

if ! id $USER >/dev/null 2>&1; then
    log_failure_msg "Cannot start $DESC, user '$USER' does not exist"
    exit 1
fi

export UCI_INSTANCE_PATH

#
# Function that starts the daemon/service
#
do_start()
{
	# Return
	#   0 if daemon has been started
	#   1 if daemon was already running
	#   2 if daemon could not be started
	start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $DAEMON --chuid $USER --user $USER --test > /dev/null \
		|| return 1
	start-stop-daemon --start --quiet --pidfile $PIDFILE --exec $DAEMON --chuid $USER --user $USER -- \
		$DAEMON_ARGS \
		|| return 2
	# The above code will not work for interpreted scripts, use the next
	# six lines below instead (Ref: #643337, start-stop-daemon(8) )
	#start-stop-daemon --start --quiet --pidfile $PIDFILE --startas $DAEMON \
	#	--name $NAME --test > /dev/null \
	#	|| return 1
	#start-stop-daemon --start --quiet --pidfile $PIDFILE --startas $DAEMON \
	#	--name $NAME -- $DAEMON_ARGS \
	#	|| return 2

	# Add code here, if necessary, that waits for the process to be ready
	# to handle requests from services started subsequently which depend
	# on this one.  As a last resort, sleep for some time.
}

#
# Function that stops the daemon/service
#
do_stop()
{
	# Return
	#   0 if daemon has been stopped
	#   1 if daemon was already stopped
	#   2 if daemon could not be stopped
	#   other if a failure occurred
	start-stop-daemon --stop --quiet --retry=TERM/30/KILL/5 --pidfile $PIDFILE --chuid $USER --exec $DAEMON
	RETVAL="$?"
	[ "$RETVAL" = 2 ] && return 2
	# Wait for children to finish too if this is a daemon that forks
	# and if the daemon is only ever run from this initscript.
	# If the above conditions are not satisfied then add some other code
	# that waits for the process to drop all resources that could be
	# needed by services started subsequently.  A last resort is to
	# sleep for some time.
	start-stop-daemon --stop --quiet --oknodo --retry=0/30/KILL/5 --chuid $USER --exec $DAEMON
	[ "$?" = 2 ] && return 2
	# Many daemons don't delete their pidfiles when they exit.
	rm -f $PIDFILE
	return "$RETVAL"
}

#
# Function that sends a SIGHUP to the daemon/service
#
#do_reload() {
	#
	# If the daemon can reload its configuration without
	# restarting (for example, when it is sent a SIGHUP),
	# then implement that here.
	#
#	start-stop-daemon --stop --signal 1 --quiet --pidfile $PIDFILE --name $NAME
#	return 0
#}

case "$1" in
  start)
    [ "$VERBOSE" != no ] && log_daemon_msg "Starting $DESC " "$NAME"
    do_start
    case "$?" in
		0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
		2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
	esac
  ;;
  stop)
	[ "$VERBOSE" != no ] && log_daemon_msg "Stopping $DESC" "$NAME"
	do_stop
	case "$?" in
		0|1) [ "$VERBOSE" != no ] && log_end_msg 0 ;;
		2) [ "$VERBOSE" != no ] && log_end_msg 1 ;;
	esac
	;;
  status)
       status_of_proc "$DAEMON" "$NAME" && exit 0 || exit $?
       ;;
  #reload|force-reload)
	#
	# If do_reload() is not implemented then leave this commented out
	# and leave 'force-reload' as an alias for 'restart'.
	#
	#log_daemon_msg "Reloading $DESC" "$NAME"
	#do_reload
	#log_end_msg $?
	#;;
  restart|force-reload)
	#
	# If the "reload" option is implemented then remove the
	# 'force-reload' alias
	#
	log_daemon_msg "Restarting $DESC" "$NAME"
	do_stop
	case "$?" in
	  0|1)
		do_start
		case "$?" in
			0) log_end_msg 0 ;;
			1) log_end_msg 1 ;; # Old process is still running
			*) log_end_msg 1 ;; # Failed to start
		esac
		;;
	  *)
	  	# Failed to stop
		log_end_msg 1
		;;
	esac
	;;
  *)
	#echo "Usage: $SCRIPTNAME {start|stop|restart|reload|force-reload}" >&2
	echo "Usage: $SCRIPTNAME {start|stop|status|restart|force-reload}" >&2
	exit 3
	;;
esac

exit 0
