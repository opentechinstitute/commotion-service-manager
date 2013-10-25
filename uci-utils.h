#ifndef UCI_UTILS_H
#define UCI_UTILS_H

#include "commotion-service-manager.h"

#ifndef UCIPATH
#define UCIPATH "/etc/config"
#endif

/**
 * Derives the UCI-encoded name of a service, as a concatenation of IP address/URL and port
 * @param i ServiceInfo object of the service
 * @param[out] name_len Length of the UCI-encoded name
 * @return UCI-encoded name
 */
char *get_name(ServiceInfo *i, size_t *name_len);

/**
 * Remove a service from UCI
 * @param i ServiceInfo object of the service
 * @return 0=success, 1=fail
 */
int uci_remove(ServiceInfo *i);

/**
 * Write a service to UCI
 * @param i ServiceInfo object of the service
 * @return 0=success, 1=fail
 */
int uci_write(ServiceInfo *i);

#endif