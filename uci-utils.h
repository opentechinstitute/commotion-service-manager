#ifndef UCI_UTILS_H
#define UCI_UTILS_H

#include "commotion-service-manager.h"

#ifndef UCIPATH
#define UCIPATH "/etc/config"
#endif

char *get_name(ServiceInfo *i, size_t *name_len);
int uci_remove(ServiceInfo *i);
int uci_write(ServiceInfo *i);

#endif