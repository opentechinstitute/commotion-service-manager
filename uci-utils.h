/**
 *       @file  uci-utils.h
 *      @brief  UCI integration for the Commotion Service Manager
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