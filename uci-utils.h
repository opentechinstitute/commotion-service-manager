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

/** 
 * Lookup a UCI section or option
 * @param c uci_context pointer
 * @param[out] sec_ptr uci_ptr struct to be populated by uci_lookup_ptr()
 * @param file UCI config name
 * @param file_len length of config name
 * @param sec UCI section name
 * @param sec_len length of section name
 * @param op UCI option name
 * @param op_len length of option name
 * @return -1 = fail, > 0 success/sec_ptr flags
 */
int get_uci_section(struct uci_context *c,
		    struct uci_ptr *sec_ptr,
		    const char *file, 
		    const size_t file_len,
		    const char *sec, 
		    const size_t sec_len,
		    const char *op,
		    const size_t op_len);

#endif