/**
 *       @file  debug.h
 *      @brief  debug macros for the Commotion Service Manager
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

#ifndef __DEBUG_H__
#define __DEBUG_H__

#include <stdio.h>
#include <errno.h>
#include <string.h>

#ifdef USESYSLOG
#include <syslog.h>
#define LOG(M, ...) syslog(M, ##__VA_ARGS__)
#else
#define LOG(M, N, ...) fprintf(stderr, "["M"] " N, ##__VA_ARGS__)
#define LOG_INFO "LOG_INFO"
#define LOG_WARNING "LOG_WARNING"
#define LOG_ERR "LOG_ERR"
#define LOG_DEBUG "LOG_DEBUG"
#endif

#if defined(NDEBUG)
#define DEBUG(M, ...)
#else
#define DEBUG(M, ...) LOG(LOG_DEBUG, "(%s:%d) " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#endif

#define CLEAN_ERRNO() (errno == 0 ? "None" : strerror(errno))

#define ERROR(M, ...) LOG(LOG_ERR, "(%s:%d: errno: %s) " M "\n", __FILE__, __LINE__, CLEAN_ERRNO(), ##__VA_ARGS__)

#define WARN(M, ...) LOG(LOG_WARNING, "(%s:%d: errno: %s) " M "\n", __FILE__, __LINE__, CLEAN_ERRNO(), ##__VA_ARGS__)

#define INFO(M, ...) LOG(LOG_INFO, "(%s:%d) " M "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#define CHECK(A, M, ...) ({ if(!(A)) { ERROR(M, ##__VA_ARGS__); errno=0; goto error; } })

#define SENTINEL(M, ...)  { ERROR(M, ##__VA_ARGS__); errno=0; goto error; }

#define CHECK_MEM(A) CHECK((A), "Out of memory.")

#define CHECK_DEBUG(A, M, ...) ({ if(!(A)) { DEBUG(M, ##__VA_ARGS__); errno=0; goto error; } })

#endif
