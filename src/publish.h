/**
 *       @file  publish.h
 *      @brief  functionality for publishing and multicasting service announcements
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

#ifndef CSM_PUBLISH_H
#define CSM_PUBLISH_H

#include "defs.h"
#include "service.h"

int csm_publish_service(csm_service *service, csm_ctx *ctx);
int csm_unpublish_service(csm_service *service, csm_ctx *ctx);
int csm_publish_all(csm_ctx *ctx);
int csm_unpublish_all(csm_ctx *ctx);

#endif