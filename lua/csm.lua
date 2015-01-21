--[[
/**
 *       @file  csm.lua
 *      @brief  Lua module for Commotion Service Manager
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
]]--

-- because Lua 5.1 doesn't have __next, __pairs, __ipairs metamethods
rawnext = next
function next(t,k)
  local m = getmetatable(t)
  local n = m and m.__next or rawnext
  return n(t,k)
end
function pairs(t) return next, t, nil end

csm_lua = package.loadlib("/usr/lib/libcsm_lua.so","luaopen_csm")
csm_lua()