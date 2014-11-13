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