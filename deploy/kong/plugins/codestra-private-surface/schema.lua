-- private_paths: contract private_only operation templates ({param} matches one
-- segment). They are unreachable through the public gateway whatever route matches.
local template = { type = "string", len_min = 2, len_max = 512, match = "^/[A-Za-z0-9._~{}/-]*$" }
return { name = "codestra-private-surface", fields = {
  { config = { type = "record", fields = {
    { allow_private = { type = "boolean", required = true, default = false } },
    { private_paths = { type = "array", required = true, default = {}, elements = template } }
  } } }
} }
