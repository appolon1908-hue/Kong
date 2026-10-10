return { name = "codestra-webhook-verifier", fields = {
  { config = { type = "record", fields = {
    { secret = { type = "string", required = true, referenceable = true, encrypted = true } },
    { key_id = { type = "string", required = true, len_min = 1, len_max = 63 } },
    -- The canonical route name is signed, so a signature cannot be replayed
    -- against another route that shares the key.
    { route_id = { type = "string", required = true, len_min = 1, len_max = 128,
                   match = "^[A-Za-z0-9][A-Za-z0-9._:-]*$" } },
    { allowed_methods = { type = "array", required = true, len_min = 1, default = { "POST" },
                          elements = { type = "string", one_of = { "POST", "PUT", "PATCH" } } } },
    { maximum_body_bytes = { type = "integer", required = true, between = {1, 1048576} } },
    { clock_skew_seconds = { type = "integer", required = true, between = {1, 300} } }
  } } }
} }
