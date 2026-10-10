local text = { type = "string", len_min = 1, len_max = 256 }
local client = { type = "string", len_min = 1, len_max = 128, match = "^[A-Za-z0-9][A-Za-z0-9._:-]*$" }

-- token: the integration templates' full claim policy.
-- contract: a generated Middleware contract route; openid-connect has already
-- enforced issuer, audience and scope, so only the reviewed caller set and the
-- minted contract metadata remain. An empty allowed_azps closes the route.
local required_by_mode = {
  token = { "issuer", "audience", "authorized_parties", "scopes", "roles", "tenant_claim" },
  contract = { "operation_id", "expected_azp", "required_scope", "allowed_azps" },
}
local entity_checks = {}
for mode, fields in pairs(required_by_mode) do
  for _, field in ipairs(fields) do
    entity_checks[#entity_checks + 1] = { conditional = {
      if_field = "config.mode", if_match = { eq = mode },
      then_field = "config." .. field, then_match = { required = true },
    } }
  end
end

return { name = "codestra-authz", fields = {
  { config = { type = "record", fields = {
    { mode = { type = "string", required = true, default = "token", one_of = { "token", "contract" } } },
    { issuer = text }, { audience = text },
    { authorized_parties = { type = "array", len_min = 1, elements = text } },
    { scopes = { type = "array", len_min = 1, elements = text } },
    { roles = { type = "array", len_min = 1, elements = text } },
    { tenant_claim = { type = "string", one_of = { "tenant_id", "tenant", "org_id" } } },
    { operation_id = { type = "string", len_min = 1, len_max = 128, match = "^[a-z][a-z0-9_]*$" } },
    { expected_azp = { type = "string", len_min = 1, len_max = 1024 } },
    { required_scope = { type = "string", len_min = 1, len_max = 128, match = "^[A-Za-z0-9][A-Za-z0-9._:-]*$" } },
    { allowed_azps = { type = "array", elements = client } },
  } } }
}, entity_checks = entity_checks }
