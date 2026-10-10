local uuid = require("kong.tools.uuid").uuid
local Handler = { PRIORITY = 100002, VERSION = "1.0.0" }
local identity_headers = {
  "X-Authenticated-Client", "X-Authenticated-Subject", "X-Authenticated-Email",
  "X-Tenant-ID", "X-Consumer-ID", "X-Consumer-Username", "X-Credential-Identifier",
  "X-Anonymous-Consumer", "X-Codestra-Tenant", "X-Codestra-Scopes",
  "X-User-ID", "X-Username", "X-Email", "X-Roles", "X-Scopes",
  "X-Authenticated-UserID", "X-Authenticated-User", "X-Authenticated-Tenant",
  "X-Authenticated-Campaign", "X-Authenticated-Role", "X-Codestra-Gateway-Secret",
  "X-Internal-Service", "X-Admin", "X-Codestra-Contract-Operation",
  "X-Codestra-Expected-Azp", "X-Codestra-Required-Scope"
}
local function safe_id(value)
  return type(value) == "string" and #value >= 1 and #value <= 128
    and value:match("^[A-Za-z0-9][A-Za-z0-9._:-]*$") ~= nil
end
-- Every X-Codestra-* header is gateway-minted; none may arrive from a client,
-- including names this release does not know yet.
local function strip_codestra_namespace()
  for name in pairs(kong.request.get_headers(1000) or {}) do
    if type(name) == "string" and name:lower():sub(1, 11) == "x-codestra-" then
      kong.service.request.clear_header(name)
    end
  end
end
-- W3C trace-context tracestate: at most 32 list members and 512 characters.
local function valid_tracestate(value)
  if type(value) ~= "string" or #value > 512 then return false end
  local members = 0
  for member in (value .. ","):gmatch("([^,]*),") do
    member = member:match("^[ \t]*(.-)[ \t]*$")
    if member ~= "" then
      members = members + 1
      local key, item = member:match("^([^=]+)=(.+)$")
      if members > 32 or not key or #key > 256 or #item > 256
        or not key:match("^[a-z0-9][a-z0-9_%-%*/@]*$")
        or item:find("[^\32-\43\45-\60\62-\126]") or item:sub(-1) == " " then
        return false
      end
    end
  end
  return members > 0
end
function Handler:access(conf)
  if conf.not_after and ngx.time() >= conf.not_after then
    return kong.response.exit(403, { error = "legacy_credential_sunset_reached" })
  end
  local tenant = kong.request.get_header("X-Tenant-ID")
  if tenant and not safe_id(tenant) then
    return kong.response.exit(400, { error = "invalid_tenant_selector" })
  end
  kong.ctx.shared.codestra_requested_tenant = tenant
  for _, name in ipairs(identity_headers) do kong.service.request.clear_header(name) end
  strip_codestra_namespace()
  local correlation = kong.request.get_header("X-Correlation-ID")
  if not correlation then
    if conf.require_correlation_id and kong.request.get_method() ~= "OPTIONS" then
      return kong.response.exit(400, { error = "correlation_id_required" })
    end
    correlation = uuid()
  end
  if not safe_id(correlation) then
    return kong.response.exit(400, { error = "invalid_correlation_id" })
  end
  kong.ctx.plugin.correlation_id = correlation
  kong.service.request.set_header("X-Correlation-ID", correlation)
  local request_id = kong.request.get_header("X-Request-ID") or correlation
  if not safe_id(request_id) then
    return kong.response.exit(400, { error = "invalid_request_id" })
  end
  kong.ctx.plugin.request_id = request_id
  kong.service.request.set_header("X-Request-ID", request_id)
  local trace = kong.request.get_header("traceparent")
  if trace then
    if type(trace) ~= "string" then
      return kong.response.exit(400, { error = "invalid_traceparent" })
    end
    local version, trace_id, parent_id, flags = trace:match("^(%x%x)%-(%x+)%-(%x+)%-(%x%x)$")
    if version ~= "00" or #trace ~= 55 or #trace_id ~= 32 or #parent_id ~= 16
      or trace_id == string.rep("0", 32) or parent_id == string.rep("0", 16)
      or trace ~= trace:lower() or (flags ~= "00" and flags ~= "01") then
      return kong.response.exit(400, { error = "invalid_traceparent" })
    end
    local state = kong.request.get_header("tracestate")
    if state ~= nil and not valid_tracestate(state) then
      kong.service.request.clear_header("tracestate")
    end
  else
    -- A fresh trace has no vendor state; a client tracestate cannot ride on it.
    kong.service.request.clear_header("tracestate")
    local trace_id = uuid():gsub("-", "")
    local parent_id = uuid():gsub("-", ""):sub(1, 16)
    kong.service.request.set_header("traceparent", "00-" .. trace_id .. "-" .. parent_id .. "-00")
  end
end
function Handler:header_filter()
  local correlation = kong.ctx.plugin.correlation_id
  if correlation then kong.response.set_header("X-Correlation-ID", correlation) end
  if kong.ctx.plugin.request_id then kong.response.set_header("X-Request-ID", kong.ctx.plugin.request_id) end
  kong.response.set_header("X-Content-Type-Options", "nosniff")
  kong.response.set_header("Referrer-Policy", "no-referrer")
  kong.response.set_header("Strict-Transport-Security", "max-age=31536000")
end
return Handler
