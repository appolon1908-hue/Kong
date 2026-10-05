-- Verify signed bytes without rewriting the body or signature headers.
-- Durable event replay/idempotency is enforced by Middleware, never local memory.
local mac = require "resty.openssl.mac"
local Handler = { PRIORITY = 1000, VERSION = "1.0.0" }
local function equal(a, b)
  if #a ~= #b then return false end
  local different = 0
  for i = 1, #a do if a:byte(i) ~= b:byte(i) then different = different + 1 end end
  return different == 0
end
local function hex(value)
  return (value:gsub(".", function(c) return string.format("%02x", c:byte()) end))
end
local function allowed(methods, method)
  for _, value in ipairs(methods or {}) do if value == method then return true end end
  return false
end
function Handler:access(conf)
  local method = kong.request.get_method()
  if not allowed(conf.allowed_methods, method) then
    return kong.response.exit(405, { error = "webhook_method_not_allowed" })
  end
  local timestamp = kong.request.get_header("X-Webhook-Timestamp")
  local event = kong.request.get_header("X-Webhook-Event-ID")
  local key_id = kong.request.get_header("X-Webhook-Key-ID")
  local signature = kong.request.get_header("X-Webhook-Signature")
  if type(timestamp) ~= "string" or not timestamp:match("^%d%d%d%d%d%d%d%d%d%d$")
    or math.abs(ngx.time() - tonumber(timestamp)) > conf.clock_skew_seconds
    or type(event) ~= "string" or #event > 128 or not event:match("^[A-Za-z0-9][A-Za-z0-9._:-]*$")
    or key_id ~= conf.key_id or type(signature) ~= "string"
    or #signature ~= 67 or not signature:match("^v2=[0-9a-f]+$") then
    return kong.response.exit(401, { error = "invalid_webhook_signature" })
  end
  -- A configured limit bounds disk-buffer reads too, not only Content-Length.
  local body, err = kong.request.get_raw_body(conf.maximum_body_bytes)
  if err or not body or #body > conf.maximum_body_bytes then
    return kong.response.exit(413, { error = "webhook_body_unavailable_or_too_large" })
  end
  if type(conf.secret) ~= "string" or #conf.secret < 32 or conf.secret:match("^{vault://") then
    return kong.response.exit(503, { error = "webhook_key_unavailable" })
  end
  local ctx = mac.new(conf.secret, "HMAC", nil, "sha256")
  local signed = ctx and ctx:final(table.concat(
    { "v2", key_id, timestamp, event, method, conf.route_id, body }, "\n"))
  if not signed then return kong.response.exit(503, { error = "webhook_verifier_unavailable" }) end
  if not equal("v2=" .. hex(signed), signature) then
    return kong.response.exit(401, { error = "invalid_webhook_signature" })
  end
end
return Handler
