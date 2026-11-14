# Phase 9 JSON request logging

The app generates a fresh 128-bit hexadecimal `X-Request-Id` for every HTTP
request and ignores a client-supplied value. The ID is available to handlers
through `request.state.request_id` and is returned on success, body-limit and
CORS rejects, and handled 500 responses. Each request emits a JSON line with
the timestamp, event, level, request ID, HTTP method, matched **route
template**, status, and bounded duration. An exception emits a second JSON
line with only its class name. Unmatched requests do not log the requested
path. Operational warnings use fixed event names and optional class names.

The logger accepts only those fields and validates or replaces malformed
values. It does not accept QR payloads or URLs, query strings, tokens, cookies,
raw IPs, account IDs, response bodies, exception messages, or arbitrary
metadata. This follows [OWASP's logging guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet)
on correlation, data exclusion, and log injection. The error logger must not
introduce a second leak if a decoder, email provider, wallet RPC, or model
loader raises with customer data in its exception text.

The Docker start command includes `--no-access-log` because Uvicorn's default
access log records the raw request line and client address. [Uvicorn's logging
documentation](https://github.com/kludex/uvicorn/blob/main/docs/concepts/logging.md)
confirms that the flag disables access logging without disabling error logs.
CLI output in `hackabull/cli.py`, `distribute.py`, and `scrop.py` remains human
readable because these are operator commands, not request handlers.

## Release checks and limits

- Confirm Render uses the Docker start command, or put `--no-access-log` in
  any overriding Uvicorn command. Exercise a QR URL containing a harmless
  marker and confirm neither the marker nor a raw IP appears in Render's app
  stdout/stderr. The request ID should appear in the response and JSON event.
- Check how Render and Cloudflare retain ingress logs; this code cannot change
  those platforms' logs, other dependencies' own diagnostics, or existing
  historical logs. Apply the organization's log access and retention policy.
- If a streaming response fails after HTTP headers have been sent, the status
  cannot be changed to 500. The middleware logs a safe failure event and ends
  the stream. Clients should treat truncated streaming content as a failed
  transfer; a later transport design can add an explicit end-of-stream check.
- Startup errors from Uvicorn still use Uvicorn's logger. This slice removes
  application request data from app events and disables its raw access log;
  it does not reformat every third-party or server lifecycle log.
