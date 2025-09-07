# SecurePath Connector for IBM DataPower (Tier-1)

A lightweight, request-path SecurePath connector implemented in **GatewayScript** for **IBM DataPower MPGW**.  
It sends a sideband request to SecurePath with the client’s HTTP request metadata/body, applies the verdict, and (by default) **fails open** on connectivity issues to preserve availability.

> **What you need to do:** upload the script to DataPower, edit the config block at the top (app ID, API key, SecurePath endpoint, etc.), and attach it as a GatewayScript action in your MPGW’s Processing Policy.

---

## Contents

- `rdwr_securepath_connector.js` – the connector script (GatewayScript)

---

## Prerequisites

- IBM DataPower Gateway (MPGW)
- SecurePath **App ID** and **API Key**
- SecurePath application endpoint (host/IP, port, TLS or not)
- Access to DataPower **File Management** and ability to create an **MPGW** and **Processing Policy**

---

## Quick Start

### 1) Upload the script
1. In DataPower, open **File Management**.
2. Upload `rdwr_securepath_connector.js` to a domain folder (e.g., `local:///`).

### 2) Create a Multi-Protocol Gateway (MPGW)
1. **Objects > Multi-Protocol Gateway > Add**.
2. **Front Side:** create/select an **HTTP/HTTPS Front-Side Handler** (port, TLS as needed).
3. **Back Side:** configure your **origin server** (e.g., your app / test backend).  
   - A simple static backend or a load-balancer group both work.
4. Leave default request/response types (Non-XML is fine).

### 3) Add a Processing Policy with GatewayScript
1. **Processing Policy > Add** and attach it to the MPGW.
2. Create a **Rule** for the **request direction** (Client to Server).
3. Add an **Action: GatewayScript** with **Transform = INPUT → OUTPUT**.
4. In that action, **Script Location**: choose **URL** and select your uploaded file (e.g., `local://rdwr_securepath_connector.js`).
5. Save and apply.

> The connector writes the request to OUTPUT and controls flow with verdicts and `skip-backside` for block responses, so no extra actions are required in the rule.

### 4) Configure the connector (inside the script)
At the top of the file there’s a `cfg` object. Set at minimum:

- `rdwr_app_ep_addr` – SecurePath endpoint address
- `rdwr_app_ep_port` – SecurePath endpoint port
- `rdwr_app_ep_ssl` – `true` if the SecurePath endpoint is HTTPS
- `rdwr_app_id` – your SecurePath App ID
- `rdwr_api_key` – your SecurePath API Key
- `dp_tls_profile_name` – DataPower TLS **client** profile name (used when `rdwr_app_ep_ssl: true`)
- Optional: adjust `rdwr_partial_body_size` / `rdwr_body_max_size`, `failOpen`, static-bypass lists, etc.

> **Don’t forget:** you must **edit these values** before deploying (App ID, API Key, endpoint, TLS profile).  

### 5) (If HTTPS) Create/assign a TLS Client Profile
If `rdwr_app_ep_ssl` is `true`, create a **TLS Client Profile** that trusts your SecurePath certificate chain and set its name in `dp_tls_profile_name`.

---

## How it works (high level)

- **Reserved headers:** Client requests that already contain `x-rdwr-*` sensitive headers are **blocked**.
- **Static asset bypass:** For GET/HEAD on static extensions (png, js, css, etc.), the connector **bypasses** SecurePath unless a query string is present.
- **Body policy:** For chunked requests, only certain content types are forwarded; large bodies are partially forwarded up to `rdwr_partial_body_size`, larger bodies send headers-only.
- **Sideband call:** The connector sends SecurePath mandatory headers (App ID, API Key, plugin tag, connector IP/port/scheme) and the (full/partial/empty) body depending on size/chunking rules.
- **Verdict handling:**  
  - **Allow:** 200 with `x-rdwr-oop-request-status: allowed` → forward to origin  
  - **Block:** 403 from SecurePath, or 200 without “allowed” → respond 403 (preserving JSON when provided)  
  - **Failure policy:** timeouts, TLS/connect errors, 5xx → **fail open** if enabled

---

## Configuration reference

| Key | What it does |
| --- | --- |
| `rdwr_app_ep_addr`, `rdwr_app_ep_port`, `rdwr_app_ep_ssl`, `rdwr_app_ep_timeout` | SecurePath endpoint and timeout |
| `rdwr_app_id`, `rdwr_api_key` | Credentials added to outbound headers |
| `rdwr_true_client_ip_header` | Header used to derive client IP (e.g., `xff`) |
| `list_of_methods_not_to_inspect`, `list_of_bypassed_extensions`, `inspect_if_query_string_exists` | Static asset bypass policy |
| `chunked_request_allowed_content_types` | Content types allowed to forward **chunked** bodies |
| `rdwr_partial_body_size`, `rdwr_body_max_size` | Size windows for partial vs. headers-only |
| `failOpen` | If `true`, origin traffic proceeds on SP errors/timeouts |
| `dp_tls_profile_name` | TLS client profile used when `rdwr_app_ep_ssl: true` |
| `plugin_info` | Tag reported to SecurePath |

---

## Testing

- From a client, send a normal GET/POST through the MPGW and watch DataPower logs.  
- Induce a SecurePath timeout or port block to confirm **fail-open** (or disable `failOpen` to see blocking behavior).
- Try a static asset (`GET /app.js`) with and without query string to see the **bypass** rule.

---

## Troubleshooting

- **403 immediately from the gateway:** request contains a reserved `x-rdwr-*` header, or SecurePath returned a block verdict.  
- **SecurePath HTTPS errors:** verify `dp_tls_profile_name` trusts the SP certificate chain and the SP host matches the certificate.  
- **Chunked uploads blocked:** your content type may not be in `chunked_request_allowed_content_types`. Add it if appropriate.

---

## Notes

- This connector is Tier-1 oriented (request path interception with fail-open defaults). Reverse-proxy paths for Bot Manager are stubbed and harmless if unused.
- Logging uses concise tags to aid validation and triage.

