/* DataPower GatewayScript – SecurePath Connector (Tier-1, ES5)
 * MPGW Transform (INPUT -> OUTPUT), request rule
 * Matches the QA validator expectations (fail-open, xff, application/json chunked allowlist)
 */

'use strict';

var urlopen = require('urlopen');
var sm = require('service-metadata');
var hm = require('header-metadata');

/* ------------------------- Config (match your validator) ------------------------- */
var cfg = {
  // SecurePath endpoint
  rdwr_app_ep_addr: '<insert_app_ep_addr>',
  rdwr_app_ep_port: 8000,
  rdwr_app_ep_ssl: false,
  rdwr_app_ep_timeout: 200, // ms

  // Credentials
  rdwr_app_id: '<insert_app_id>',
  rdwr_api_key: '<insert_api_key>',

  // Body sizing
  rdwr_partial_body_size: 10 * 1024,  // 10KB
  rdwr_body_max_size: 100 * 1024,     // 100KB

  // True client IP
  rdwr_true_client_ip_header: 'xff',  

  // Static bypass (AND: method + extension) with query override
  list_of_methods_not_to_inspect: ['GET', 'HEAD'],
  list_of_bypassed_extensions: /\.(png|jpe?g|gif|css|js|ico|svg|woff2?|ttf|otf|eot)$/i,
  inspect_if_query_string_exists: true,

  // Chunked allowlist (validator expects only application/json)
  chunked_request_allowed_content_types: ['application/json'],

  // TLS posture for sideband
  ssl_verify_certificate: true,
  dp_tls_profile_name: '<insert_profile_name, for example: SP_WAF_HTTPS>',

  // Failure policy
  failOpen: true,

  // Optional: hard bypass for Bot-Manager paths (Tier-2; harmless here)
  reverse_proxy_paths: [
    '/18f5227b-e27b-445a-a53f-f845fbe69b40/',
    '/c99a4269-161c-4242-a3f0-28d44fa6ce24/'
  ],

  // Tag
  plugin_info: 'DataPower-v1.4.2'
};

/* ------------------------- Utilities ------------------------- */
function log(lvl, msg) {
  try { console.error(new Date().toISOString(), '[SP]', (lvl+'     ').slice(0,5), String(msg)); } catch(e){}
}
function assert(cond, id, msg) { if (!cond) throw new Error('CFG_'+id+' '+msg); }
function safeGetVar(name) { try { return sm.existsVar(name) ? sm.getVar(name) : null; } catch(e){ return null; } }
function lc(s){ return String(s||'').toLowerCase(); }
function headerGet(n){ try { return hm.current && hm.current.get ? (hm.current.get(n) || '') : ''; } catch(e){ return ''; } }
function respond(status, headers, body){
  try {
    hm.response.statusCode = status;
    for (var k in headers){ if (headers.hasOwnProperty(k)) hm.response.set(k, headers[k]); }
    session.output.write(body || '');
    sm.setVar('var://service/mpgw/skip-backside', true);
  } catch(e){ session.output.write(body || ''); }
}
function writeThrough(buf){ try { if (buf && buf.length) { session.output.write(buf); } } catch(e){} }

/* Robust path resolver for static-bypass */
function getPathAndQuery() {
  var uri = safeGetVar('var://service/URI');         // often "/foo?x=1"
  var url = safeGetVar('var://service/URL');         // e.g., "https://host:port/foo?x=1"
  if (url && url.indexOf('://') > 0) {
    var p = url.split('://')[1];
    var slash = p.indexOf('/');
    if (slash >= 0) return p.substring(slash);       // "/foo?x=1"
  }
  if (uri) return String(uri);
  // last resort: try :path (HTTP/2) or Host + Request-URI guesses
  var hPath = headerGet(':path');
  if (hPath) return String(hPath);
  return '/';
}

/* ------------------------- Config sanity ------------------------- */
try {
  assert(typeof cfg.rdwr_app_ep_addr === 'string', '01', 'rdwr_app_ep_addr missing');
  assert(typeof cfg.rdwr_app_ep_port === 'number', '02', 'rdwr_app_ep_port must be number');
  assert(typeof cfg.rdwr_app_ep_ssl === 'boolean', '03', 'rdwr_app_ep_ssl must be boolean');
  assert(cfg.rdwr_partial_body_size <= cfg.rdwr_body_max_size, '04', 'partial must be ≤ max');
} catch(e){
  log('ERR', e.message);
  respond(500, {'Content-Type':'text/html; charset=utf-8'}, '<h1>500 Configuration Error</h1>');
  return;
}

/* ------------------------- Main ------------------------- */
try {
  session.input.readAsBuffer(function (err, originalBody) {
    if (err){ log('ERR','READ_INPUT '+err.message); respond(500, {'Content-Type':'text/html; charset=utf-8'}, '<h1>500 Read Error</h1>'); return; }

    var method = String(safeGetVar('var://service/protocol-method') || 'GET');
    var uriFull = getPathAndQuery();
    var qidx = uriFull.indexOf('?');
    var pathOnly = qidx >= 0 ? uriFull.substring(0, qidx) : uriFull;
    var hasQuery = qidx >= 0;

    log('INFO', 'REQ '+method+' '+uriFull);

    /* --- Reserved Header Enforcement (allow plugin-info) --- */
    var forbidden = {'x-rdwr-app-id':1,'x-rdwr-api-key':1,'x-rdwr-connector-ip':1,'x-rdwr-partial-body':1,'x-rdwr-cdn-ip':1,'x-rdwr-ip':1};
    if (hm.current && hm.current.headers){
      for (var h in hm.current.headers){
        if (!hm.current.headers.hasOwnProperty(h)) continue;
        var hl = lc(h);
        if (forbidden[hl]) { log('WARN','TCHVALxx RESERVED '+hl); respond(403, {'Content-Type':'text/html; charset=utf-8'}, '<h1>403 Forbidden</h1>'); return; }
        // x-rdwr-plugin-info explicitly allowed (TCHVAL04)
      }
    }

    /* --- Static asset bypass (AND: method + extension) + query override --- */
    var methodBypass = false;
    for (var i=0;i<cfg.list_of_methods_not_to_inspect.length;i++){
      if (lc(method) === lc(cfg.list_of_methods_not_to_inspect[i])) { methodBypass = true; break; }
    }
    var extBypass = cfg.list_of_bypassed_extensions.test(pathOnly);
    if (methodBypass && extBypass){
      if (cfg.inspect_if_query_string_exists && hasQuery){
        log('INFO','static-bypass canceled by query -> inspect');
      } else {
        log('INFO','TCBYP01 bypass -> origin');
        writeThrough(originalBody);           // IMPORTANT: write INPUT to OUTPUT so request proceeds
        return;
      }
    }

    /* --- Prepare outbound headers for SecurePath --- */
    var hdrOut = {};
    if (hm.current && hm.current.headers){
      for (var h2 in hm.current.headers){
        if (!hm.current.headers.hasOwnProperty(h2)) continue;
        var h2l = lc(h2);
        if (h2l.indexOf('x-rdwr-') === 0) continue;  // never forward client x-rdwr-*
        if (h2l === 'transfer-encoding' || h2l === 'expect') continue;
        hdrOut[h2] = hm.current.headers[h2];
      }
    }

    // Mandatory headers
    hdrOut['X-RDWR-App-Id'] = cfg.rdwr_app_id;
    hdrOut['X-RDWR-Api-Key'] = cfg.rdwr_api_key;
    hdrOut['X-RDWR-Plugin-Info'] = cfg.plugin_info;

    // True client IP (prefer configured header; fallback to remote address). Always set x-rdwr-connector-ip.
    var trueIP = '';
    var tcipName = cfg.rdwr_true_client_ip_header;
    if (tcipName) {
      var hv = headerGet(tcipName);
      if (hv) { trueIP = String(hv.split(',')[0]).replace(/^\s+|\s+$/g, ''); }
    }
    if (!trueIP) trueIP = String(safeGetVar('var://service/remote-address') || '');
    hdrOut['X-RDWR-Connector-IP'] = trueIP;
    hdrOut['X-RDWR-Connector-Port'] = String(safeGetVar('var://service/remote-port') || '0');
    var localPort = String(safeGetVar('var://service/local-port') || '');
    hdrOut['X-RDWR-Connector-Scheme'] = (localPort === '443' || cfg.rdwr_app_ep_ssl) ? 'https' : 'http';

    if (!hdrOut['Host']) hdrOut['Host'] = headerGet('Host') || 'unknown';

    /* --- Request body policy --- */
    var transferEnc = lc(headerGet('Transfer-Encoding'));
    var isChunked = transferEnc.indexOf('chunked') >= 0;
    var ct = lc(headerGet('Content-Type'));
    var bodyForSP = originalBody || new Buffer(0);

    // Chunked handling: allow only configured types; otherwise send headers-only (length 0)
    if (isChunked) {
      var allowed = false;
      for (i=0;i<cfg.chunked_request_allowed_content_types.length;i++){
        var t = lc(cfg.chunked_request_allowed_content_types[i]);
        if (ct.indexOf(t) === 0) { allowed = true; break; }
      }
      if (!allowed) {
        log('WARN','TCCHNK disallowed-ctype '+ct+' -> headers-only');
        hdrOut['Content-Length'] = '0';
        bodyForSP = new Buffer(0);
      }
    }

    // Size windows (do these ONLY if we still have a body to send)
    if (bodyForSP.length > 0) {
      if (bodyForSP.length > cfg.rdwr_body_max_size){
        log('INFO','OVERSIZE -> headers-only');
        bodyForSP = new Buffer(0);
        hdrOut['Content-Length'] = '0';
      } else if (bodyForSP.length > cfg.rdwr_partial_body_size){
        bodyForSP = bodyForSP.slice(0, cfg.rdwr_partial_body_size);
        hdrOut['X-RDWR-Partial-Body'] = 'true';
        hdrOut['Content-Length'] = String(bodyForSP.length);
        log('INFO','PARTIAL '+bodyForSP.length+' bytes');
      } else {
        hdrOut['Content-Length'] = String(bodyForSP.length);
        log('INFO','FULL '+bodyForSP.length+' bytes');
      }
    } else {
      hdrOut['Content-Length'] = '0';
    }

    delete hdrOut['Transfer-Encoding'];
    delete hdrOut['Expect'];

    /* --- Reverse-proxy hard bypass (Tier-2 paths; no SP headers added) --- */
    for (i=0;i<cfg.reverse_proxy_paths.length;i++){
      var pfx = cfg.reverse_proxy_paths[i];
      if (pathOnly.indexOf(pfx) === 0) {
        log('INFO','TCPATH hard-bypass '+pfx);
        writeThrough(originalBody);
        return;
      }
    }

    /* --- Sideband call to SecurePath --- */
    var target = (cfg.rdwr_app_ep_ssl ? 'https' : 'http') + '://' +
                 cfg.rdwr_app_ep_addr + ':' + cfg.rdwr_app_ep_port + uriFull;

    var openOpts = { target: target, method: method, headers: hdrOut, data: bodyForSP, timeout: cfg.rdwr_app_ep_timeout };
    if (cfg.rdwr_app_ep_ssl) openOpts.sslClientProfile = cfg.dp_tls_profile_name;

    urlopen.open(openOpts, function (eOpen, res) {
      if (eOpen) {
        var msg = String(eOpen.message || '');
        if (/timeout/i.test(msg)) log('ERR','TIMEOUT_CONNECT '+msg);          // TCFAIL01
        else if (/SSL|TLS|certificate|handshake/i.test(msg)) log('ERR','TLS_VERIFY_FAILED '+msg); // TCFAIL04
        else log('ERR','SP_CONNECT_ERR '+msg);
        if (cfg.failOpen) { writeThrough(originalBody); return; }
        respond(502, {'Content-Type':'text/plain; charset=utf-8'}, 'SecurePath Unreachable');
        return;
      }

      res.readAsBuffer(function (eRead, spBuf) {
        if (eRead) {
          log('ERR','TIMEOUT_READ '+String(eRead.message||''));               // TCFAIL02
          if (cfg.failOpen) { writeThrough(originalBody); return; }
          respond(500, {'Content-Type':'text/plain; charset=utf-8'}, 'SecurePath Read Error');
          return;
        }

        var status = res.statusCode;
        var rh = res.headers || {};
        var oop = lc(rh['X-RDWR-OOP-Request-Status'] || rh['x-rdwr-oop-request-status'] || '');
        var ctype = rh['Content-Type'] || rh['content-type'] || 'text/html';

        // Treat unexpected 301/302 from SecurePath as failure (do not redirect) – T1 TCFAIL06
        if ((status === 301 || status === 302) && rh['Location']) {
          log('WARN','TCFAIL06 UNEXPECTED_REDIRECT '+rh['Location']);
          if (cfg.failOpen) { writeThrough(originalBody); return; }
          respond(502, {'Content-Type':'text/plain; charset=utf-8'}, 'SecurePath redirect not followed');
          return;
        }

        // Allow: 200 + oop=allowed
        if (status === 200 && oop === 'allowed') {
          log('INFO','TCVRD01 allowed -> origin');
          writeThrough(originalBody);
          return;
        }

        // Block: 403 OR 200-without-allowed (no uzmcr exceptions in T1)
        if (status === 403 || (status === 200 && oop !== 'allowed')) {
          var body = spBuf ? spBuf.toString() : '';
          // Preserve JSON content-type when blocking JSON verdict (TCVRD10)
          var ctLower = lc(ctype);
          if (ctLower.indexOf('application/json') === 0) {
            respond(403, {'Content-Type':'application/json; charset=utf-8'}, spBuf);
          } else {
            respond(403, {'Content-Type':'text/html; charset=utf-8'}, body || '<h1>403 Forbidden</h1>');
          }
          return;
        }

        // 5xx from SecurePath => failure policy
        if (status >= 500) {
          log('ERR','SP_HTTP_ERROR '+status);                                   // TCFAIL03
          if (cfg.failOpen) { writeThrough(originalBody); return; }
          respond(502, {'Content-Type':'text/plain; charset=utf-8'}, 'SecurePath error');
          return;
        }

        // Default: allow
        log('INFO','default allow -> origin');
        writeThrough(originalBody);
      });
    });
  });
} catch(e){
  log('FATAL', e.message);
  respond(500, {'Content-Type':'text/html; charset=utf-8'}, '<h1>500 Internal Error</h1>');
}
