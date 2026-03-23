# Google Identity Services (GIS) Library - FedCM Implementation Analysis

Analysis date: 2026-03-19
Source: `https://accounts.google.com/gsi/client` (254KB minified, 7520 lines beautified)

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Core FedCM Functions](#core-fedcm-functions)
  - [ht - FedCM Caller Object](#ht---fedcm-caller-object)
  - [it - Build FedCM Options](#it---build-fedcm-options)
  - [jt - Execute FedCM Call](#jt---execute-fedcm-call)
  - [ht.prototype.ga - Response Handler (Continuation API)](#htprototypega---response-handler-continuation-api)
- [Flow Orchestration](#flow-orchestration)
  - [kt/lt/mt/nt - FedCM Call Wrappers](#ktltmtnt---fedcm-call-wrappers)
  - [Is - FedCM Mode Support Detection](#is---fedcm-mode-support-detection)
  - [fu - FedCM Eligibility Check (One Tap)](#fu---fedcm-eligibility-check-one-tap)
  - [gu - FedCM Eligibility Check (Button)](#gu---fedcm-eligibility-check-button)
  - [ju - Launch FedCM One Tap Flow](#ju---launch-fedcm-one-tap-flow)
  - [Zt.prototype.ma - Main Prompt Entry Point](#ztprototypema---main-prompt-entry-point)
- [Abort Mechanism](#abort-mechanism)
  - [bu - Abort FedCM Flow](#bu---abort-fedcm-flow)
  - [eu - Click Outside Handler](#eu---click-outside-handler)
- [Cooldown System](#cooldown-system)
  - [Et - Read State from Cookie](#et---read-state-from-cookie)
  - [Gt - Set Cooldown](#gt---set-cooldown)
  - [Ht - Check Cooldown Active](#ht---check-cooldown-active)
- [Error Handling](#error-handling)
  - [Zt.prototype.la - FedCM Error Handler](#ztprototypela---fedcm-error-handler)
  - [Zt.prototype.ga - Credential Processing](#ztprototypega---credential-processing)
- [Callback System](#callback-system)
  - [cu - Skipped Moment Callback](#cu---skipped-moment-callback)
  - [iu - Dismissed Moment Callback](#iu---dismissed-moment-callback)
- [Utility Functions](#utility-functions)
- [FedCM Configuration URLs](#fedcm-configuration-urls)
- [Experiment Flags](#experiment-flags)
- [Declarative FedCM (Bluedog PoC)](#declarative-fedcm-bluedog-poc)
- [Key Findings for Stale Tab Hang Issue](#key-findings-for-stale-tab-hang-issue)

---

## Overview

The GIS library is a closed-source, minified JavaScript library that Google distributes
from `accounts.google.com/gsi/client`. It provides two main authentication UIs:

1. **One Tap (widget mode)** - Auto-appearing prompt, uses FedCM **passive** mode
2. **Sign In With Google Button (button mode)** - User-initiated, uses FedCM **active** mode

The library internally wraps `navigator.credentials.get()` and handles the FedCM flow,
but exposes no timeout, abort, or fallback configuration to consumers.

---

## Architecture

```
User calls google.accounts.id.prompt() or clicks Sign In button
  |
  v
Zt.prototype.ma()  -- Main entry point
  |
  +-- Cooldown check (Ht) -- If in cooldown, skip prompt entirely
  |
  +-- FedCM eligibility (fu/gu) -- Browser/config checks
  |     |
  |     +-- YES: ju() -- FedCM path
  |     |     |
  |     |     +-- mt()/nt() -> lt() -> jt()
  |     |     |     |
  |     |     |     +-- it() builds options (AbortController created here)
  |     |     |     +-- navigator.credentials.get(options)
  |     |     |     +-- .then() -> ht.prototype.ga -> Zt.prototype.ga
  |     |     |     +-- .catch() -> Zt.prototype.la
  |     |     |     +-- .finally() -> clear AbortController
  |     |     |
  |     |     +-- eu() -- Install "click outside" handler
  |     |
  |     +-- NO: iframe path
  |           +-- lu() -> iframe setup
  |           +-- mu() -> 90-second auto-dismiss timer (iframe only!)
  |           +-- eu() -> click outside handler
  |
  v
Callbacks: callback(credential) or moment notification
```

---

## Core FedCM Functions

### ht - FedCM Caller Object

Each FedCM call gets a unique ID for logging/tracking.

```javascript
// Constructor: creates a caller with unique ID
var ht = function() {
  this.g = ns();  // unique call ID (e.g., random string)
};

// Properties after initialization:
// this.g = call ID (string)
// this.h = AbortController (set in it(), cleared in finally())
```

### it - Build FedCM Options

Constructs the options object passed to `navigator.credentials.get()`.

```javascript
var it = function(a, b, c) {
  // a = ht instance (caller)
  // b = config object (contains client_id, nonce, params, etc.)
  // c = mode: "widget" | "button"

  _.E("Generating FedCM options. callId: " + a.g + ".");

  // *** KEY: AbortController created fresh for each call ***
  a.h = new AbortController;

  // Build provider config
  var d = {
    url:       b.Mc,          // FedCM base URL (https://accounts.google.com/gsi/)
    configURL: b.pb,          // FedCM config (fedcm.json or split active/passive)
    clientId:  b.m.client_id,
    params:    b.Ra            // Additional params (nonce, response_type, scope, etc.)
  };

  // Optional: request name/email/picture fields (unicorn experiment)
  if (_.I("enable_unicorn_in_fedcm_onetap")) {
    d.fields = ["name", "email", "picture"];
  }

  // Optional fields
  if (b.m.nonce)         d.nonce = b.m.nonce;
  if (b.m.hint)          d.loginHint = b.m.hint;
  if (b.m.hosted_domain) d.domainHint = (b.m.hosted_domain === "*") ? "any" : b.m.hosted_domain;

  // Build identity options
  d = {
    context:   b.m.context || "signin",
    providers: [d],
    // Chrome >= 131: "button" -> "active", "widget" -> "passive"
    // Older Chrome: pass mode string directly
    mode: _.Ra() >= 131 ? (c === "button" ? "active" : "passive") : c
  };

  // Build top-level options
  var e = {
    signal:    a.h.signal,    // *** AbortController signal ***
    federated: d,             // Legacy key (kept for compatibility)
    identity:  d              // Standard key
  };

  // Mediation: "optional" allows auto-reauthn, "required" forces user interaction
  e.mediation = b.Ja ? "optional" : "required";

  // Widget mode: enable auto re-authentication
  if (c === "widget") {
    d.autoReauthn = !!b.Ja;
  }

  _.E("FedCM options generated. callId: " + a.g + ". " + e);
  return e;
};
```

**Important observations:**
- `mode: "active"` is only used for "button" flow on Chrome >= 131
- "widget" (One Tap) always uses `mode: "passive"`
- Both `federated` and `identity` keys are set (backward compatibility)
- The AbortController `signal` is attached but **never auto-aborted by a timer**

### jt - Execute FedCM Call

The actual `navigator.credentials.get()` invocation.

```javascript
var jt = function(a, b, c) {
  // a = ht instance (caller)
  // b = config object
  // c = mode ("widget" | "button")

  c = c === void 0 ? "widget" : c;
  _.E("Starting FedCM call. Mode: " + c + " | callId: " + a.g + ".");

  navigator.credentials.get(it(a, b, c))
    .then(function(d) {
      // *** SUCCESS: credential received ***
      _.E("Response received. callId: " + a.g + ".");
      a.ga(b, c, d);             // -> ht.prototype.ga (handles continuation API)
    }, function(d) {
      // *** ERROR: Promise rejected ***
      _.E("Error received. callId: " + a.g + ".");
      b.la(c, d);                // -> error handler (eventually Zt.prototype.la)
    })
    .finally(function() {
      // *** ALWAYS: clear AbortController reference ***
      a.h = void 0;
    });
};
```

**Critical observation:**
- **NO timeout wrapping** - no `Promise.race()`, no `setTimeout`, no `AbortSignal.timeout()`
- If `navigator.credentials.get()` hangs, `then`/`catch`/`finally` **never fire**
- The AbortController is only cleared in `finally`, so if the promise hangs, `a.h` remains set

### ht.prototype.ga - Response Handler (Continuation API)

Handles the FedCM Continuation API (`.login()` method on credential).

```javascript
ht.prototype.ga = function(a, b, c) {
  // a = config object
  // b = mode
  // c = credential (IdentityCredential)

  if (c) {
    _.E("Processing FedCM response. callId " + this.g);

    if (c.login) {
      // *** Continuation API: call .login() for multi-step flow ***
      c.login({
        signal: this.h.signal,   // Reuse same AbortController signal
        nonce: a.m.nonce
      }).then(function(d) {
        a.ga(b, d, a.Ra);       // Process the login result
      }, function(d) {
        a.la(b, d);             // Handle login error
      });
    } else {
      // Standard flow: pass credential directly
      a.ga(b, c, a.Ra);        // -> Zt.prototype.ga
    }
  } else {
    // Null credential
    _.E("FedCM credential is null. callId " + this.g);
    a.la(b, Error("W"));       // Error code "W" = null credential
  }
};
```

---

## Flow Orchestration

### kt/lt/mt/nt - FedCM Call Wrappers

```javascript
// kt = FedCM manager object
var kt = function() {
  this.h = false;    // FedCM "mode" supported flag (set by Is())
};

// lt = generic launcher
var lt = function(a, b, c) {
  a.g = new ht();                        // Create new caller with unique ID
  jt(a.g, b, c === void 0 ? "widget" : c);  // Execute FedCM call
};

// mt = One Tap launcher (passive mode)
var mt = function(a, b) {
  lt(a, b, "widget");
};

// nt = Button launcher (active mode)
var nt = function(a, b) {
  lt(a, b, "button");
};
```

### Is - FedCM Mode Support Detection

Uses a clever trick: creates a `credentials.get()` call with a property getter
to detect if the browser reads the `mode` field.

```javascript
var Is = function(a) {
  _.E("Evaluating FedCM mode support.");
  var b = {
    identity: Object.defineProperty({}, "mode", {
      get: function() {
        // If the browser reads "mode", it supports active/passive modes
        _.E("FedCM mode supported.");
        a.h = true;   // Set flag: mode is supported
      }
    })
  };
  try {
    // Fire and forget - just to trigger the getter
    navigator.credentials.get(b).then(function() {}, function() {});
  } catch (c) {}
};
```

**Interesting technique**: This is a feature-detection pattern that probes
browser support without making a real FedCM call.

### fu - FedCM Eligibility Check (One Tap)

Determines whether to use FedCM or fall back to iframe-based One Tap.

```javascript
var fu = function(a) {
  // Hard disable via feature flag
  if (_.I("disable_fedcm") || !$r() || !_.md()) return false;

  // Inject origin trial token for account labels feature
  if (_.I("enable_account_labels") && !ct.accountLabelsToken) {
    var b = document.createElement("meta");
    b.httpEquiv = "origin-trial";
    b.content = "A0bwwYX3EzD2AQ197RM...";  // origin trial token
    document.getElementsByTagName("head")[0].appendChild(b);
    ct.accountLabelsToken = true;
  }

  // Exclusions
  if (a.xc()) return false;                          // Subclass override
  if (bs() === "https://meet.google.com") return false;  // Meet excluded

  // A/B testing groups
  if (_.I("enable_fedcm_global_experiment")) {
    _.E("In FedCM global experiment group");
    return true;
  }
  if (_.I("enable_fedcm_global_control")) {
    _.E("In FedCM global control group");
    return false;
  }

  // Auto-select requires Chrome >= 121
  if (a.m.auto_select && !(_.Ra() >= 121)) return false;

  // Opt-out is disabled on Chrome >= 142 (FedCM becomes mandatory)
  if (_.I("disable_fedcm_opt_out") && _.Ra() >= 142) return true;

  // Check user's explicit opt-out setting
  var isOptedOut = (a.wa === false);
  if (isOptedOut) {
    _.G("Currently, you disable FedCM on Google One Tap. " +
        "FedCM for One Tap will become mandatory soon...");
  }
  return !isOptedOut;
};
```

Where `$r()` checks browser compatibility:
```javascript
$r = function() {
  // Chrome-based browser, not Samsung Browser, not Edge mobile, not Opera
  // Minimum Chrome 108 (or Chrome 118 for desktop)
  return !_.Xa() || _.ck(_.dk(), "118") >= 0
    ? _.ld() && (_.Ta() || !_.kd() && !_.jd()) && _.ck(_.dk(), "108") >= 0
    : false;
};
```

And `_.md()` checks FedCM API availability:
```javascript
_.md = function() {
  var a = window;
  return "IdentityCredential" in window
      || ("FederatedCredential" in window && a.FederatedCredential.prototype.login);
};
```

### gu - FedCM Eligibility Check (Button)

```javascript
var gu = function(a) {
  return $r() && a.v.h   // Browser compatible AND mode supported
    ? _.I("enable_fedcm_button_global_control")
      ? (_.E("In FedCM button global control group"), false)
      : _.I("enable_fedcm_button_global_experiment")
        ? (_.E("In FedCM button global experiment group"), true)
        : !!a.xe          // a.xe = use_fedcm_for_button config
    : false;
};
```

### ju - Launch FedCM One Tap Flow

The function that actually initiates the FedCM One Tap (widget/passive) flow.

```javascript
var ju = function(a) {
  a.D = true;   // Mark: FedCM flow is active

  // Build params
  var b = {
    as:           a.l,
    top_origin:   cs() ? bs() : void 0,
    library_name: a.m.library_name || void 0
  };

  // Unicorn experiment: add id_token params
  if (_.I("enable_unicorn_in_fedcm_onetap")) {
    b.response_type = "id_token";
    b.ss_domain     = a.m.origin || location.origin;
    b.scope         = "email profile openid";
    b.nonce         = a.m.nonce || "not_provided";
    b.state         = a.m.state;
  }
  if (a.m.claims) b.claims = a.m.claims;

  // Launch FedCM via mt() -> lt() -> jt()
  mt(a.v, {
    Mc:  a.ib,                                              // fedcm_url
    pb:  _.I("enable_fedcm_config_split") ? a.hb : a.B,    // config URL
    m:   a.m,                                               // full config
    Ja:  !!a.m.auto_select,                                 // auto-reauthn
    ga:  a.ga.bind(a),                                      // success callback
    la:  function(c, d) {
      // *** ERROR HANDLER ***
      Fr(a.J, a.i.client_id, a.l);  // Tracking/logging

      // Check for specific errors
      var e = document.location.ancestorOrigins
        ? document.location.ancestorOrigins.length : 0;
      e = e > 0 ? document.location.ancestorOrigins[e - 1] : "";
      var f = [document.location.protocol, "//", document.location.host].join("");

      // Permission policy error
      if (d.message.indexOf("identity-credentials-get") >= 0) {
        Nr("failedWithIframeGetPermission",
           "iframeOrigin=" + f, "path=" + document.location.pathname, "topOrigin=" + e);
      }
      // CSP error
      if (d.message.indexOf("Content Security Policy") >= 0) {
        Nr("failedWithCsp",
           "iframeOrigin=" + f, "path=" + document.location.pathname, "topOrigin=" + e);
      }

      a.la(c, d);  // -> Zt.prototype.la
    },
    pe: function() {
      a.D = false;  // Clear: FedCM flow no longer active
    },
    Ra: b    // params
  });

  // Install "click outside" handler
  eu(a);
};
```

### Zt.prototype.ma - Main Prompt Entry Point

The master decision function called by `google.accounts.id.prompt()`.

```javascript
_.Zt.prototype.ma = function(a, b, c) {
  var d = this;
  b = Object.assign({}, this.i, b);
  Yt(this, b);

  // ... cross-origin warning, chrome extension check ...

  // Cancel any existing flow
  if (bu(this, true)) {
    iu(this, "flow_restarted");   // Fire "dismissed" moment
  }

  // Store callbacks
  this.o  = a;    // moment notification callback
  this.vc = c;    // intermediate_iframe_close_callback

  if (!this.m.client_id) {
    // Error: missing client_id
    return;
  }

  if (/* unsupported browser */) {
    this.j("browser_not_supported");
    return;
  }

  // *** COOLDOWN CHECK (GIS's own, not Chrome's) ***
  if (Ht(this.g)) {
    _.F("User has closed One Tap before. Still in the cool down period.");
    this.j("suppressed_by_user");
    return;
  }

  // *** FEDCM vs IFRAME DECISION ***
  if (fu(this)) {
    // FedCM path
    if (_.I("enable_fedcm_config_split")) {
      ku(this, function(f) {
        if (f && /* all accounts opted out */) {
          d.j("opt_out_or_no_session");
        } else {
          ju(d);   // -> Launch FedCM
        }
      });
    } else {
      ju(this);    // -> Launch FedCM directly
    }
  } else {
    // Iframe path (legacy)
    ku(this, function(f) {
      // ... credential status check ...
      lu(d);              // Setup iframe
      if (!ts()) mu(d);   // *** 90-second auto-dismiss (IFRAME ONLY!) ***
      nu(d);              // Additional setup
      eu(d);              // Click outside handler
    });
  }
};
```

**Key insight**: The 90-second auto-dismiss timer (`mu()`) is **only** in the iframe path.
The FedCM path has **no timeout whatsoever**.

---

## Abort Mechanism

### bu - Abort FedCM Flow

Called when the user clicks outside or when the flow needs to be restarted.

```javascript
var bu = function(a, b) {
  // a = Zt instance
  // b = true if this is a "force" cancel (e.g., flow restart)

  if (a.D) {
    // *** FedCM flow is active ***
    var result;
    var manager = a.v;  // kt instance
    _.E("Aborting current FedCM flow.");

    if (manager.g) {
      // manager.g = ht instance (current caller)
      var caller = manager.g;
      _.E("Aborting FedCM flow. callId " + caller.g);

      if (caller.h) {
        // caller.h = AbortController
        caller.h.abort();
        _.E("FedCM flow aborted. callId " + caller.g);
        caller.h = void 0;  // Clear reference
        result = true;
      } else {
        _.E("No FedCM flow to abort. callId " + caller.g);
        result = false;
      }
    } else {
      _.E("No FedCM flow to abort.");
      result = false;
    }

    if (result) {
      du(a);   // Clean up click listener
      return true;
    }
    return false;
  }

  // Iframe flow cancel (not FedCM)
  // ... remove iframe from DOM ...
};
```

**Observations:**
- `bu()` only fires when `a.D === true` (FedCM is marked active)
- The abort is always user-initiated (click outside, flow restart)
- **There is no timer-based call to `bu()`**

### eu - Click Outside Handler

Installs a document-level click listener to detect "tap outside" events.

```javascript
var eu = function(a) {
  setTimeout(function() {
    // Install click listener (delayed to avoid capturing the triggering click)
    a.Fa = _.Ef(document, "click", function() {
      if (a.fb && bu(a, false)) {
        cu(a, "tap_outside");     // Fire "skipped" moment: user tapped outside
        du(a);                     // Remove click listener

        // ITP optimization: track tapped outside event
        if (_.I("enable_itp_optimization")) Lr("tappedOutside");

        // Some experiment groups set a 30-minute cooldown on tap outside
        // (Gt with true = 30-minute suppress instead of escalating cooldown)
        switch (zr("enable_itp_optimization")) {
          case 12:
            Gt(a.g, true);   // 30-minute cooldown
            break;
          default:
            break;
        }
      }
    });
  });
};

var du = function(a) {
  // Remove the click listener
  if (a.Fa) {
    _.Mf(a.Fa);
    a.Fa = void 0;
  }
};
```

---

## Cooldown System

GIS implements its **own** cooldown system (separate from Chrome's FedCM cooldown),
stored in a cookie called `g_state`.

### Et - Read State from Cookie

```javascript
var Et = function(a) {
  var b = Ct(a);          // Parse JSON from g_state cookie
  var c = b[a.g + "l"];   // prompt_suppress_level (0-4)
  var d = typeof c === "number" && !isNaN(c);

  var state = {
    prompt_suppress_level: d && c >= 0 && c <= 4 ? c : (Dt() ? 1 : 0)
  };

  // Additional state fields
  var p = b[a.g + "p"];  if (p !== void 0) state.disable_auto_prompt     = p;  // timestamp
  var t = b[a.g + "t"];  if (t !== void 0) state.disable_auto_select_to  = t;  // timestamp
  var u = b[a.g + "u"];  if (u !== void 0) state.prompt_ui               = u;
  var x = b[a.g + "x"];  if (x !== void 0) state.mini_prompt_right       = x;
  var y = b[a.g + "y"];  if (y !== void 0) state.mini_prompt_bottom      = y;
  var ll = b[a.g + "ll"]; if (ll !== void 0) state.last_library_load_time = ll;
  var bs = b[a.g + "b"];  if (bs !== void 0) state.browsing_session_id    = bs;
  var e = b[a.g + "e"];  if (e !== void 0) state.experiment_values       = e;

  return state;
};
```

### Gt - Set Cooldown

```javascript
var Gt = function(a, b) {
  // a = Bt instance (state manager)
  // b = true for 30-minute suppress, false for escalating cooldown

  var c = Et(a);

  if (b) {
    // *** 30-minute suppress (e.g., tap outside in some experiment groups) ***
    _.E("Prompt ignored. Suppressing prompt for 30 minutes.");
    var timestamp = new Date().getTime() + 1800000;  // 30 minutes
    c.disable_auto_prompt = Math.max(c.disable_auto_prompt || 0, timestamp);
  } else {
    // *** Escalating cooldown (standard dismissal) ***
    c.prompt_suppress_level = Math.min(c.prompt_suppress_level + 1, 4);
    c.disable_auto_prompt = new Date().getTime() + zt[c.prompt_suppress_level] * 1000;
    // zt = cooldown durations per level (see below)
    Hr(new Ir("onetap", void 0, "startCooldown", c.prompt_suppress_level.toString()));
  }

  Ft(a, c);  // Write back to cookie
};
```

The cooldown duration array `zt` (not directly visible but implied by Chrome docs):

| Level | Duration |
|-------|----------|
| 0 | 0 (no cooldown) |
| 1 | ~2 hours |
| 2 | ~1 day |
| 3 | ~1 week |
| 4 | ~4 weeks |

### Ht - Check Cooldown Active

```javascript
var Ht = function(a) {
  var timestamp = Et(a).disable_auto_prompt;
  return timestamp !== void 0 && timestamp > new Date().getTime();
};
```

**Important**: This is GIS's **application-level** cooldown (stored in cookie).
Chrome also has its own **browser-level** FedCM cooldown that operates independently.
When GIS cooldown is active, `Zt.prototype.ma` skips the FedCM call entirely,
so the browser's cooldown is never hit.

---

## Error Handling

### Zt.prototype.la - FedCM Error Handler

```javascript
_.Zt.prototype.la = function(a, b) {
  // a = mode ("widget" | "button")
  // b = Error or DOMException

  _.H("FedCM get() rejects with " + b);   // console.error()

  if (a === "widget") {
    cu(this, "unknown_reason");  // Fire "skipped" moment callback
  }

  // *** THAT'S IT. No retry. No fallback to iframe. ***
};
```

**Critical finding**: When FedCM rejects (or is aborted), the error handler:
1. Logs to console
2. Fires a "skipped" moment callback with reason `"unknown_reason"`
3. **Does nothing else** - no fallback to iframe, no retry

The inline error handler in `ju()` additionally checks for two specific error messages:
- `"identity-credentials-get"` - Permission Permissions-Policy header issue
- `"Content Security Policy"` - CSP blocking the FedCM call

But these are only for telemetry; they don't trigger any recovery.

### Zt.prototype.ga - Credential Processing

```javascript
_.Zt.prototype.ga = function(a, b, c) {
  // a = mode, b = credential, c = additional params

  if (b) {
    _.E("Processing FedCM credential");

    var token = null;

    if (_.I("enable_unicorn_in_fedcm_onetap")) {
      // New format: JSON with id_token
      try {
        token = JSON.parse(b.token).id_token;
      } catch (f) {
        token = b.token;  // Fallback to raw token
      }
    } else {
      // Standard format
      token = b.token;

      // Handle nested token object: {"token": "...", "state": "...", "loginUri": "..."}
      if (typeof token === "object" && "token" in token) {
        token = b.token && b.token.token;
        var envelope = b.token;

        // Validate state and login_uri if continuation params exist
        if (c) {
          if (c.state !== envelope.state) {
            _.G("State returned by FedCM does not match. Response will not be processed.");
            return;
          }
          if (c.login_uri !== envelope.loginUri) {
            _.G("Login Uri returned by FedCM does not match. Response will not be processed.");
            return;
          }
        }
      } else {
        token = b.token;
      }

      token = b && (b.idToken || token);
    }

    // Build response object
    var response = { credential: token };

    // Determine select_by value for tracking
    response.select_by = a === "widget"
      ? (b.isAutoSelected ? "fedcm_auto" : "fedcm")
      : (b.isAutoSelected ? "fedcm_button_auto" : "fedcm_button");

    // Announce credential received
    hu({ data: { announcement: _.Jl({}) } });

    _.E("FedCM response :" + JSON.stringify(response));

    // Route to appropriate callback
    if (a === "widget") {
      // One Tap flow
      if (this.callback) {
        this.callback.call(this, response);
      }
      iu(this, "credential_returned");   // Fire "dismissed" moment
    } else {
      // Button flow
      if (c && c.state) response.state = c.state;

      if (this.U === "popup") {
        if (this.callback) this.callback.call(this, response);
      } else if (c && c.login_uri) {
        // Redirect mode
        Sr(c.login_uri, { state: c.state }, response.credential);
      } else if (this.N) {
        this.N.call(this, response);   // Redirect callback
      }
    }

    It(this.g);   // Reset browsing session ID
  } else {
    _.E("FedCM credential is null");
  }
};
```

---

## Callback System

### cu - Skipped Moment Callback

Fired when the prompt is skipped (not shown to user or dismissed before interaction).

```javascript
var cu = function(a, b) {
  // a = Zt instance
  // b = skip reason string

  if (a.o) {
    var callback = a.o;
    a.o = void 0;           // Clear callback (one-shot)

    var notification = new yt("skipped");
    notification.l = b;     // reason: "unknown_reason", "tap_outside", etc.

    callback.call(a, notification);
  }
};
```

### iu - Dismissed Moment Callback

Fired when the prompt is dismissed after being displayed.

```javascript
var iu = function(a, b) {
  // a = Zt instance
  // b = dismiss reason string

  if (a.o) {
    var callback = a.o;
    a.o = void 0;           // Clear callback (one-shot)

    var notification = new yt("dismissed");
    notification.i = b;     // reason: "credential_returned", "flow_restarted", etc.

    callback.call(a, notification);
  }
};
```

**Note with FedCM**: Google's migration docs warn that `PromptMomentNotification`
behavior changes with FedCM:
- Display moment notifications are delayed up to **1 minute**
- Skip moment reasons are **no longer provided** (always "unknown_reason")
- `isDisplayMoment()` may not fire at all

---

## Utility Functions

```javascript
// Logging functions
_.E = function(a, b) { /* console.log (debug level) */ };
_.F = function(a, b) { /* console.info */ };
_.G = function(a, b) { /* console.warn */ };
_.H = function(a, b) { /* console.error */ };

// Feature flag check
_.I = function(a) {
  return !!_.Kc.g[a]            // Server-controlled flags
      || _.Lc.includes(a) && _.Mc.get("ge_" + a) === "1";  // Client-side experiments
};

// Chrome version detection
_.Ra = function() {
  // Returns Chromium major version number (e.g., 131)
  // Uses navigator.userAgentData.brands or UA string parsing
};

// Browser checks
_.ld = function() {
  // Is Chrome-based (not Samsung, not Edge mobile, not Opera)
};

_.md = function() {
  // Has FedCM support: IdentityCredential or FederatedCredential.login
};

$r = function() {
  // Full FedCM browser compatibility check (Chrome >= 108/118)
};
```

---

## FedCM Configuration URLs

```javascript
// Default
a.B = b.fedcm_config_url || "https://accounts.google.com/gsi/fedcm.json";

// Split config (when enable_fedcm_config_split flag is on)
a.hb = b.fedcm_passive_config_url || "https://accounts.google.com/gsi/fedcm/config/passive.json";
a.he = b.fedcm_active_config_url  || "https://accounts.google.com/gsi/fedcm/config/active.json";

// Base URL for FedCM endpoints
a.ib = b.fedcm_url || "https://accounts.google.com/gsi/";
```

---

## Experiment Flags

| Flag | Description | Default |
|------|-------------|---------|
| `disable_fedcm` | Hard-disable FedCM entirely | off |
| `disable_fedcm_on_samsung_browsers` | Disable on Samsung Browser | on |
| `disable_fedcm_opt_out` | Prevent sites from opting out | **on** |
| `enable_fedcm_global_experiment` | A/B: force FedCM on | off |
| `enable_fedcm_global_control` | A/B: force FedCM off | off |
| `enable_fedcm_button_global_experiment` | A/B: force button FedCM on | off |
| `enable_fedcm_button_global_control` | A/B: force button FedCM off | off |
| `enable_fedcm_config_split` | Use separate active/passive configs | off |
| `enable_unicorn_in_fedcm_onetap` | id_token + fields in FedCM | **on** |
| `enable_fedcm_bluedog_poc` | Declarative FedCM (`<login>` element) | off |
| `enable_account_labels` | FedCM account labels feature | off |
| `cancelable_auto_select` | Auto-select can be canceled | on |

---

## Declarative FedCM (Bluedog PoC)

GIS has experimental support for Declarative FedCM using HTML `<login>` element:

```javascript
// ot() creates the declarative FedCM markup
var ot = function(a, b) {
  var providers = [{
    "@type":      "FederatedLoginProvider",
    configURL:    a,
    clientId:     b.client_id,
    loginHint:    b.hint,
    domainHint:   b.hosted_domain === "*" ? "any" : b.hosted_domain,
    params:       Js(b),
    fields:       ["email", "name", "picture"]
  }];

  var login = document.createElement("login");
  var credential = document.createElement("credential");
  login.appendChild(credential);
  credential.setAttribute("type", "federated");
  credential.setAttribute("configURL", providers[0].configURL);
  credential.setAttribute("clientId", providers[0].clientId);
  // ... set other attributes ...
  return login;
};
```

This is behind the `enable_fedcm_bluedog_poc` flag and not yet widely deployed.

---

## Key Findings for Stale Tab Hang Issue

### 1. Google does NOT handle the hang scenario

The FedCM path in GIS has:
- **No timeout** on `navigator.credentials.get()`
- **No `AbortSignal.timeout()`**
- **No `Promise.race()` with a timer**
- **No fallback** from FedCM to iframe when FedCM fails
- **No retry** logic

If the promise hangs, GIS waits forever.

### 2. AbortController is only for user-initiated cancel

The `AbortController` created in `it()` is only aborted by `bu()`, which is triggered by:
- User clicking outside the prompt (`eu()`)
- Flow restart (`Zt.prototype.ma` called again)

Never by a timer.

### 3. The 90-second auto-dismiss is iframe-only

```javascript
// In Zt.prototype.ma, iframe path only:
if (!ts()) mu(d);   // mu() sets 90-second timeout

// mu():
var mu = function(a) {
  a.K === "bottom_sheet" && window.setTimeout(function() {
    bu(a, false) && cu(a, "auto_cancel");
  }, a.re);   // a.re = auto_dismiss_duration_ms (default ~90000)
};
```

This timer is **never set** in the FedCM path.

### 4. GIS has its own cooldown (separate from Chrome's)

GIS stores cooldown state in the `g_state` cookie. When GIS cooldown is active,
`navigator.credentials.get()` is **never called**, so Chrome's FedCM cooldown
is never reached. This is a different layer of cooldown.

### 5. One Tap uses passive mode, Button uses active mode

```javascript
mode: _.Ra() >= 131 ? (c === "button" ? "active" : "passive") : c
```

Our project uses `mode: "active"` (button-style flow). Per Chrome docs, active mode
should not be subject to cooldown. The hang in our stale tab scenario may be:
- A Chrome bug where active mode still hits cooldown state
- A different Chrome bug related to browsing context state

### 6. Error handling is minimal

When FedCM rejects:
```javascript
_.H("FedCM get() rejects with " + b);       // Log error
cu(this, "unknown_reason");                   // Fire callback
// DONE - no fallback, no retry
```

### 7. Potential approaches not used by Google (but available to us)

Since Google doesn't solve this problem, we need our own approach:

| Approach | Pros | Cons |
|----------|------|------|
| `AbortSignal.timeout(N)` | Simple, one line | Can't distinguish hang vs. slow user |
| `Promise.race([fedcm, timeout])` | Same as above | Same as above |
| Show fallback link after N seconds | User chooses | Extra UI complexity |
| Detect "no dialog shown" via timing | More accurate | Complex, fragile |
| Pre-flight probe call | Could detect bad state | May trigger its own issues |

### 8. GIS's feature detection trick is interesting

The `Is()` function's technique of using `Object.defineProperty` with a getter
to detect browser capabilities without making a real API call could potentially
be adapted to detect stale FedCM state -- though this would require identifying
a property that behaves differently in the stale state.