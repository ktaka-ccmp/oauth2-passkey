# iOS Safari Link Click Issue Investigation

## Issue Description

On the demo-both login page, buttons are not clickable for anonymous users on iPhone Safari/Chrome when accessed through ngrok. The same page works correctly on Android and desktop browsers.

**Affected page:** `/o2p/user/login` (demo-both application)
**Affected device:** iPhone (Safari and Chrome browsers)
**Working platforms:** Android, Desktop browsers, iOS via direct nginx proxy

## Investigation Summary

Date: 2025-11-27 (Updated)

### Root Cause Analysis - Final

**Actual Root Cause:** ngrok's interstitial page blocking external JavaScript files

When accessing the application through ngrok on iOS:
1. The main HTML page loads successfully (user has clicked through ngrok's browser verification)
2. External JavaScript files (`oauth2.js`, `passkey.js`) are requested
3. ngrok returns its HTML interstitial page instead of the JavaScript files
4. Browser receives `content-type: text/html` with `<!DOCTYPE html>` content instead of JavaScript
5. Script loading fails, buttons remain disabled

**Evidence from debugging:**
```
fetch oauth2.js status=200
fetch oauth2.js content-type=text/html
fetch oauth2.js length=2780 starts=<!DOCTYPE html><html class="h
oauth2.js LOAD ERROR
```

When using nginx proxy directly (bypassing ngrok):
```
fetch oauth2.js status=200
fetch oauth2.js content-type=application/javascript
fetch oauth2.js length=3054 starts=const oauth2 = (function() {
oauth2.js onload fired
```

### Previous Hypotheses (Incorrect)

Several hypotheses were investigated before identifying the actual cause:

1. **Modal overlay interference** - INCORRECT
2. **iOS Safari inline onclick handler incompatibility** - INCORRECT (worked fine via nginx)
3. **CSS cursor:pointer requirement** - INCORRECT (not the root cause)
4. **iOS Safari popup blocking** - PARTIALLY CORRECT (separate issue, handled with redirect fallback)

## Solution

### Current Implementation

The solution uses external JavaScript files with a robust loading mechanism:

**File: `login.j2`**
```html
<head>
    <script>
        const O2P_ROUTE_PREFIX = '{{o2p_route_prefix}}';
        const csrfToken = "_NOT_SET_";
    </script>

    <script src="{{o2p_route_prefix}}/oauth2/oauth2.js" defer></script>
    <script src="{{o2p_route_prefix}}/passkey/passkey.js" defer></script>

    <style>
        button {
            cursor: pointer;
        }
        button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }
    </style>
</head>

<body>
    <!-- Buttons start disabled -->
    <button id="oauth2-create-user" disabled>Create User</button>
    <!-- ... other buttons ... -->

    <script>
        function enableButtons() {
            if (window.oauth2Ready && window.passkeyReady) {
                // Enable all buttons
                document.getElementById('oauth2-create-user').disabled = false;
                // ... enable other buttons ...

                // Attach event listeners
                document.getElementById('oauth2-create-user').addEventListener('click', function() {
                    oauth2.openPopup('create_user');
                });
                // ... attach other listeners ...
            }
        }
        window.onScriptsReady = enableButtons;
    </script>
</body>
```

**File: `oauth2.js` and `passkey.js`**

Each external script signals when it's loaded:
```javascript
// At end of oauth2.js
window.oauth2Ready = true;
if (typeof window.onScriptsReady === 'function') {
    window.onScriptsReady();
}

// At end of passkey.js
window.passkeyReady = true;
if (typeof window.onScriptsReady === 'function') {
    window.onScriptsReady();
}
```

### How It Works

1. External scripts load with `defer` attribute (parallel download, execute after HTML parsing)
2. Buttons start `disabled` to prevent clicks before scripts are ready
3. Each script sets a ready flag and calls `onScriptsReady()` callback
4. When both scripts are ready, buttons are enabled and event listeners attached
5. Visual feedback: disabled buttons show at 50% opacity

### iOS Safari Popup Handling

The `oauth2.js` file also handles iOS Safari's popup blocking:

```javascript
function isIOSWebKit() {
    const ua = navigator.userAgent;
    return /iPad|iPhone|iPod/.test(ua) && /WebKit/.test(ua);
}

function openPopup(mode, page_context) {
    // iOS WebKit blocks popups, use full-page redirect instead
    if (isIOSWebKit()) {
        window.location.href = url;
        return;
    }

    // Desktop/other browsers: use popup
    popupWindow = window.open(url, "PopupWindow", "width=550,height=640,...");

    // Fallback if popup was blocked
    if (!popupWindow || popupWindow.closed) {
        window.location.href = url;
        return;
    }
}
```

## Key Learnings

1. **ngrok's interstitial** can interfere with external resource loading on mobile browsers
2. **External scripts with `defer`** work correctly on iOS when served properly
3. **Button disabling until scripts load** provides a robust user experience
4. **Event listeners** (via `addEventListener`) are more reliable than inline `onclick` attributes
5. **Popup fallback to redirect** is essential for iOS Safari compatibility

## ngrok Workarounds

ngrok shows an interstitial page for free accounts to prevent phishing attacks. This page blocks external JavaScript file loading because browsers can't add custom headers to `<script src="...">` tags.

### Why iOS Fails but Android Works

**Root Cause: iOS Safari's Intelligent Tracking Prevention (ITP)**

1. **ngrok's interstitial sets a cookie** - When you click "Visit" on the interstitial page, ngrok sets a cookie to remember you've passed the check (valid for 7 days).

2. **iOS Safari blocks/partitions this cookie** - Safari's ITP (Intelligent Tracking Prevention) is enabled by default on iOS and:
   - Blocks third-party cookies by default
   - Partitions cookies between contexts
   - May treat the ngrok cookie as a tracking cookie and block it

3. **Subresource requests fail** - When the browser requests `oauth2.js` or `passkey.js`:
   - The ngrok cookie isn't sent (blocked by ITP)
   - ngrok thinks it's a new session and returns the interstitial HTML
   - Script loading fails

4. **Android Chrome allows the cookie** - Chrome doesn't block third-party cookies by default, so the ngrok session cookie works normally.

5. **iOS Chrome also fails** - All browsers on iOS must use WebKit (Apple's engine), so iOS Chrome has the same ITP restrictions as Safari.

| Browser | Third-party cookies | ngrok works? |
|---------|---------------------|--------------|
| Android Chrome | Allowed by default | Yes |
| Desktop Chrome | Allowed by default | Yes |
| iOS Safari | Blocked by ITP | No |
| iOS Chrome | Blocked by ITP (uses WebKit) | No |

**Conclusion**: It's a combination of ngrok's cookie-based interstitial bypass + iOS Safari's strict privacy controls. There's no workaround for free ngrok on iOS.

#### References
- [Full Third-Party Cookie Blocking and More - WebKit](https://webkit.org/blog/10218/full-third-party-cookie-blocking-and-more/)
- [Third party cookies disabled in Chrome on iOS - Stack Overflow](https://stackoverflow.com/questions/64539850/third-party-cookies-disabled-in-chrome-on-ios)
- [ngrok Free Plan Limits](https://ngrok.com/docs/pricing-limits/free-plan-limits)
- [Ngrok interstitial page blocks requests - Atlassian Developer Community](https://community.developer.atlassian.com/t/ngrok-interstitial-page-blocks-requests/61146)

### Options to Bypass ngrok's Browser Warning

#### 1. Add `ngrok-skip-browser-warning` Header
The client must send a header with any value:
```javascript
fetch(url, {
  headers: {
    'ngrok-skip-browser-warning': '1'
  }
})
```

**Limitation**: This works for `fetch()` requests but **NOT for `<script src="...">` tags** - browsers don't allow custom headers on script tags.

#### 2. Change User-Agent Header
Use a browser extension to change the User-Agent to something non-standard (e.g., `MyApp/0.0.1`).

**Limitation**: Requires installing an extension on the iOS device, which is impractical.

#### 3. Use a Proxy that Adds the Header
Run a Docker proxy like [ngrok-skip-browser-warning](https://github.com/igops/ngrok-skip-browser-warning) that automatically adds the header:
```bash
docker run -d --rm -p 8443:443 -p 8080:80 \
  -e NGROK_HOST=https://your-ngrok-domain.ngrok.io \
  igops/ngrok-skip-browser-warning:latest
```

**Limitation**: Adds complexity to the setup.

#### 4. Upgrade to ngrok Paid Plan
Any paid plan removes the interstitial page entirely.

#### 5. Inline the Scripts
Inline the JavaScript directly in the HTML so there are no external script requests.

**Limitation**: Requires `unsafe-inline` in CSP, less maintainable.

### Recommended Solution

**For `<script src="...">` tags specifically, there's no good free ngrok workaround** because you can't add custom headers to script tags.

Best options:
1. **Use nginx/direct proxy** - Best solution for development and production
2. **Upgrade ngrok to paid plan** - Removes the issue entirely
3. **Inline the scripts** - Works but has CSP implications

### Why nginx Works Perfectly

With nginx (or any direct reverse proxy), there is no issue on any browser including iOS Safari:

1. **No interstitial page** - nginx forwards requests directly to your app
2. **No cookie dependency** - there's no "session cookie" needed to bypass anything
3. **Proper Content-Type** - your app returns `application/javascript` for `.js` files
4. **Works on all browsers** - iOS Safari, iOS Chrome, Android, desktop all work identically

**The issue is entirely ngrok-specific**, not an iOS Safari or code limitation. The application code works correctly; ngrok's free tier anti-phishing mechanism combined with iOS's strict cookie policies (ITP) causes the problem.

### References
- [How to Bypass Ngrok Browser Warning - Stack Overflow](https://stackoverflow.com/questions/73017353/how-to-bypass-ngrok-browser-warning)
- [ngrok - Combating abuse](https://ngrok.com/abuse)
- [ngrok-skip-browser-warning GitHub](https://github.com/igops/ngrok-skip-browser-warning)

## ngrok Alternatives

If you need to expose your local development server for testing on mobile devices, consider these alternatives that don't have ngrok's interstitial page issue:

### 1. Cloudflare Tunnel (Recommended)
- **Free** for up to 50 users
- **No interstitial page** - direct tunneling, no cookie dependency
- Supports custom domains (point your own domain to localhost)
- Auto HTTPS included
- Works with iOS Safari (no ITP issues)

```bash
# Install cloudflared, then:
cloudflared tunnel --url http://localhost:3001
```

### 2. Localtunnel
- **Completely free**, no paid tier
- No sign-up required
- Simple npm-based tool

```bash
npm install -g localtunnel
lt --port 3001
```

### 3. Pinggy
- No download required (SSH-based)
- No sign-up needed
- Free tier has 60-minute timeout

```bash
ssh -p 443 -R0:localhost:3001 a.pinggy.io
```

### 4. localhost.run
- SSH-based, no installation needed
- Simple and quick

```bash
ssh -R 80:localhost:3001 localhost.run
```

### Which to Choose?

**Cloudflare Tunnel** is the best choice for iOS testing because:
- No interstitial or warning pages
- No cookie-based session tracking
- Works with iOS Safari (no ITP issues)
- Free custom domain support

### References
- [awesome-tunneling - GitHub](https://github.com/anderspitman/awesome-tunneling)
- [Top 10 Ngrok alternatives - Pinggy](https://pinggy.io/blog/best_ngrok_alternatives/)
- [ngrok Alternatives - Tailscale](https://tailscale.com/learn/ngrok-alternatives)
- [Cloudflare Tunnel: a free ngrok alternative](https://kyrylo.org/rails/2024/03/31/cloudflare-tunnel-a-free-ngrok-alternative-for-developing-rails-apps-locally.html)

## Testing Recommendations

When testing iOS compatibility:

1. **Use a direct proxy** (nginx, Apache) instead of ngrok for accurate results
2. **If using ngrok**, ensure the browser has passed through the interstitial for all resource types
3. **Verify JavaScript Content-Type** - must be `application/javascript` not `text/html`
4. **Check browser console** for script loading errors

## Files Modified

1. `/home/ktaka/GitHub/oauth2-passkey/oauth2_passkey_axum/templates/login.j2`
   - External script loading with `defer`
   - Buttons start disabled, enabled when scripts ready
   - Event listeners attached via JavaScript (not inline onclick)

2. `/home/ktaka/GitHub/oauth2-passkey/oauth2_passkey_axum/static/oauth2.js`
   - iOS WebKit detection
   - Popup fallback to redirect
   - Script ready signaling

3. `/home/ktaka/GitHub/oauth2-passkey/oauth2_passkey_axum/static/passkey.js`
   - Script ready signaling

## Implementation Status

**Investigation:** Complete (2025-11-27)
**Root Cause Identified:** ngrok interstitial blocking JS files
**Solution Implementation:** Complete
**Testing:** Verified working on iOS Safari/Chrome via nginx proxy
