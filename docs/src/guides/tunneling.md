# Development Tunneling

When developing OAuth2 and Passkey authentication, you need HTTPS access from external devices (mobile testing) or to satisfy OAuth2 redirect URI requirements. This guide covers tunneling solutions.

## Cloudflare Tunnel (Recommended)

Cloudflare Tunnel provides free, reliable tunneling without interstitial pages.

### Installation

Install cloudflared from [Cloudflare Downloads](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/)

### Quick Start

1. Create a quick tunnel (no account required):

```bash
cloudflared tunnel --url http://localhost:3001
```

2. Note the generated URL (e.g., `https://random-name.trycloudflare.com`)

3. Update your `.env`:

```bash
ORIGIN='https://random-name.trycloudflare.com'
```

4. Update Google OAuth2 redirect URI to `https://random-name.trycloudflare.com/o2p/oauth2/authorized`

5. Start your local server:

```bash
cd demo-both && cargo run
```

### Why Cloudflare Tunnel?

- **No interstitial page** - Direct tunneling without cookie dependencies
- **iOS compatible** - Works reliably on iOS Safari (unlike ngrok free tier)
- **Free** - Quick tunnels require no account
- **Stable** - No session cookie issues

## ngrok

ngrok is a popular alternative but has limitations on iOS.

### Installation

Download from [ngrok.com](https://ngrok.com/download)

### Quick Start

1. Create a tunnel:

```bash
ngrok http 3001
```

2. Note the generated URL (e.g., `https://random-name.ngrok-free.app`)

3. Update your `.env`:

```bash
ORIGIN='https://random-name.ngrok-free.app'
```

4. Update Google OAuth2 redirect URI to `https://random-name.ngrok-free.app/o2p/oauth2/authorized`

5. Start your local server:

```bash
cd demo-both && cargo run
```

### iOS Limitation

**ngrok's free tier does not work on iOS Safari.** The interstitial page requires a cookie that iOS Safari's Intelligent Tracking Prevention (ITP) blocks for subresource requests.

For iOS testing, use Cloudflare Tunnel instead. See [iOS Safari Compatibility](../compatibility/ios-safari.md) for technical details.

### Workaround

Upgrade to ngrok's paid plan, which removes the interstitial page entirely.

## Comparison

| Feature | Cloudflare Tunnel | ngrok (free) |
|---------|-------------------|--------------|
| iOS Safari | Works | Broken |
| Interstitial page | None | Yes |
| Account required | No (quick tunnels) | No |
| Cost | Free | Free |

**Recommendation:** Use Cloudflare Tunnel for all development, especially when testing on iOS devices.
