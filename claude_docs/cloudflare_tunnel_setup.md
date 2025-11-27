# Cloudflare Tunnel Setup Guide

This guide explains how to expose your local development server to the internet using Cloudflare Tunnel, which is a free alternative to ngrok that works reliably on iOS Safari.

## Why Cloudflare Tunnel?

- **No interstitial page** - Unlike ngrok's free tier, no browser warning pages
- **No cookie dependency** - Works with iOS Safari's strict privacy settings (ITP)
- **Free** - Quick tunnels require no account or payment
- **Auto HTTPS** - Secure connections included

## Quick Start (No Account Required)

### Step 1: Install cloudflared

#### Linux (Debian/Ubuntu)

**Option A: Using apt (recommended)**

First, add the GPG key:
```bash
sudo mkdir -p --mode=0755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
```

Then add the repository (choose your distribution):
```bash
# Ubuntu 24.04 (Noble)
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared noble main' | sudo tee /etc/apt/sources.list.d/cloudflared.list

# Ubuntu 22.04 (Jammy)
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared jammy main' | sudo tee /etc/apt/sources.list.d/cloudflared.list

# Ubuntu 20.04 (Focal)
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared focal main' | sudo tee /etc/apt/sources.list.d/cloudflared.list

# Debian 12 (Bookworm)
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared bookworm main' | sudo tee /etc/apt/sources.list.d/cloudflared.list
```

Install cloudflared:
```bash
sudo apt update
sudo apt install cloudflared
```

**Option B: Direct download (works on any Linux)**
```bash
# For Linux amd64
wget https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
chmod +x cloudflared-linux-amd64
sudo mv cloudflared-linux-amd64 /usr/local/bin/cloudflared
```

#### macOS

```bash
brew install cloudflared
```

#### Windows

Download from [cloudflared releases](https://github.com/cloudflare/cloudflared/releases) and add to PATH.

### Step 2: Start Your Local Server

Start your application locally:
```bash
# Example: demo-both on port 3001
cd demo-both && cargo run
```

### Step 3: Create a Quick Tunnel

In a new terminal:
```bash
cloudflared tunnel --url http://localhost:3001
```

You'll see output like:
```
2024-01-15T10:30:00Z INF Thank you for trying Cloudflare Tunnel.
2024-01-15T10:30:00Z INF Your quick Tunnel has been created! Visit it at:
2024-01-15T10:30:00Z INF https://random-words-here.trycloudflare.com
```

### Step 4: Access from iOS

Open the `https://random-words-here.trycloudflare.com` URL on your iOS device. It will work immediately without any interstitial pages or cookie issues.

## Quick Tunnel Limitations

- URL is randomly generated each time you run the command
- Tunnels are temporary (stop when you close the terminal)
- Subject to rate limits for concurrent requests
- Meant for testing/development, not production

## Persistent Tunnels (Optional)

For persistent URLs or custom domains, you need a free Cloudflare account:

### Step 1: Login to Cloudflare

```bash
cloudflared tunnel login
```

This opens a browser to authenticate with your Cloudflare account.

### Step 2: Create a Named Tunnel

```bash
cloudflared tunnel create my-dev-tunnel
```

### Step 3: Configure the Tunnel

Create `~/.cloudflared/config.yml`:
```yaml
tunnel: my-dev-tunnel
credentials-file: /home/username/.cloudflared/<tunnel-id>.json

ingress:
  - hostname: myapp.example.com
    service: http://localhost:3001
  - service: http_status:404
```

### Step 4: Route DNS

```bash
cloudflared tunnel route dns my-dev-tunnel myapp.example.com
```

### Step 5: Run the Tunnel

```bash
cloudflared tunnel run my-dev-tunnel
```

## Comparison with ngrok

| Feature | Cloudflare Tunnel | ngrok (Free) |
|---------|-------------------|--------------|
| Interstitial page | No | Yes |
| iOS Safari support | Yes | No (ITP blocks cookies) |
| Custom domains | Yes (free) | No (paid only) |
| Account required | No (quick tunnels) | Yes |
| HTTPS | Automatic | Automatic |

## Troubleshooting

### Tunnel not starting
- Ensure your local server is running first
- Check the port number matches your application

### Connection refused
- Verify the localhost URL is correct
- Try `http://127.0.0.1:3001` instead of `http://localhost:3001`

### Slow connections
- Quick tunnels route through Cloudflare's global network
- First request may be slower due to tunnel establishment

## References

- [Quick Tunnels - Cloudflare Docs](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/do-more-with-tunnels/trycloudflare/)
- [cloudflared GitHub](https://github.com/cloudflare/cloudflared)
- [Create a locally-managed tunnel - Cloudflare Docs](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/get-started/create-local-tunnel/)
