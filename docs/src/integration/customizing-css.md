# Customizing CSS

This page explains how to create your own CSS theme for the built-in UI pages. If you just want to pick a ready-made theme, see [Built-in Themes](themes.md) first.

The built-in pages use CSS Custom Properties (CSS variables) for theming. You can override these variables to change colors, fonts, spacing, and more without modifying the HTML structure.

## Quick Start

1. Create a CSS file with your overrides:

```css
/* static/my-theme.css */
:root {
    --o2p-primary: #ff6b6b;
    --o2p-background: #1a1a2e;
}
```

1. Serve the CSS file from your application (see [Serving Your CSS File](#serving-your-css-file)).

1. Set the environment variable:

```bash
# .env
O2P_CUSTOM_CSS_URL=/static/my-theme.css
```

## CSS Custom Properties Reference

### Colors

| Property | Default | Description |
| -------- | ------- | ----------- |
| `--o2p-primary` | `#4f46e5` | Primary action buttons |
| `--o2p-primary-hover` | `#4338ca` | Primary button hover state |
| `--o2p-oauth2` | `#6366f1` | OAuth2 buttons |
| `--o2p-oauth2-hover` | `#4f46e5` | OAuth2 button hover state |
| `--o2p-passkey` | `#818cf8` | Passkey buttons |
| `--o2p-passkey-hover` | `#6366f1` | Passkey button hover state |
| `--o2p-danger` | `#dc2626` | Delete/danger buttons |
| `--o2p-danger-hover` | `#b91c1c` | Danger button hover state |
| `--o2p-secondary` | `#6b7280` | Secondary/cancel buttons |
| `--o2p-secondary-hover` | `#4b5563` | Secondary button hover state |

### Text

| Property | Default | Description |
| -------- | ------- | ----------- |
| `--o2p-text` | `#111827` | Primary text color |
| `--o2p-text-secondary` | `#4b5563` | Secondary text color |
| `--o2p-text-light` | `#9ca3af` | Light/muted text |

### Backgrounds

| Property | Default | Description |
| -------- | ------- | ----------- |
| `--o2p-background` | `#f9fafb` | Page background |
| `--o2p-surface` | `#ffffff` | Card/container background |
| `--o2p-surface-alt` | `#f3f4f6` | Alternate surface (items) |

### Borders & Radius

| Property | Default | Description |
| -------- | ------- | ----------- |
| `--o2p-border` | `#e5e7eb` | Border color |
| `--o2p-border-light` | `#f3f4f6` | Light border color |
| `--o2p-radius-sm` | `4px` | Small radius (inputs) |
| `--o2p-radius-md` | `6px` | Medium radius (buttons) |
| `--o2p-radius-lg` | `8px` | Large radius (cards) |

### Spacing

| Property | Default | Description |
| -------- | ------- | ----------- |
| `--o2p-space-xs` | `4px` | Extra small spacing |
| `--o2p-space-sm` | `8px` | Small spacing |
| `--o2p-space-md` | `16px` | Medium spacing |
| `--o2p-space-lg` | `24px` | Large spacing |
| `--o2p-space-xl` | `32px` | Extra large spacing |

### Typography

| Property | Default | Description |
| -------- | ------- | ----------- |
| `--o2p-font` | `system-ui, -apple-system, ...` | Font family |
| `--o2p-font-size` | `16px` | Base font size |
| `--o2p-line-height` | `1.6` | Line height |

### Shadows

| Property | Default | Description |
| -------- | ------- | ----------- |
| `--o2p-shadow` | `0 1px 3px rgba(0,0,0,0.08)` | Standard shadow |
| `--o2p-shadow-lg` | `0 4px 12px rgba(0,0,0,0.1)` | Large shadow |

## Serving Your CSS File

Add a route in your application to serve the custom CSS:

```rust,ignore
use axum::{Router, routing::get, response::Response, http::{StatusCode, header::CONTENT_TYPE}};

async fn serve_custom_css() -> Response {
    let css = include_str!("../static/my-theme.css");
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/css")
        .body(css.into())
        .unwrap()
}

let app = Router::new()
    .route("/static/my-theme.css", get(serve_custom_css))
    .merge(oauth2_passkey_full_router());
```

## Credential Type Styling

Passkey and OAuth2 credentials are visually distinguished with colored left borders:

- **Passkey credentials**: Uses `--o2p-passkey` color
- **OAuth2 accounts**: Uses `--o2p-secondary` color

These use CSS classes `.passkey` and `.oauth2` on credential items:

```css
.item.passkey {
    border-left-color: var(--o2p-passkey);
}

.item.oauth2 {
    border-left-color: var(--o2p-secondary);
}
```

## Examples

### Dark Mode

```css
/* dark-theme.css */
:root {
    /* Dark backgrounds */
    --o2p-background: #1a1a2e;
    --o2p-surface: #16213e;
    --o2p-surface-alt: #1f2b47;

    /* Light text */
    --o2p-text: #e4e4e4;
    --o2p-text-secondary: #a0a0a0;
    --o2p-text-light: #6c6c6c;

    /* Darker borders */
    --o2p-border: #0f3460;
    --o2p-border-light: #1a3a5c;

    /* Adjusted shadows for dark mode */
    --o2p-shadow: 0 2px 8px rgba(0, 0, 0, 0.3);
    --o2p-shadow-lg: 0 4px 16px rgba(0, 0, 0, 0.4);
}
```

### Brand Colors

```css
/* brand-theme.css */
:root {
    /* Use your brand's primary color */
    --o2p-primary: #e91e63;
    --o2p-primary-hover: #c2185b;
}

/* Override the login page gradient */
.login-page {
    background: linear-gradient(135deg, #e91e63 0%, #9c27b0 100%);
}
```

### Rounded Style

```css
/* rounded-theme.css */
:root {
    --o2p-radius-sm: 12px;
    --o2p-radius-md: 16px;
    --o2p-radius-lg: 24px;
}
```

## When to Use Templates

CSS customization is sufficient for most branding needs. Consider [template customization](customizing-templates.md) when you need:

- Different page structure or layout
- Additional form fields or sections
- Integration with your existing design system
- Completely different user flow
