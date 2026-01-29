# Built-in Themes

The library ships with 9 pre-built CSS themes. To apply a theme, set a single environment variable -- no custom CSS files or additional code needed.

## Quick Start

```bash
# .env
O2P_CUSTOM_CSS_URL=/o2p/themes/theme-zinc.css
```

## Available Themes

Themes are served at `{O2P_ROUTE_PREFIX}/themes/` (default prefix: `/o2p`).

| Theme | URL Path | Style |
| ----- | -------- | ----- |
| Zinc | `/o2p/themes/theme-zinc.css` | Neutral zinc palette |
| Slate | `/o2p/themes/theme-slate.css` | Cool slate gray palette |
| Blue | `/o2p/themes/theme-blue.css` | Primary blue palette |
| Violet | `/o2p/themes/theme-violet.css` | Elegant violet palette |
| Rose | `/o2p/themes/theme-rose.css` | Warm rose palette |
| Neumorphism | `/o2p/themes/theme-neumorphism.css` | Soft shadows creating depth |
| Material | `/o2p/themes/theme-material.css` | Google Material design principles |
| Eco | `/o2p/themes/theme-eco.css` | Nature-inspired green tones |
| SaaS | `/o2p/themes/theme-saas.css` | Stripe-inspired purple accents |

> **Note:** If you use a custom `O2P_ROUTE_PREFIX`, replace `/o2p` in the paths accordingly.

## Theme Types

### Variable-only themes

**Zinc, Slate, Blue, Violet, Rose**

These themes override `:root` CSS variables and a few selectors like the `.login-page` background gradient. They are lightweight and predictable -- the page structure and layout remain identical to the default.

### Extended themes

**Neumorphism, Material, Eco, SaaS**

These themes override CSS variables and add additional CSS rules for borders, shadows, gradients, and other visual effects. They produce a more distinctive look.

## Further Customization

If the built-in themes don't match your needs, you can create your own CSS file. See [Customizing CSS](customizing-css.md) for the full CSS Custom Properties reference and examples.
