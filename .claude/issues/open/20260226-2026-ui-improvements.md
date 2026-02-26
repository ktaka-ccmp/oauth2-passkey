# Issue: UI Improvements

## Table of Contents

- [Description](#description)
- [Related Issues](#related-issues)
- [Approach](#approach)
- [Related Files](#related-files)
- [Implementation Tasks](#implementation-tasks)
- [Decision Log](#decision-log)
- [Resolution](#resolution)

## ID: 20260226-2026

## Created: 2026-02-26

## Closed:

## Status: open

## Priority: low

## Difficulty: large

## Description

Improve the built-in UI components for better user experience and accessibility. The current UI uses browser-native `alert()` and `confirm()` dialogs, lacks accessibility features, and could benefit from modern CSS patterns.

### Already Implemented (v0.3.0)

- 9 pre-built CSS themes (Zinc, Slate, Blue, Violet, Rose, Neumorphism, Material, Eco, SaaS)
- `O2P_CUSTOM_CSS_URL` for custom theme loading
- Responsive mobile layout for admin user list

### Remaining Improvements

#### Critical (User Trust and Accessibility)
- Replace `alert()` dialogs with toast/snackbar notification system
- Add accessibility features: ARIA labels, keyboard navigation, focus management
- Implement inline form validation instead of alert-based error handling
- Add loading indicators (spinners/progress bars) for async operations

#### High Priority (Modern UX)
- Improve responsive design: tablet breakpoints, mobile modal handling
- Create confirmation dialogs for destructive actions (replace `confirm()`)

#### Medium Priority (Polish)
- Smooth CSS transitions for modals and state changes
- Better mobile experience: larger tap targets, optimized forms
- User-friendly error messages replacing technical errors

### Design Principles

- **No heavy JS frameworks** (React/Vue/Svelte) -- keep the library lightweight
- **Modern CSS** for most improvements (custom properties, Grid/Flexbox, animations)
- **Minimal JS**: Consider tiny libraries like Notyf (4KB) for toast notifications
- **Keep vanilla JS** for critical authentication flows

## Related Issues

None

## Approach

Incremental improvements prioritized by impact. Start with accessibility and alert replacement since these affect all users. Use modern CSS features (already have custom properties via theme system) and minimal JavaScript additions.

## Related Files

- `oauth2_passkey_axum/src/assets/` - CSS and JavaScript files
- `oauth2_passkey_axum/src/templates/` - HTML templates (Jinja2)
- `oauth2_passkey_axum/src/assets/css/` - Theme CSS files

## Implementation Tasks

- [ ] Replace `alert()` with toast/snackbar notifications
- [ ] Replace `confirm()` with styled confirmation dialogs
- [ ] Add ARIA labels and roles to all interactive elements
- [ ] Add keyboard navigation support
- [ ] Implement inline form validation
- [ ] Add loading indicators for async operations
- [ ] Improve responsive design for tablets
- [ ] Add CSS transitions for modals and state changes
- [ ] Improve mobile tap targets and form usability
- [ ] Replace technical error messages with user-friendly text

## Decision Log

### 2026-02-26: Migrated from ToDo.md

- Context: Migrating incomplete tasks from ToDo.md to issue tracking system
- Decision: Bundle all UI improvements into a single issue; low priority
- Reason: The built-in UI is functional and themed. These are polish improvements that can be done incrementally. Individual sub-tasks can be split into separate issues if needed

## Resolution
