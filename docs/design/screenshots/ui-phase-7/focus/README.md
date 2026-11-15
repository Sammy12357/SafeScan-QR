# Fraud review keyboard focus

The unassigned fraud row has no action control. At 375 CSS px its table scrolls horizontally, so the containing card is keyboard focusable. These synthetic dark and light captures show the visible focus ring:

- [Dark, 375 px](dark/375/admin_fraud_unassigned_focused.jpg)
- [Light, 375 px](light/375/admin_fraud_unassigned_focused.jpg)

Axe reported zero WCAG 2/2.1/2.2 A/AA violations at 375, 768, and 1440 px in both themes. At 375 px, Tab reached the card and ArrowRight scrolled it from 0 to 40 px.
