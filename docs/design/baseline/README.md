# Phase 0 visual baseline

Captured locally from `83eed0a` in `MOCK_MODE` with a throwaway SQLite database and synthetic accounts. The screenshot server has a temporary home, cannot inherit API credentials, and does not load `.env`. These 48 images are a reviewable sample across the main scanner, first-use, public data, profile, and admin views. They contain no customer QR payloads or account data.

The capture script also produced **294 images for 49 view variants** at the same three widths and two themes in ignored `.cache/ui-shots/isolated-final/` in the Phase 0 worktree. The full local manifest validates route, status, rendered theme, and image presence. Run `python scripts/ui_screenshots.py` to regenerate it after installing the development dependencies and Chromium.

This is the unchanged pre-polish UI. Later visual PRs should attach before/after pairs for the views and states they modify. No `?__state=` fixture exists in Phase 0; the mock-only state gallery begins in Phase 3.

| View | Dark 375 | Dark 768 | Dark 1440 | Light 375 | Light 768 | Light 1440 |
| --- | --- | --- | --- | --- | --- | --- |
| Home | [Image](dark/375/home.jpg) | [Image](dark/768/home.jpg) | [Image](dark/1440/home.jpg) | [Image](light/375/home.jpg) | [Image](light/768/home.jpg) | [Image](light/1440/home.jpg) |
| History First Use | [Image](dark/375/history_first_use.jpg) | [Image](dark/768/history_first_use.jpg) | [Image](dark/1440/history_first_use.jpg) | [Image](light/375/history_first_use.jpg) | [Image](light/768/history_first_use.jpg) | [Image](light/1440/history_first_use.jpg) |
| Leaderboard | [Image](dark/375/leaderboard.jpg) | [Image](dark/768/leaderboard.jpg) | [Image](dark/1440/leaderboard.jpg) | [Image](light/375/leaderboard.jpg) | [Image](light/768/leaderboard.jpg) | [Image](light/1440/leaderboard.jpg) |
| Malicious Database | [Image](dark/375/malicious_database.jpg) | [Image](dark/768/malicious_database.jpg) | [Image](dark/1440/malicious_database.jpg) | [Image](light/375/malicious_database.jpg) | [Image](light/768/malicious_database.jpg) | [Image](light/1440/malicious_database.jpg) |
| Go Ghost Guest | [Image](dark/375/go_ghost_guest.jpg) | [Image](dark/768/go_ghost_guest.jpg) | [Image](dark/1440/go_ghost_guest.jpg) | [Image](light/375/go_ghost_guest.jpg) | [Image](light/768/go_ghost_guest.jpg) | [Image](light/1440/go_ghost_guest.jpg) |
| Generate Qr | [Image](dark/375/generate_qr.jpg) | [Image](dark/768/generate_qr.jpg) | [Image](dark/1440/generate_qr.jpg) | [Image](light/375/generate_qr.jpg) | [Image](light/768/generate_qr.jpg) | [Image](light/1440/generate_qr.jpg) |
| Profile | [Image](dark/375/profile.jpg) | [Image](dark/768/profile.jpg) | [Image](dark/1440/profile.jpg) | [Image](light/375/profile.jpg) | [Image](light/768/profile.jpg) | [Image](light/1440/profile.jpg) |
| Admin Dashboard | [Image](dark/375/admin_dashboard.jpg) | [Image](dark/768/admin_dashboard.jpg) | [Image](dark/1440/admin_dashboard.jpg) | [Image](light/375/admin_dashboard.jpg) | [Image](light/768/admin_dashboard.jpg) | [Image](light/1440/admin_dashboard.jpg) |
