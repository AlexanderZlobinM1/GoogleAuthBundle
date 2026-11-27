# Compatibility index

Last synchronized from confirmed workspace evidence: 25 November 2026.

Current release: `1.0.15`. Declared support: Mautic 5.x, 6.x, 7.x; PHP >=8.1.

| Mautic | Status | Confirmed scope |
| --- | --- | --- |
| 5.2.10 | ✓ | Fresh container and integration settings, 6 Sep 2026 |
| 6.0.9 | ✓ | Fresh container and integration settings, 6 Sep 2026 |
| 7.1.3 | ✓ | Fresh container and integration settings, 6 Sep 2026 |
| 7.2.0 | ✓ | Fresh container and integration settings, 6 Sep 2026 |

The 1.0.15 change is limited to login-page alternative-button markup,
separator coordination JavaScript and translations. Joint Mautic 7.2.1
acceptance on 25 November 2026 rendered Google, Mail.ru, Yandex and Passkey
with one localized separator. It does not change the Google authentication
protocol, services, storage or Mautic APIs; earlier compatibility evidence is
inherited.

Composer metadata is intentionally constrained to the verified Mautic minor
branches `5.2.x`, `6.0.x`, `7.1.x` and `7.2.x` (`>=5.2 <5.3 || >=6.0 <6.1
|| >=7.1 <7.3`). Exact checks are recorded on 5.2.10, 6.0.9, 7.1.3, 7.2.0
and the shared separator acceptance on 7.2.1. It does not claim support for
unverified 5.0/5.1, 6.1 or 7.0/7.3 versions through a broad constraint.

Google OAuth/API exchange was not exercised. Update this file and the workspace `../../COMPATIBILITY_INDEX.md` row with every plugin-related change or review.
