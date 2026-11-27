# Changelog

## 1.0.15 — 2026-11-25

- Mark the Google alternative login button with the shared Mautic auth-button
  contract so it can coexist with Passkey, Mail.ru and Yandex buttons.
- Coordinate one translated separator before the topmost alternative button;
  duplicate separators are removed after repeated or AJAX DOM initialization.
- Add the separator translation to `en_US`, `ru` and `sr_RS`.
- Add Packagist-ready Composer metadata and constrain installation to the
  verified Mautic 5.2.x, 6.0.x, 7.1.x and 7.2.x branches.

## 1.0.14 — 2026-09-06

- Support Mautic 7.2 while retaining the declared older Mautic versions.
- Use a plugin-scoped EncryptionHelper service alias; keep legacy argument parsing and the global core container unchanged.
- Add a fresh-kernel regression check that instantiates integration services and resolves form types.
- Preserve the Mautic 5 session constructor argument and correctly recognize two-digit patch versions such as 5.2.10.


## 1.0.13 - 2026-08-30

- Added Serbian Latin (`sr_RS`) translations for the Google Auth plugin.

## 1.0.12 - 2026-08-30

- Clarified the Google Cloud Console setup for the OAuth consent screen,
  authorized domains, JavaScript origins, internal Mautic callback, redirect
  URIs, Client ID, and unused Client Secret.
- Documented the plugin tile's **Active** and official-button settings.

## 1.0.11 - 2026-07-06

- Unified the Sales Snap settings footer and retained the copy controls for the
  JavaScript origin and Mautic callback.
