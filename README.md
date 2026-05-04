# GoogleAuthBundle

Google sign-in plugin for Mautic 5, 6, and 7.

The plugin authenticates only existing Mautic users. A Google login succeeds when:

- the plugin is published and configured,
- Google returns a valid signed ID token,
- `aud` matches the configured Google Client ID,
- `iss` is `https://accounts.google.com` or `accounts.google.com`,
- `email_verified` is true,
- the Google email matches an active Mautic user email.

No Mautic user is auto-created.

## Setup

1. Install the bundle into `plugins/GoogleAuthBundle`.
2. Run Mautic plugin discovery/install and clear cache.
3. Open the Google Auth plugin tile.
4. Set Google Client ID.
5. Optionally set Hosted Domain, for example `sales-snap.com`.
6. Publish the plugin.

The Google OAuth client must allow the Mautic login domain as a JavaScript origin.
