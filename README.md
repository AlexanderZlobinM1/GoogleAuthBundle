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
5. Optionally set Hosted Domain, for example `example.com`.
6. Publish the plugin.

The Google OAuth client must allow the Mautic login domain as a JavaScript origin.

## Google Cloud setup

This plugin uses Google Identity Services and verifies Google ID tokens on the
Mautic server. It does not use OAuth access tokens, refresh tokens, or a client
secret. The only value you need to copy into Mautic is the Web application
Client ID.

### Create or find the OAuth client

1. Open Google Cloud Console:
   [Google Auth Platform clients](https://console.cloud.google.com/auth/clients).
2. Select the Google Cloud project used for this Mautic installation, or create
   a new project.
3. If the project has no OAuth branding yet, open
   [Branding](https://console.cloud.google.com/auth/branding) and fill in the
   required app name, support email, and authorized domains.
4. Open **Clients** and create a client, or open an existing one.
5. Set **Application type** to **Web application**.
6. In **Authorized JavaScript origins**, add the public origin of your Mautic
   instance. Use only scheme and host, without a path:

   ```text
   https://mautic.example.com
   ```

   Do not add `/s/login`, `/s/sso_login_check/GoogleAuth`, query strings, or
   fragments to the JavaScript origin.

7. **Authorized redirect URIs** are not required for the default plugin flow.
   The plugin uses the Google browser callback and posts the ID token to
   Mautic. Add redirect URIs only if you change the implementation to a redirect
   based OAuth flow.
8. Save the client.

### Copy the value into Mautic

1. In Google Cloud Console, copy the **Client ID** from the Web application
   client. It looks like:

   ```text
   1234567890-abcdef.apps.googleusercontent.com
   ```

2. In Mautic, open **Settings -> Plugins -> Google Auth**.
3. Paste the value into **Google Client ID**.
4. Optional: set **Hosted domain** to a Google Workspace domain, for example
   `example.com`. Leave it empty to allow any verified Google account whose
   email matches an existing Mautic user.
5. Keep **Show official Google button on login page** enabled.
6. Publish the plugin and save.
7. Clear Mautic cache if the login page still shows old settings.

### What happens with tokens

- The Google button loads `https://accounts.google.com/gsi/client` in the
  browser.
- After a successful Google sign-in, Google returns an ID token to the browser.
- The browser posts that ID token to Mautic as `credential`.
- The plugin verifies the token signature and validates `aud`, `iss`, `exp`,
  `email`, `email_verified`, optional `hd`, and the nonce.
- If the Google email equals an existing Mautic user email, that user is signed
  in.

You do not need to copy any Google token into Mautic. You also do not need to
store the downloaded JSON file's `client_secret` in this plugin.

### Troubleshooting

- `origin_mismatch`: the current Mautic origin is not listed in **Authorized
  JavaScript origins** for the same Client ID configured in Mautic.
- Google button does not render: check the Client ID, browser console, content
  security policy, ad blockers, and whether the Mautic page can load
  `https://accounts.google.com/gsi/client`.
- Login returns to the Mautic login page: check that the Google account email is
  verified and exactly matches an active Mautic user email.

### References

- [Google Identity Services setup](https://developers.google.com/identity/gsi/web/guides/get-google-api-clientid)
- [Verify the Google ID token on your server side](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token)
