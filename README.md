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
6. Leave **Show official Google button on login page** enabled unless you
   intentionally want to hide the button.
7. Publish the plugin by enabling **Active** in the tile and save.

The Google OAuth client must allow the Mautic login domain as a JavaScript origin.

When other alternative login plugins are enabled, the Google button participates
in the shared `mautic-auth-alternative-button` /
`data-mautic-auth-alternative="1"` DOM contract. Its wrapper is marked with
`data-mautic-auth-alternative-block="1"` and carries the translated separator
label. A singleton coordinator leaves one translated separator directly before
the topmost alternative wrapper; the standard Mautic login remains unchanged.

## Google Cloud setup

This plugin uses Google Identity Services and verifies Google ID tokens on the
Mautic server. It does not use OAuth access tokens, refresh tokens, or a client
secret. The only value you need to copy into Mautic is the Web application
Client ID.

### Configure the OAuth consent screen

1. Open Google Cloud Console:
   [Google Auth Platform clients](https://console.cloud.google.com/auth/clients).
2. Select the Google Cloud project used for this Mautic installation, or create
   a new project.
3. Open [Branding](https://console.cloud.google.com/auth/branding), which is
   the current Google Cloud Console location for the OAuth consent screen.
4. Fill in the app name and support email. Select the audience required by your
   organization. If the app is **External** and remains in testing, add the
   Google accounts that are allowed to test it.
5. Add the domain used by Mautic to **Authorized domains**. Use the registrable
   domain, for example `example.com`, not a URL, path, port, or wildcard. The
   domain may need to be verified in Google Search Console before Google lets
   you save it.

### Create or find the OAuth client

1. Open **Clients** in Google Auth Platform and create a client, or open an
   existing one.
2. Set **Application type** to **Web application**.
3. In **Authorized JavaScript origins**, add the public origin of your Mautic
   instance. Use only scheme and host, without a path:

   ```text
   https://mautic.example.com
   ```

   Do not add `/s/login`, `/s/sso_login_check/GoogleAuth`, query strings, or
   fragments to the JavaScript origin.

4. **Authorized redirect URIs** are not required for this plugin's default
   Google Identity Services flow. Google returns the ID token to the browser,
   and the browser POSTs it to the Mautic callback shown in the plugin tile.
   That Mautic callback is an internal token endpoint, not a Google OAuth
   redirect URI. Do not add it to the redirect URI list for this flow.
5. Save the client.

### Copy the value into Mautic

1. In Google Cloud Console, copy the **Client ID** from the Web application
   client. It looks like:

   ```text
   1234567890-abcdef.apps.googleusercontent.com
   ```

2. Google may also display a **Client Secret** or include it in a downloaded
   OAuth client JSON file. This plugin does not use an OAuth client secret:
   it verifies the signed ID token on the Mautic server. Do not paste the
   secret into Mautic, commit it, or place it in the plugin configuration.
3. In Mautic, open **Settings -> Plugins -> Google Auth**.
4. Paste the value into **Google Client ID**.
5. Optional: set **Hosted domain** to a Google Workspace domain, for example
   `example.com`. Leave it empty to allow any verified Google account whose
   email matches an existing Mautic user.
6. Keep **Show official Google button on login page** enabled.
7. Enable **Active**, publish the plugin, and save.
8. Clear Mautic cache if the login page still shows old settings.

### What happens with tokens

- The Google button loads `https://accounts.google.com/gsi/client` in the
  browser.
- After a successful Google sign-in, Google returns an ID token to the browser.
- The browser posts that ID token to Mautic as `credential`.
- The plugin verifies the token signature and validates `aud`, `iss`, `exp`,
  `email`, `email_verified`, optional `hd`, and the nonce.
- If the Google email equals an existing Mautic user email, that user is signed
  in.

You do not need to copy any Google token into Mautic. The downloaded JSON file
is useful as a record of the client, but its `client_secret` is not used by this
plugin and must be kept out of Mautic configuration.

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
