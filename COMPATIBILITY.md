# Mautic compatibility

Composer-supported Mautic branches are intentionally limited to the verified
minor branches `5.2.x`, `6.0.x`, `7.1.x` and `7.2.x`. Exact checks are recorded
on `5.2.10`, `6.0.9`, `7.1.3`, `7.2.0` and the shared separator acceptance on
`7.2.1`.

Run against each supported Mautic installation with this plugin installed:

```sh
MAUTIC_ROOT=/path/to/mautic php -d memory_limit=1G Tests/runtime-compatibility.php
```

The test compiles an isolated container, instantiates this plugin’s integrations
and form types, then removes its temporary cache. Production cache and provider
settings are not changed. Live external-provider delivery requires a separate
configured acceptance environment; a successful kernel test does not prove delivery.

## Verified on 6 September 2026

Fresh-kernel service instantiation and form construction/resolution passed on
`7.2.0`, `7.1.3`, `6.0.9`, `5.2.10`; the shared separator acceptance also
passed on `7.2.1`. Mautic 5/6 used PHP 8.2.33; Mautic 7 used PHP 8.4.25.
External delivery and OAuth/CAPTCHA provider exchanges were not exercised.
