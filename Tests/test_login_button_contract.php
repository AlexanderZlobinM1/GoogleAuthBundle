<?php

declare(strict_types=1);

$source = file_get_contents(dirname(__DIR__).'/EventListener/GoogleAuthSubscriber.php');
if (false === $source) {
    throw new RuntimeException('Unable to read Google Auth subscriber.');
}

$required = [
    'shared alternative-login class'       => 'mautic-auth-alternative-button',
    'shared alternative-login data marker' => 'data-mautic-auth-alternative="1"',
    'shared alternative-login wrapper'     => 'data-mautic-auth-alternative-block="1"',
    'localized separator label'            => 'data-mautic-auth-separator-label=',
    'shared separator class'               => 'mautic-auth-alternative-separator',
    'shared separator data marker'         => 'data-mautic-auth-alternative-separator="1"',
    'global coordinator'                   => 'MauticAuthAlternativeCoordinator',
    'DOM-order top wrapper'                => 'var topBlock=blocks[0]',
    'duplicate cleanup'                   => 'remove(separators[duplicateIndex])',
    'separator relocation'                => 'insertBefore(separatorNode,topBlock)',
    'repeat DOM initialization support'    => 'MutationObserver',
];

foreach ($required as $name => $needle) {
    if (!str_contains($source, $needle)) {
        throw new RuntimeException('Missing '.$name.' contract.');
    }
}

foreach (['googleauth-sep', '>or</div>', 'data-mautic-auth-separator="1"'] as $forbidden) {
    if (str_contains($source, $forbidden)) {
        throw new RuntimeException('Google Auth still owns a local hard-coded separator: '.$forbidden);
    }
}

$translations = [
    'en_US' => 'or',
    'ru'    => 'или',
    'sr_RS' => 'ili',
];

foreach ($translations as $locale => $expectedSeparator) {
    $path = dirname(__DIR__).'/Translations/'.$locale.'/messages.ini';
    $values = parse_ini_file($path, false, INI_SCANNER_RAW);
    if (!is_array($values)) {
        throw new RuntimeException('Unable to parse '.$locale.' translations.');
    }

    if (($values['mautic.integration.googleauth.login_separator'] ?? null) !== $expectedSeparator) {
        throw new RuntimeException('Wrong separator translation for '.$locale.'.');
    }
}

echo "Google Auth alternative-login contract tests passed\n";
