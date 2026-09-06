<?php

declare(strict_types=1);

use Mautic\CoreBundle\DependencyInjection\MauticCoreExtension;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

return function (ContainerConfigurator $configurator): void {
    $services = $configurator->services()
        ->defaults()
        ->autowire()
        ->autoconfigure()
        ->public();

    $excludes = [
        'Assets',
        'DependencyInjection',
        'EventListener',
        'Integration',
        'Resources',
        'Tests',
        'Translations',
    ];

    // Legacy config.php treats FQCN arguments as strings, not service references.
    $services->alias('googleauthbundle.helper.encryption', \Mautic\CoreBundle\Helper\EncryptionHelper::class);

    $services->load('MauticPlugin\\GoogleAuthBundle\\', '../')
        ->exclude('../{'.implode(',', array_merge(MauticCoreExtension::DEFAULT_EXCLUDES, $excludes)).'}');
};
