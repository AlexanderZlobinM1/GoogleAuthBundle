<?php

$mauticMajor = (int) (new \Mautic\CoreBundle\Helper\AppVersion())->getVersion();

return [
    'name'        => 'Google Auth',
    'description' => 'Google sign-in for existing Mautic users matched by email.',
    'version'     => '1.0.16',
    'author'      => 'Sales Snap',
    'services'    => [
        'events' => [
            'plugin.googleauth.auth_subscriber' => [
                'class'     => MauticPlugin\GoogleAuthBundle\EventListener\GoogleAuthSubscriber::class,
                'arguments' => [
                    'mautic.helper.integration',
                    'router',
                    'translator',
                    'doctrine.orm.entity_manager',
                    'logger',
                ],
            ],
        ],
        'integrations' => [
            'mautic.integration.googleauth' => [
                'class'     => MauticPlugin\GoogleAuthBundle\Integration\GoogleAuthIntegration::class,
                'arguments' => [
                    'event_dispatcher',
                    'mautic.helper.cache_storage',
                    'doctrine.orm.entity_manager',
                    ...($mauticMajor < 6 ? ['session'] : []),
                    'request_stack',
                    'router',
                    'translator',
                    'logger',
                    'googleauthbundle.helper.encryption',
                    'mautic.lead.model.lead',
                    'mautic.lead.model.company',
                    'mautic.helper.paths',
                    'mautic.core.model.notification',
                    'mautic.lead.model.field',
                    'mautic.plugin.model.integration_entity',
                    'mautic.lead.model.dnc',
                    ...($mauticMajor >= 6 ? ['mautic.lead.field.fields_with_unique_identifier'] : []),
                ],
            ],
        ],
    ],
];
