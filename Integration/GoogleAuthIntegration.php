<?php

namespace MauticPlugin\GoogleAuthBundle\Integration;

use Mautic\CoreBundle\Form\Type\YesNoButtonGroupType;
use Mautic\PluginBundle\Integration\AbstractIntegration;
use Symfony\Component\Form\Extension\Core\Type\TextType;
use Symfony\Component\Form\Form;
use Symfony\Component\Form\FormBuilder;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class GoogleAuthIntegration extends AbstractIntegration
{
    public const NAME = 'GoogleAuth';

    public const CLIENT_ID_FIELD = 'client_id';

    public const HOSTED_DOMAIN_FIELD = 'hosted_domain';

    public const SHOW_OFFICIAL_BUTTON_FIELD = 'show_official_button';

    public function getName()
    {
        return self::NAME;
    }

    public function getDisplayName()
    {
        return 'Google Auth';
    }

    public function getDescription()
    {
        return '';
    }

    public function getAuthenticationType()
    {
        return 'none';
    }

    public function getIcon()
    {
        return 'plugins/GoogleAuthBundle/Assets/img/googleauth.svg';
    }

    public function getPriority()
    {
        return 10;
    }

    public function getSupportedFeatures()
    {
        return [
            'sso_service',
        ];
    }

    public function getRequiredKeyFields()
    {
        return [
            self::CLIENT_ID_FIELD => 'mautic.integration.googleauth.client_id',
        ];
    }

    /**
     * @param FormBuilder|Form $builder
     * @param array            $data
     * @param string           $formArea
     */
    public function appendToForm(&$builder, $data, $formArea): void
    {
        if ('keys' !== $formArea) {
            return;
        }

        $builder
            ->add(
                self::HOSTED_DOMAIN_FIELD,
                TextType::class,
                [
                    'label'    => 'mautic.integration.googleauth.hosted_domain',
                    'required' => false,
                    'data'     => $data[self::HOSTED_DOMAIN_FIELD] ?? '',
                    'attr'     => [
                        'class'   => 'form-control',
                        'tooltip' => 'mautic.integration.googleauth.hosted_domain.tooltip',
                    ],
                ]
            )
            ->add(
                self::SHOW_OFFICIAL_BUTTON_FIELD,
                YesNoButtonGroupType::class,
                [
                    'label' => 'mautic.integration.googleauth.show_official_button',
                    'data'  => array_key_exists(self::SHOW_OFFICIAL_BUTTON_FIELD, $data)
                        ? (bool) $data[self::SHOW_OFFICIAL_BUTTON_FIELD]
                        : true,
                    'attr'  => [
                        'tooltip' => 'mautic.integration.googleauth.show_official_button.tooltip',
                    ],
                ]
            );
    }

    public function getClientId(): string
    {
        return trim((string) ($this->keys[self::CLIENT_ID_FIELD] ?? ''));
    }

    public function getHostedDomain(): string
    {
        return strtolower(trim((string) ($this->keys[self::HOSTED_DOMAIN_FIELD] ?? '')));
    }

    public function shouldShowOfficialButton(): bool
    {
        if (!array_key_exists(self::SHOW_OFFICIAL_BUTTON_FIELD, $this->keys)) {
            return true;
        }

        return (bool) $this->keys[self::SHOW_OFFICIAL_BUTTON_FIELD];
    }

    public function getAuthCheckUrl(): string
    {
        return $this->router->generate(
            'mautic_sso_login_check',
            ['integration' => self::NAME],
            UrlGeneratorInterface::ABSOLUTE_URL
        );
    }

    public function getAuthStartUrl(): string
    {
        return $this->router->generate(
            'mautic_sso_login',
            ['integration' => self::NAME],
            UrlGeneratorInterface::ABSOLUTE_URL
        );
    }

    public function getJavascriptOrigin(): string
    {
        $parts = parse_url($this->getAuthCheckUrl());
        if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
            return '';
        }

        $origin = $parts['scheme'].'://'.$parts['host'];
        if (!empty($parts['port'])) {
            $origin .= ':'.$parts['port'];
        }

        return $origin;
    }

    public function getFormNotes($section)
    {
        if ('custom' === $section) {
            return [
                'custom'     => true,
                'template'   => '@GoogleAuth/Integration/form.html.twig',
                'parameters' => [
                    'origin'    => $this->getJavascriptOrigin(),
                    'check_url' => $this->getAuthCheckUrl(),
                    'start_url' => $this->getAuthStartUrl(),
                ],
            ];
        }

        return parent::getFormNotes($section);
    }
}
