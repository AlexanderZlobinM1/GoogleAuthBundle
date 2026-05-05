<?php

namespace MauticPlugin\GoogleAuthBundle\EventListener;

use Doctrine\ORM\EntityManagerInterface;
use Mautic\PluginBundle\Helper\IntegrationHelper;
use Mautic\UserBundle\Entity\User;
use Mautic\UserBundle\Event\AuthenticationEvent;
use Mautic\UserBundle\UserEvents;
use MauticPlugin\GoogleAuthBundle\Helper\GoogleIdTokenVerifier;
use MauticPlugin\GoogleAuthBundle\Integration\GoogleAuthIntegration;
use Psr\Log\LoggerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Contracts\Translation\TranslatorInterface;

class GoogleAuthSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private IntegrationHelper $integrationHelper,
        private RouterInterface $router,
        private TranslatorInterface $translator,
        private EntityManagerInterface $entityManager,
        private LoggerInterface $logger,
    ) {
    }

    public static function getSubscribedEvents(): array
    {
        return [
            UserEvents::USER_PRE_AUTHENTICATION => ['onUserPreAuthentication', 0],
            KernelEvents::RESPONSE              => ['onKernelResponse', 0],
        ];
    }

    public function onUserPreAuthentication(AuthenticationEvent $event): void
    {
        if (GoogleAuthIntegration::NAME !== (string) $event->getAuthenticatingService()) {
            return;
        }

        $integration = $this->getReadyIntegration();
        if (!$integration instanceof GoogleAuthIntegration) {
            $this->fail($event, 'mautic.integration.googleauth.misconfigured');

            return;
        }

        if (!$event->isLoginCheck()) {
            $event->setResponse($this->renderStartResponse($event->getRequest(), $integration));

            return;
        }

        $request    = $event->getRequest();
        $credential = trim((string) ($request->request->get('credential') ?: $request->request->get('id_token')));
        $nonce      = trim((string) $request->getSession()->get('googleauth_nonce', ''));
        $request->getSession()->remove('googleauth_nonce');

        if ('' === $credential || '' === $nonce) {
            $this->fail($event, 'mautic.integration.googleauth.invalid_state');

            return;
        }

        try {
            $claims = GoogleIdTokenVerifier::verify(
                $credential,
                $integration->getClientId(),
                $integration->getHostedDomain(),
                $nonce
            );
        } catch (\Throwable $e) {
            $this->logger->warning('Google Auth token verification failed: '.$e->getMessage());
            $this->fail($event, $e->getMessage());

            return;
        }

        $email = strtolower(trim((string) ($claims['email'] ?? '')));
        if ('' === $email) {
            $this->fail($event, 'mautic.integration.googleauth.email_missing');

            return;
        }

        try {
            $user = $this->loadUserByEmail($event, $email);
        } catch (\Throwable $e) {
            $this->logger->info('Google Auth user lookup failed for '.$email.': '.$e->getMessage());
            $this->fail($event, 'mautic.integration.googleauth.not_authorized');

            return;
        }

        $mauticEmail = strtolower(trim((string) $user->getEmail()));
        if (!hash_equals($email, $mauticEmail)) {
            $this->fail($event, 'mautic.integration.googleauth.email_mismatch');

            return;
        }

        $event->setIsAuthenticated(GoogleAuthIntegration::NAME, $user, false);
    }

    public function onKernelResponse(ResponseEvent $event): void
    {
        if (method_exists($event, 'isMainRequest') && !$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        if ('login' !== (string) $request->attributes->get('_route') || $request->isXmlHttpRequest()) {
            return;
        }

        $integration = $this->getReadyIntegration();
        if (!$integration instanceof GoogleAuthIntegration || !$integration->shouldShowOfficialButton()) {
            return;
        }

        $response = $event->getResponse();
        if (200 !== $response->getStatusCode()) {
            return;
        }

        $contentType = (string) $response->headers->get('Content-Type', '');
        if ('' !== $contentType && false === stripos($contentType, 'html')) {
            return;
        }

        $content = (string) $response->getContent();
        if ('' === $content || false !== strpos($content, 'googleauth-login-block')) {
            return;
        }

        $block = $this->renderButtonBlock($request, $integration, false);
        $pos   = stripos($content, '</form>');
        if (false === $pos) {
            $content = str_ireplace('</body>', $block.'</body>', $content);
        } else {
            $content = substr_replace($content, '</form>'.$block, $pos, 7);
        }
        $content = $this->removeStandardSsoLink($content);

        $response->setContent($content);
    }

    private function getReadyIntegration(): ?GoogleAuthIntegration
    {
        $integration = $this->integrationHelper->getIntegrationObject(GoogleAuthIntegration::NAME);
        if (!$integration instanceof GoogleAuthIntegration) {
            return null;
        }

        $settings = $integration->getIntegrationSettings();
        $published = false;
        if (is_object($settings)) {
            if (method_exists($settings, 'isPublished')) {
                $published = (bool) $settings->isPublished();
            } elseif (method_exists($settings, 'getIsPublished')) {
                $published = (bool) $settings->getIsPublished();
            }
        }

        if (!$published || !$integration->isConfigured()) {
            return null;
        }

        $features = method_exists($settings, 'getSupportedFeatures') ? (array) $settings->getSupportedFeatures() : [];
        if (!in_array('sso_service', $features, true)) {
            return null;
        }

        return $integration;
    }

    private function loadUserByEmail(AuthenticationEvent $event, string $email): User
    {
        $user = $this->entityManager->getRepository(User::class)->findOneBy(['email' => $email]);
        if (!$user instanceof User) {
            throw new \RuntimeException('Mautic user not found');
        }

        $identifier = $this->getUserIdentifier($user, $email);
        $provider = $event->getUserProvider();
        if (method_exists($provider, 'loadUserByIdentifier')) {
            $providerUser = $provider->loadUserByIdentifier($identifier);
        } else {
            $providerUser = $provider->loadUserByUsername($identifier);
        }

        if (!$providerUser instanceof User || !$this->isSameUser($user, $providerUser)) {
            throw new \RuntimeException('Mautic user not found');
        }

        return $providerUser;
    }

    private function getUserIdentifier(User $user, string $fallback): string
    {
        foreach (['getUserIdentifier', 'getUsername'] as $method) {
            if (method_exists($user, $method)) {
                $identifier = trim((string) $user->{$method}());
                if ('' !== $identifier) {
                    return $identifier;
                }
            }
        }

        return $fallback;
    }

    private function isSameUser(User $expected, User $actual): bool
    {
        if (method_exists($expected, 'getId') && method_exists($actual, 'getId')) {
            return (string) $expected->getId() === (string) $actual->getId();
        }

        return hash_equals(
            strtolower(trim((string) $expected->getEmail())),
            strtolower(trim((string) $actual->getEmail()))
        );
    }

    private function fail(AuthenticationEvent $event, string $message): void
    {
        $translated = $this->translator->trans($message);
        $event->setFailedAuthenticationMessage($translated);

        $request = $event->getRequest();
        if ($request->hasSession()) {
            $request->getSession()->getFlashBag()->add('error', $translated);
        }

        $event->setResponse(new RedirectResponse($this->router->generate('login')));
    }

    private function renderStartResponse(Request $request, GoogleAuthIntegration $integration): Response
    {
        $title = $this->translator->trans('mautic.integration.googleauth.login_title');
        $intro = $this->translator->trans('mautic.integration.googleauth.login_intro');
        $body  = $this->renderButtonBlock($request, $integration, true);

        $html = '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'.
            '<title>'.$this->e($title).'</title>'.
            '<style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#f4f6f8;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;color:#1f2933}.googleauth-card{width:min(420px,calc(100vw - 32px));background:#fff;border:1px solid #d9e2ec;border-radius:8px;padding:28px;box-shadow:0 16px 42px rgba(31,41,51,.12)}h1{font-size:22px;line-height:1.25;margin:0 0 8px}.googleauth-intro{font-size:14px;color:#52606d;margin:0 0 20px}.googleauth-error{margin-top:12px;color:#b42318;font-size:13px}.googleauth-loading{color:#52606d;font-size:13px}</style>'.
            '</head><body><main class="googleauth-card"><h1>'.$this->e($title).'</h1><p class="googleauth-intro">'.$this->e($intro).'</p>'.$body.'</main></body></html>';

        return new Response($html);
    }

    private function renderButtonBlock(Request $request, GoogleAuthIntegration $integration, bool $standalone): string
    {
        $nonce = bin2hex(random_bytes(16));
        $request->getSession()->set('googleauth_nonce', $nonce);

        $buttonId = 'googleauth-button-'.bin2hex(random_bytes(4));
        $formId   = 'googleauth-form-'.bin2hex(random_bytes(4));
        $inputId  = 'googleauth-credential-'.bin2hex(random_bytes(4));
        $errorId  = 'googleauth-error-'.bin2hex(random_bytes(4));

        $checkUrl = $this->router->generate('mautic_sso_login_check', ['integration' => GoogleAuthIntegration::NAME]);
        $loading  = $this->translator->trans('mautic.integration.googleauth.loading');
        $error    = $this->translator->trans('mautic.integration.googleauth.unavailable');

        $style = $standalone ? '' : '<style>.googleauth-login-block{clear:both;margin:14px 0 0}.googleauth-sep{font-size:11px;color:#6b7280;text-align:center;margin:10px 0}.googleauth-login-block .googleauth-error{margin-top:8px;color:#b42318;font-size:12px}.googleauth-login-block .googleauth-loading{font-size:12px;color:#6b7280;text-align:center}</style>';

        $script = '<script>(function(){'.
            'var clientId='.$this->js($integration->getClientId()).';'.
            'var hostedDomain='.$this->js($integration->getHostedDomain()).';'.
            'var nonce='.$this->js($nonce).';'.
            'var buttonId='.$this->js($buttonId).';'.
            'var formId='.$this->js($formId).';'.
            'var inputId='.$this->js($inputId).';'.
            'var errorId='.$this->js($errorId).';'.
            'var unavailable='.$this->js($error).';'.
            'var sdkSrc="https://accounts.google.com/gsi/client";'.
            'var initialized=false;'.
            'function showError(message){var el=document.getElementById(errorId);if(el){el.textContent=message||unavailable;}}'.
            'function submitCredential(response){if(!response||!response.credential){showError(unavailable);return;}var input=document.getElementById(inputId);var form=document.getElementById(formId);if(!input||!form){showError(unavailable);return;}input.value=response.credential;form.submit();}'.
            'function hasGoogle(){return !!(window.google&&google.accounts&&google.accounts.id);}'.
            'function init(){if(initialized){return true;}if(!hasGoogle()){return false;}try{var cfg={client_id:clientId,callback:submitCredential,nonce:nonce};if(hostedDomain){cfg.hosted_domain=hostedDomain;}google.accounts.id.initialize(cfg);var target=document.getElementById(buttonId);if(target){target.innerHTML="";google.accounts.id.renderButton(target,{theme:"outline",size:"large",type:"standard",shape:"rectangular",text:"signin_with",width:320});}initialized=true;return true;}catch(e){showError(unavailable);initialized=true;return true;}}'.
            'function boot(){if(init()){return;}var done=false;function ready(){if(done){return;}if(init()){done=true;}}function fail(){if(!done){showError(unavailable);done=true;}}var script=document.querySelector("script[data-googleauth-gsi]")||document.querySelector("script[src^=\\""+sdkSrc+"\\"]");if(script){script.addEventListener("load",ready,{once:true});script.addEventListener("error",fail,{once:true});}else{script=document.createElement("script");script.src=sdkSrc;script.async=true;script.defer=true;script.setAttribute("data-googleauth-gsi","1");script.onload=ready;script.onerror=fail;(document.head||document.documentElement).appendChild(script);}var attempts=0;var timer=window.setInterval(function(){attempts++;if(init()){window.clearInterval(timer);done=true;}else if(attempts>=60){window.clearInterval(timer);fail();}},250);}'.
            'if(document.readyState==="loading"){document.addEventListener("DOMContentLoaded",boot,{once:true});}else{boot();}'.
            '}());</script>';

        return $style.
            '<div class="googleauth-login-block">'.
            (!$standalone ? '<div class="googleauth-sep">or</div>' : '').
            '<div id="'.$this->e($buttonId).'" class="googleauth-loading">'.$this->e($loading).'</div>'.
            '<div id="'.$this->e($errorId).'" class="googleauth-error" aria-live="polite"></div>'.
            '<form id="'.$this->e($formId).'" method="post" action="'.$this->e($checkUrl).'" style="display:none">'.
            '<input id="'.$this->e($inputId).'" type="hidden" name="credential" value="">'.
            '</form>'.
            '</div>'.$script;
    }

    private function removeStandardSsoLink(string $content): string
    {
        $path = $this->router->generate('mautic_sso_login', ['integration' => GoogleAuthIntegration::NAME]);
        $pattern = '#\s*<a\s+href="'.preg_quote($path, '#').'"[^>]*>.*?</a>#is';
        $updated = preg_replace($pattern, '', $content, 1);

        return is_string($updated) ? $updated : $content;
    }

    private function e(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    private function js(string $value): string
    {
        return (string) json_encode($value, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_AMP | JSON_HEX_QUOT);
    }
}
