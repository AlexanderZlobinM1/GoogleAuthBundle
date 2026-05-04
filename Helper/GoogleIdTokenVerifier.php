<?php

namespace MauticPlugin\GoogleAuthBundle\Helper;

class GoogleIdTokenVerifier
{
    private const JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';

    /**
     * @return array<string, mixed>
     */
    public static function verify(string $idToken, string $clientId, string $hostedDomain = '', string $expectedNonce = ''): array
    {
        $token = trim($idToken);
        if ('' === $token || '' === trim($clientId)) {
            throw new \RuntimeException('mautic.integration.googleauth.invalid_token');
        }

        $parts = explode('.', $token);
        if (3 !== count($parts)) {
            throw new \RuntimeException('mautic.integration.googleauth.invalid_token');
        }

        $header  = self::jsonDecode(self::base64UrlDecode($parts[0]));
        $payload = self::jsonDecode(self::base64UrlDecode($parts[1]));

        if ('RS256' !== ($header['alg'] ?? null) || empty($header['kid'])) {
            throw new \RuntimeException('mautic.integration.googleauth.invalid_token');
        }

        $key = self::findJwk((string) $header['kid']);
        $pem = self::jwkToPem($key);

        $signature = self::base64UrlDecode($parts[2]);
        $verified  = openssl_verify($parts[0].'.'.$parts[1], $signature, $pem, OPENSSL_ALGO_SHA256);
        if (1 !== $verified) {
            throw new \RuntimeException('mautic.integration.googleauth.invalid_token');
        }

        self::validateClaims($payload, trim($clientId), trim($hostedDomain), trim($expectedNonce));

        return $payload;
    }

    /**
     * @return array<string, mixed>
     */
    private static function jsonDecode(string $json): array
    {
        $decoded = json_decode($json, true);
        if (!is_array($decoded)) {
            throw new \RuntimeException('mautic.integration.googleauth.invalid_token');
        }

        return $decoded;
    }

    private static function validateClaims(array $claims, string $clientId, string $hostedDomain, string $expectedNonce): void
    {
        $now = time();
        $exp = (int) ($claims['exp'] ?? 0);
        if ($exp < ($now - 60)) {
            throw new \RuntimeException('mautic.integration.googleauth.invalid_token');
        }

        if (isset($claims['nbf']) && (int) $claims['nbf'] > ($now + 60)) {
            throw new \RuntimeException('mautic.integration.googleauth.invalid_token');
        }

        $issuer = trim((string) ($claims['iss'] ?? ''));
        if (!in_array($issuer, ['https://accounts.google.com', 'accounts.google.com'], true)) {
            throw new \RuntimeException('mautic.integration.googleauth.invalid_token');
        }

        $audience = $claims['aud'] ?? null;
        $audValid = is_array($audience)
            ? in_array($clientId, $audience, true)
            : hash_equals($clientId, (string) $audience);
        if (!$audValid) {
            throw new \RuntimeException('mautic.integration.googleauth.invalid_token');
        }

        if ('' !== $expectedNonce && !hash_equals($expectedNonce, (string) ($claims['nonce'] ?? ''))) {
            throw new \RuntimeException('mautic.integration.googleauth.invalid_state');
        }

        $email = trim((string) ($claims['email'] ?? ''));
        if ('' === $email) {
            throw new \RuntimeException('mautic.integration.googleauth.email_missing');
        }

        $emailVerified = $claims['email_verified'] ?? false;
        if (!(true === $emailVerified || 'true' === strtolower((string) $emailVerified))) {
            throw new \RuntimeException('mautic.integration.googleauth.email_unverified');
        }

        $requiredDomain = strtolower(trim($hostedDomain));
        if ('' !== $requiredDomain) {
            $tokenDomain = strtolower(trim((string) ($claims['hd'] ?? '')));
            if (!hash_equals($requiredDomain, $tokenDomain)) {
                throw new \RuntimeException('mautic.integration.googleauth.domain_denied');
            }
        }
    }

    /**
     * @return array<string, mixed>
     */
    private static function findJwk(string $kid): array
    {
        $jwks = self::downloadJwks();
        foreach (($jwks['keys'] ?? []) as $key) {
            if (is_array($key) && hash_equals($kid, (string) ($key['kid'] ?? ''))) {
                return $key;
            }
        }

        throw new \RuntimeException('mautic.integration.googleauth.invalid_token');
    }

    /**
     * @return array<string, mixed>
     */
    private static function downloadJwks(): array
    {
        $headers = [
            'Accept: application/json',
            'User-Agent: mautic-google-auth/1.0',
        ];

        if (function_exists('curl_init')) {
            $ch = curl_init(self::JWKS_URL);
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
            curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
            curl_setopt($ch, CURLOPT_TIMEOUT, 10);
            $body = curl_exec($ch);
            $code = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            curl_close($ch);

            if (is_string($body) && $code >= 200 && $code < 300) {
                return self::jsonDecode($body);
            }
        }

        $context = stream_context_create([
            'http' => [
                'method'  => 'GET',
                'header'  => implode("\r\n", $headers)."\r\n",
                'timeout' => 10,
            ],
        ]);
        $body = @file_get_contents(self::JWKS_URL, false, $context);
        if (!is_string($body) || '' === $body) {
            throw new \RuntimeException('mautic.integration.googleauth.invalid_token');
        }

        return self::jsonDecode($body);
    }

    private static function jwkToPem(array $jwk): string
    {
        if (empty($jwk['n']) || empty($jwk['e'])) {
            throw new \RuntimeException('mautic.integration.googleauth.invalid_token');
        }

        $modulus  = self::base64UrlDecode((string) $jwk['n']);
        $exponent = self::base64UrlDecode((string) $jwk['e']);

        $rsaPublicKey = self::asn1Sequence(
            self::asn1Integer($modulus).
            self::asn1Integer($exponent)
        );

        $algorithmIdentifier = hex2bin('300d06092a864886f70d0101010500');
        if (false === $algorithmIdentifier) {
            throw new \RuntimeException('mautic.integration.googleauth.invalid_token');
        }

        $subjectPublicKeyInfo = self::asn1Sequence(
            $algorithmIdentifier.
            self::asn1BitString($rsaPublicKey)
        );

        return "-----BEGIN PUBLIC KEY-----\n".
            chunk_split(base64_encode($subjectPublicKeyInfo), 64, "\n").
            "-----END PUBLIC KEY-----\n";
    }

    private static function asn1Integer(string $value): string
    {
        $value = ltrim($value, "\x00");
        if ('' === $value) {
            $value = "\x00";
        }
        if (ord($value[0]) > 0x7f) {
            $value = "\x00".$value;
        }

        return "\x02".self::asn1Length(strlen($value)).$value;
    }

    private static function asn1Sequence(string $value): string
    {
        return "\x30".self::asn1Length(strlen($value)).$value;
    }

    private static function asn1BitString(string $value): string
    {
        $value = "\x00".$value;

        return "\x03".self::asn1Length(strlen($value)).$value;
    }

    private static function asn1Length(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $out = '';
        while ($length > 0) {
            $out    = chr($length & 0xff).$out;
            $length = $length >> 8;
        }

        return chr(0x80 | strlen($out)).$out;
    }

    private static function base64UrlDecode(string $value): string
    {
        $remainder = strlen($value) % 4;
        if ($remainder) {
            $value .= str_repeat('=', 4 - $remainder);
        }

        $decoded = base64_decode(strtr($value, '-_', '+/'), true);
        if (false === $decoded) {
            throw new \RuntimeException('mautic.integration.googleauth.invalid_token');
        }

        return $decoded;
    }
}
