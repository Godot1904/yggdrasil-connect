<?php

namespace LittleSkin\YggdrasilConnect\Middleware;

use LittleSkin\YggdrasilConnect\Exceptions\Yggdrasil\ForbiddenOperationException;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Cache;
use Vectorface\Whip\Whip;
use Log;

class UnionHostVerify {
    
    public function handle($request, \Closure $next)
    {
        // IP verification (Disabled in case of CDN)
        /*
        function binaryip($ip)
        {
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
                $ip = inet_pton($ip);
                $binaryIp = '';
                foreach (str_split($ip) as $char) {
                    $binaryIp .= str_pad(decbin(ord($char)), 8, '0', STR_PAD_LEFT);
                }
            } else {
                $ip = ip2long($ip);
                $binaryIp = str_pad(decbin($ip), 32, '0', STR_PAD_LEFT);
            }
            return $binaryIp;
        }

        $records = dns_get_record(parse_url(option('union_api_root'), PHP_URL_HOST), DNS_A + DNS_AAAA);
        $host = array();
        for ($i = 0; $i < count($records); $i++) {
            if ($records[$i]['type'] == 'A') {
                $host[] = binaryip($records[$i]['ip']);
            }
            if ($records[$i]['type'] == 'AAAA') {
                $host[] = binaryip($records[$i]['ipv6']);
            }
        }
        $whip = new Whip();
        $ip = binaryip($whip->getValidIpAddress());

        if (!in_array($ip, $host)) {
            throw new ForbiddenOperationException("Union host verification failure.");
        }
        */

        // Signature verification
        $signature = $request->header('X-Message-Signature');
        $timestamp = $request->header('X-Message-Timestamp');
        $nonce = $request->header('X-Message-Nonce');
        $body = (string) $request->getContent();

        if (!$signature || !$timestamp || !$nonce) {
            throw new ForbiddenOperationException("Union host verification failure.");
        }

        // Prevent replay attack
        if (Cache::has('union_host_signature_'.$nonce)) {
            Log::channel('ygg')->info("Union host verification failure: Invalid nonce.");
            throw new ForbiddenOperationException("Union host verification failure.");
        }
        if ((int) $timestamp < time() - 10 || (int) $timestamp > time() + 30) {
            Log::channel('ygg')->info("Union host verification failure: Invalid timestamp.");
            throw new ForbiddenOperationException("Union host verification failure.");
        }

        // Verify signature
        $apiRoot = rtrim((string) option('union_api_root'), '/');
        if ($apiRoot === '') {
            throw new ForbiddenOperationException("Union host verification failure.");
        }

        try {
            $public_key = Http::timeout(5.0)->get($apiRoot)->json('union_host_signature_public_key');
        } catch (\Throwable $e) {
            Log::channel('ygg')->info("Union host verification failure: Unable to fetch public key.");
            throw new ForbiddenOperationException("Union host verification failure.");
        }
        $decoded_signature = base64_decode($signature, true);

        if (!is_string($public_key) || $public_key === '' || $decoded_signature === false) {
            throw new ForbiddenOperationException("Union host verification failure.");
        }

        if (openssl_verify($body.$timestamp.$nonce, $decoded_signature, $public_key, OPENSSL_ALGO_SHA256) != 1) {
            Log::channel('ygg')->info("Union host verification failure: Invalid signature.");
            throw new ForbiddenOperationException("Union host verification failure.");
        }

        // Cache nonce for 60 seconds
        Cache::put('union_host_signature_'.$nonce, $signature, 60);

        return $next($request);
    }
}