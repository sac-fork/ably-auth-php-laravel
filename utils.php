<?php

namespace Ably;

function generateJwt($headers, $payload, $secret = 'secret')
{
    $headers_encoded = base64url_encode(json_encode($headers));
    $payload_encoded = base64url_encode(json_encode($payload));

    $signature = hash_hmac('SHA256', "$headers_encoded.$payload_encoded", $secret, true);
    $signature_encoded = base64url_encode($signature);

    return "$headers_encoded.$payload_encoded.$signature_encoded";
}

function isJwtValid($jwt, $timeFn, $secret = 'secret')
{
    // split the jwt
    $tokenParts = explode('.', $jwt);
    $header = $tokenParts[0];
    $payload = $tokenParts[1];
    $signature_provided = $tokenParts[2];

    // check the expiration time - note this will cause an error if there is no 'exp' claim in the jwt
    $expiration = json_decode(base64_decode($payload))->exp;
    $is_token_expired = $expiration <= $timeFn();

    // build a signature based on the header and payload using the secret
    $signature = hash_hmac('SHA256', $header . "." . $payload, $secret, true);
    $is_signature_valid = base64url_encode($signature) === $signature_provided;

    return $is_signature_valid && !$is_token_expired;
}

function parseJwt($jwt)
{
    $tokenParts = explode('.', $jwt);
    $header = json_decode(base64_decode($tokenParts[0]));
    $payload = json_decode(base64_decode($tokenParts[1]));
    return array('header' => $header, 'payload' => $payload);
}

function base64url_encode($str)
{
    return rtrim(strtr(base64_encode($str), '+/', '-_'), '=');
}
