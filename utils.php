<?php

namespace Ably;

function generateJwt($headers, $payload, $secret = 'secret')
{
    $encodedHeaders = base64urlEncode(json_encode($headers));
    $encodedPayload = base64urlEncode(json_encode($payload));

    $signature = hash_hmac('SHA256', "$encodedHeaders.$encodedPayload", $secret, true);
    $encodedSignature = base64urlEncode($signature);

    return "$encodedHeaders.$encodedPayload.$encodedSignature";
}

function isJwtValid($jwt, $timeFn, $secret = 'secret')
{
    // split the jwt
    $tokenParts = explode('.', $jwt);
    $header = $tokenParts[0];
    $payload = $tokenParts[1];
    $tokenSignature = $tokenParts[2];

    // check the expiration time - note this will cause an error if there is no 'exp' claim in the jwt
    $expiration = json_decode(base64_decode($payload))->exp;
    $isTokenExpired = $expiration <= $timeFn();

    // build a signature based on the header and payload using the secret
    $signature = hash_hmac('SHA256', $header . "." . $payload, $secret, true);
    $isSignatureValid = base64urlEncode($signature) === $tokenSignature;

    return $isSignatureValid && !$isTokenExpired;
}

function parseJwt($jwt)
{
    $tokenParts = explode('.', $jwt);
    $header = json_decode(base64_decode($tokenParts[0]));
    $payload = json_decode(base64_decode($tokenParts[1]));
    return array('header' => $header, 'payload' => $payload);
}

function base64urlEncode($str)
{
    return rtrim(strtr(base64_encode($str), '+/', '-_'), '=');
}
