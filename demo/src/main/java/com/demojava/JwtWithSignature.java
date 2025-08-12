package com.demojava;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import javax.crypto.SecretKey;
import java.util.Base64;
import java.util.Date;

public class JwtWithSignature {
    public static void main(String[] args) {

        // Generate an HS256 key
        SecretKey key = Jwts.SIG.HS256.key().build();

        // Base64URL encode the key for jwt.io display
        String base64UrlKey = Base64.getUrlEncoder().withoutPadding().encodeToString(key.getEncoded());
        System.out.println("Signature Key: " + base64UrlKey);

        Date now = new Date();
        Date expiration = new Date(now.getTime() + 3600_000); // 1 hour

        // Create JWT
        String jws = Jwts.builder()
                .issuer("me")
                .subject("Bob")
                .audience().add("you").and()
                .expiration(expiration)
                .notBefore(now)
                .issuedAt(now)
                .id("1")
                .signWith(key)
                .compact();

        System.out.println("JWT: " + jws);

        // Parse & verify
        Claims claims = Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(jws)
                .getPayload();

        System.out.println("Issuer: " + claims.getIssuer());
        System.out.println("Subject: " + claims.getSubject());
        System.out.println("Audience: " + claims.getAudience());
        System.out.println("Expiration: " + claims.getExpiration());
        System.out.println("Not Before: " + claims.getNotBefore());
        System.out.println("Issued At: " + claims.getIssuedAt());
        System.out.println("JWT ID: " + claims.getId());
    }
}
