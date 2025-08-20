package com.demojava;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;

public class JwtWithKeyPair {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Load keystore
        KeyStore keyStore = KeyStore.getInstance("BCFKS", "BC");
        try (InputStream is = JwtWithKeyPair.class.getClassLoader().getResourceAsStream("keystore.p12")) {
            keyStore.load(is, "F#qj/W43KCI>z;oyJgA5".toCharArray());
        }

        // Extract key-pair
        String alias = "access-token-key";
        String aliasPassword = "Passw0rd";
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(aliasPassword.toCharArray()));
        if (privateKeyEntry == null) {
            throw new KeyStoreException("Alias not found: " + alias);
        }

        PrivateKey privateKey = privateKeyEntry.getPrivateKey();
        PublicKey publicKey = privateKeyEntry.getCertificate().getPublicKey();
        Certificate certificate = privateKeyEntry.getCertificate();

        // Encode keys as Base64
        String privateKeyBase64 = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        String publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String cert = Base64.getEncoder().encodeToString(certificate.getEncoded());

        // Output results
        System.out.println("Private Key (Base64): " + privateKeyBase64);
        System.out.println("Public Key (Base64): " + publicKeyBase64);
        System.out.println("Certificate (Base64): " + cert);

        // Generate JWT
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
        Date expiry = new Date(nowMillis + 3600_000);

        String jws = Jwts.builder()
                .issuer("me")
                .subject("Bob")
                .audience().add("you").and()
                .expiration(expiry)
                .notBefore(now)
                .issuedAt(now)
                .id("1")
                .signWith(privateKey)
                .compact();
        System.out.println("JWT: " + jws);

        // Verify JWT
        Claims claims = Jwts.parser()
                .verifyWith(publicKey)
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


// Verify JWT
//        try {
//                Jwts.parser()
//                    .setSigningKey(publicKey)
//                    .parseClaimsJws(jwt);
//            System.out.println("JWT Verification: Valid");
//        } catch (Exception e) {
//        System.out.println("JWT Verification: Invalid - " + e.getMessage());
//        }