package com.demojava;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.SecretKey;
import java.io.InputStream;
import java.security.*;
import java.util.Base64;

public class JwtWithSecreteKey {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Load keystore
        KeyStore keyStore = KeyStore.getInstance("BCFKS", "BC");
        try (InputStream is = JwtWithSecreteKey.class.getClassLoader().getResourceAsStream("keystore.p12")) {
            keyStore.load(is, "F#qj/W43KCI>z;oyJgA5".toCharArray());
        }

        // Extract key-pairs
        String alias = "access-token-secret-key";
        String aliasPassword = "Passw0rd";
        KeyStore.SecretKeyEntry secretKeyEntry = (KeyStore.SecretKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(aliasPassword.toCharArray()));
        SecretKey secretKey = secretKeyEntry.getSecretKey();
        System.out.println("Secret Key: " + Base64.getEncoder().encodeToString(secretKey.getEncoded()));
    }
}
