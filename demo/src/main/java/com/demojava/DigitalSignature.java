package com.demojava;

import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.util.Base64;

public class DigitalSignature {
    public static void main(String[] args) throws Exception {
        // Load the keystore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream keyStoreStream = DigitalSignature.class.getClassLoader().getResourceAsStream("keystore.p12")) {
            keyStore.load(keyStoreStream, "Passw0rd".toCharArray());
        }

        // Get private key for signing
        PrivateKey privateKey = keyStore.getKey("signing-key", "keyPass".toCharArray());

        // Get certificate for public key
        Certificate cert = keyStore.getCertificate("signing-key");
        PublicKey publicKey = cert.getPublicKey();

        // Sign a message
        String message = "Hello, this is a secure message!";
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        byte[] digitalSignature = signature.sign();
        System.out.println("Signature: " + Base64.getEncoder().encodeToString(digitalSignature));

        // Verify the signature
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(message.getBytes());
        boolean isValid = verifier.verify(digitalSignature);
        System.out.println("Signature valid: " + isValid);
    }
}