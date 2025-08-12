package com.demojava;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.Enumeration;

public class Keyfile {
    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableKeyException, InvalidKeyException, NoSuchProviderException, SignatureException , UnrecoverableEntryException{
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream keyStoreStream = Keyfile.class.getClassLoader().getResourceAsStream("keystore.p12")) {
            if (keyStoreStream == null) {
                System.err.println("ERROR: Could not find 'keystore.p12' on the classpath.");
                throw new FileNotFoundException("Resource keystore.p12 not found in classpath. Please check your project structure.");
            }
            keyStore.load(keyStoreStream, "Passw0rd".toCharArray());

            // Load Symmetric Key
            Key sk = keyStore.getKey("user-secret-key", "Bns205#A1HHDKcdYYO2D".toCharArray());
//            System.out.println("Secret Key: " + Base64.getEncoder().encodeToString(sk.getEncoded()));


            // Load Certificate
            Certificate cf = keyStore.getCertificate("rupp-key");
            PublicKey publicKey = cf.getPublicKey();
            cf.verify(publicKey);
        }
    }

    static  public void printAllAliases(KeyStore keyStore) throws KeyStoreException {
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println("Alias: " + alias);
        }
    }
}
