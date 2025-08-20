package com.demojava;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HexFormat;

public class CryptoUtils {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        KeyStore keyStore = KeyStore.getInstance("BCFKS", "BC");
        String fileName = "keystore.p12";
        String filePassword = "F#qj/W43KCI>z;oyJgA5";

        try (InputStream is = CryptoUtils.class.getClassLoader().getResourceAsStream(fileName)) {
            keyStore.load(is, filePassword.toCharArray());
        }

        String alias = "access-token-key";
        String aliasPassword = "Passw0rd";
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(aliasPassword.toCharArray()));
        PublicKey publicKey = privateKeyEntry.getCertificate().getPublicKey();
        byte[] encoded = publicKey.getEncoded();
        String hex = HexFormat.of().formatHex(encoded);
        System.out.println("Public Key (Hex): " + hex);

        byte[] message = "Hello Cryptography!".getBytes();
        byte[] sig = signData(message, privateKeyEntry.getPrivateKey());
        boolean isValid = verifySignature(message, sig, privateKeyEntry.getCertificate().getPublicKey());

        System.out.println("Signature (Base64): " + Base64.getEncoder().encodeToString(sig));
        System.out.println("Is signature valid? " + isValid);
    }

    static  public void printAllAliases(KeyStore keyStore) throws KeyStoreException {
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            System.out.println("Alias: " + alias);
        }
    }

    public static byte[] signData(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public static boolean verifySignature(byte[] data, byte[] sigBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(sigBytes);
    }

}
