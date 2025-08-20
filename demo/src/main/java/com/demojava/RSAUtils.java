package com.demojava;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;

public class RSAUtils {
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

        byte[] secretMessage = "Top Secret!".getBytes();
        byte[] encrypted = RSAUtils.encrypt(secretMessage, privateKeyEntry.getCertificate().getPublicKey());
        byte[] decrypted = RSAUtils.decrypt(encrypted, privateKeyEntry.getPrivateKey());

        System.out.println("Encrypted (Base64): " + Base64.getEncoder().encodeToString(encrypted));
        System.out.println("Decrypted: " + new String(decrypted));

    }

    public static byte[] encrypt(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }

    public static byte[] decrypt(byte[] data, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(data);
    }
}
