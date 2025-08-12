package com.demojava;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class HashPassword {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        String password = "mySecurePassword";

        // Generate a 16-byte random salt
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        // Hash the password with the salt
        MessageDigest digest = MessageDigest.getInstance("SHA-512");
        digest.update(salt);
        byte[] hashedPassword = digest.digest(password.getBytes());
        // Encode results for storage
        String saltBase64 = Base64.getEncoder().encodeToString(salt);
        String hashBase64 = Base64.getEncoder().encodeToString(hashedPassword);

        System.out.println("Salt (Base64): " + saltBase64);
        System.out.println("Hashed Password (Base64): " + hashBase64);

        byte[] saltBytes = Base64.getDecoder().decode(saltBase64);
        byte[] hashBytes = Base64.getDecoder().decode(hashBase64);

        // Verify the password
        MessageDigest verifyDigest = MessageDigest.getInstance("SHA-512");
        verifyDigest.update(saltBytes);
        byte[] verifyHash = verifyDigest.digest(password.getBytes());
        boolean isPasswordCorrect = MessageDigest.isEqual(verifyHash, hashBytes);
        System.out.println("Is password correct? " + isPasswordCorrect);
    }
}
