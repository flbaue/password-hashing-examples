/*
 * Florian Bauer
 * florian.bauer@posteo.de
 * Copyright (c) 2014.
 */

//package ... 
 
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

public class PBKDF2 {

    public static final int ITERATIONS = 30000;
    public static final int DERIVED_KEY_LENGTH = 256; // in bit
    public static final int SALT_LENGTH = 8; // in byte

    public static void main(final String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException {
        new PBKDF2().run(args);
    }

    private void run(final String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException {
        
        if(args.length < 1) {
            printHelp();
        }
        
        if (args[0].equals("-i") || args[0].equals("--interactive")) {
            interactiveMode();
            return;
        }

        if (args[0].equals("-p") || args[0].equals("--password")) {
            if(args.length != 2) {
                System.err.println("Password-Hasher: Password is empty.");
                return;
            }
            commandlineMode(args[1].trim());
            return;
        }

        printHelp();
    }

    private void commandlineMode(final String password) throws InvalidKeySpecException, NoSuchAlgorithmException {
        final String hash = generateStorngPasswordHash(password);
        if (validatePassword(password, hash)) {
            System.out.println(hash);
        } else {
            System.err.println("Password-Hasher: Generated hash could not be validated.");
        }
    }

    private void interactiveMode() throws InvalidKeySpecException, NoSuchAlgorithmException {
        final Scanner in = new Scanner(System.in);
        System.out.println("Enter password that should be hashed:");
        final String password = in.nextLine().trim();
        final String hashedPassword = generateStorngPasswordHash(password);
        System.out.println("Hash:");
        System.out.println(hashedPassword);
        System.out.println("is valid: " + validatePassword(password, hashedPassword));
    }

    private void printHelp() {
        final String help = "Password-Hasher Help\n" +
                "Parameter options:\n" +
                "-i or --interactive\t\t\t\t\t\tInteractive mode with prompt for password\n" +
                "-p [password] or --password [password]\tPassword hash will be delegated to StdOut";
        System.out.println(help);
    }

    private String generateStorngPasswordHash(final String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        final char[] chars = password.toCharArray();
        final byte[] salt = generateSalt();

        final PBEKeySpec spec = new PBEKeySpec(chars, salt, ITERATIONS, DERIVED_KEY_LENGTH);
        final SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        final byte[] hash = skf.generateSecret(spec).getEncoded();

        return ITERATIONS + ":" + DatatypeConverter.printHexBinary(salt) + ":" + DatatypeConverter.printHexBinary(hash);
    }

    private byte[] generateSalt() throws NoSuchAlgorithmException {
        final SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        final byte[] salt = new byte[SALT_LENGTH];
        sr.nextBytes(salt);
        return salt;
    }

    private boolean validatePassword(final String originalPassword, final String storedPassword) throws NoSuchAlgorithmException, InvalidKeySpecException {
        final String[] parts = storedPassword.split(":");
        final int iterations = Integer.parseInt(parts[0]);
        final byte[] salt = DatatypeConverter.parseHexBinary(parts[1]);
        final byte[] hash = DatatypeConverter.parseHexBinary(parts[2]);

        final PBEKeySpec spec = new PBEKeySpec(originalPassword.toCharArray(), salt, iterations, hash.length * 8);
        final SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        final byte[] testHash = skf.generateSecret(spec).getEncoded();

        return MessageDigest.isEqual(hash, testHash);
    }
}
