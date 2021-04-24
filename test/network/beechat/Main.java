package network.beechat;

import java.io.*;
import java.util.Scanner;
import java.nio.charset.StandardCharsets;

public class Main {

    public static void main(String[] args) throws FileNotFoundException{
        String message = "example message for verification";
        Base58 b58 = new Base58();
        byte[] pk = new byte[Dilithium.CRYPTO_PUBLICKEYBYTES];
        byte[] sk = new byte[Dilithium.CRYPTO_SECRETKEYBYTES];
        byte[] sm = new byte[Dilithium.CRYPTO_BYTES + message.length()];
        byte[] m = new byte[Dilithium.CRYPTO_BYTES + message.length()];

        // Step 1: Create key pair
        int rc = Dilithium.crypto_sign_keypair(pk, sk);

        String testOutput = new String(b58.encode(pk));
        System.out.println("Sign public key:\n" + testOutput);
        try (FileWriter writer = new FileWriter("key.public", false)) {
            writer.write(testOutput);
            writer.flush();
            writer.close();
        } catch (IOException ex){}
        testOutput = new String(b58.encode(sk));
        try (FileWriter writer2 = new FileWriter("key.secret", false)) {
            writer2.write(testOutput);
            writer2.flush();
            writer2.close();
        } catch (IOException ex){}
        System.out.println("\nSign secret key:\n" + testOutput);


        // Step 2: Signing message
        long smlen = Dilithium.crypto_sign(sm, message.toCharArray(), message.length(), sk);

        System.out.println("\nOriginal message:\n" + message);
        testOutput = new String(b58.encode(sm));
        System.out.println("\nSigned message:\n" + testOutput);

        // Step 3: Checking message
        Scanner sc = new Scanner(new File("key.public"));
        rc = Dilithium.crypto_sign_open(m, sm, smlen, b58.decode(sc.nextLine()));

        System.out.println("\nRestored message:\n" + new String(m));

        if (rc != -1) {
            System.out.println("\nSuccess!");
            rc = 0;
        } else {
            System.out.println("\nFailed.");
            rc = 1;
        }


        // ------------ DilithiumAes ------------

        // Step 1: Create key pair
        rc = DilithiumAes.crypto_sign_keypair(pk, sk);

        testOutput = new String(b58.encode(pk));
        System.out.println("Sign public key:\n" + testOutput);
        try (FileWriter writer = new FileWriter("key.public", false)) {
            writer.write(testOutput);
            writer.flush();
            writer.close();
        } catch (IOException ex){}
        testOutput = new String(b58.encode(sk));
        try (FileWriter writer2 = new FileWriter("key.secret", false)) {
            writer2.write(testOutput);
            writer2.flush();
            writer2.close();
        } catch (IOException ex){}
        System.out.println("\nSign secret key:\n" + testOutput);


        // Step 2: Signing message
        smlen = DilithiumAes.crypto_sign(sm, message.toCharArray(), message.length(), sk);

        System.out.println("\nOriginal message:\n" + message);
        testOutput = new String(b58.encode(sm));
        System.out.println("\nSigned message:\n" + testOutput);

        // Step 3: Checking message
        sc = new Scanner(new File("key.public"));
        rc = DilithiumAes.crypto_sign_open(m, sm, smlen, b58.decode(sc.nextLine()));

        System.out.println("\nRestored message:\n" + new String(m));

        if (rc != -1) {
            System.out.println("\nSuccess!");
            rc = 0;
        } else {
            System.out.println("\nFailed.");
            rc = 1;
        }
        System.exit(rc);
    }

}

