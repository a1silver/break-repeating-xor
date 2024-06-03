package dev.a1silver.breakrepeatingxor;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.HashMap;

public class Main {

    public static final HashMap<Character, Double> frequencies = new HashMap<>();

    static {
        frequencies.put('a', 8.55/100);
        frequencies.put('b', 1.6/100);
        frequencies.put('c', 3.16/100);
        frequencies.put('d', 3.87/100);
        frequencies.put('e', 12.10/100);
        frequencies.put('f', 2.18/100);
        frequencies.put('g', 2.09/100);
        frequencies.put('h', 4.96/100);
        frequencies.put('i', 7.33/100);
        frequencies.put('j', 0.22/100);
        frequencies.put('k', 0.81/100);
        frequencies.put('l', 4.21/100);
        frequencies.put('m', 2.53/100);
        frequencies.put('n', 7.17/100);
        frequencies.put('o', 7.47/100);
        frequencies.put('p', 2.07/100);
        frequencies.put('q', 0.10/100);
        frequencies.put('r', 6.33/100);
        frequencies.put('s', 6.73/100);
        frequencies.put('t', 8.94/100);
        frequencies.put('u', 2.68/100);
        frequencies.put('v', 1.06/100);
        frequencies.put('w', 1.83/100);
        frequencies.put('x', 0.19/100);
        frequencies.put('y', 1.72/100);
        frequencies.put('z', 0.11/100);
        frequencies.put(' ', 10.0);
    }

    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    public static byte[] base64ToBytes(String base64) {
        return Base64.getDecoder().decode(base64);
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static String bytesToBase64(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    public static byte[] fixedXOR(byte[] buf1, byte[] buf2) {
        if (buf1.length != buf2.length) {
            return new byte[0];
        }

        byte[] newBuf = new byte[buf1.length];

        for (int i = 0; i < buf1.length; i++) {
            newBuf[i] = (byte) (buf1[i] ^ buf2[i]);
        }

        return newBuf;
    }

    public static byte[] keyXOR(byte[] input, byte key) {
        byte[] output = new byte[input.length];
        for (int i = 0; i < input.length; i++) {
            output[i] = (byte) (input[i] ^ key);
        }
        return output;
    }

    public static byte[] repeatingKeyXOR(byte[] input, byte[] key) {
        int keyCounter = 0;
        byte[] output = new byte[input.length];
        for (int i = 0; i < input.length; i++) {
            output[i] = (byte) (input[i] ^ key[keyCounter]);
            keyCounter++;
            if (keyCounter == key.length) {
                keyCounter = 0;
            }
        }
        return output;
    }

    /**
     * http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/english-letter-frequencies
     *
     * English Letter Frequencies in %
     *
     * A :  8.55        K :  0.81        U :  2.68
     * B :  1.60        L :  4.21        V :  1.06
     * C :  3.16        M :  2.53        W :  1.83
     * D :  3.87        N :  7.17        X :  0.19
     * E : 12.10        O :  7.47        Y :  1.72
     * F :  2.18        P :  2.07        Z :  0.11
     * G :  2.09        Q :  0.10
     * H :  4.96        R :  6.33
     * I :  7.33        S :  6.73
     * J :  0.22        T :  8.94
     */
    public static double scoreText(String text) {

        int totalCharacters = text.length();
        if (totalCharacters == 0) return 0;

        double score = 0;
        for (char c : text.toCharArray()) {
            if (frequencies.containsKey(Character.toLowerCase(c))) {
                score += frequencies.get(Character.toLowerCase(c));
            }
        }
        return score / totalCharacters; // Normalize the score by the total number of characters
    }

    public static Structures.Pair<Character, byte[]> findKey(String inputString) {
        double maxScore = 0;
        char bestKey = '\0';
        byte[] finalDecrypted = new byte[0];

        for (char key = 0; key < 128; key++) { // ASCII range
            byte[] decrypted = keyXOR(hexToBytes(inputString), (byte) key);
            String decryptedText = new String(decrypted);
            double score = scoreText(decryptedText);
            if (score > maxScore) {
                maxScore = score;
                bestKey = key;
                finalDecrypted = decrypted;
            }
        }

        return new Structures.Pair<>(bestKey, finalDecrypted);
    }

    public static int hammingDistance(byte[] buf1, byte[] buf2) {
        if (buf1.length != buf2.length) {
            return -1;
        }

        int distance = 0;
        for (int i = 0; i < buf1.length; i++) {
            distance += Integer.bitCount(buf1[i] ^ buf2[i]);
        }
        return distance;
    }

    public static int hammingDistance(String str1, String str2) {
        return hammingDistance(str1.getBytes(), str2.getBytes());
    }


    // == Main ==
    public static void main(String[] args) throws IOException {
        System.out.println("Hello, world");
    }

}
