package dev.a1silver.breakrepeatingxor;

import java.util.Arrays;
import java.util.Comparator;
import java.util.stream.IntStream;

public class Vigenere {

    public static int hammingDistance(byte[] bytes1, byte[] bytes2) {
        if (bytes1.length != bytes2.length) {
            throw new IllegalArgumentException("Byte arrays must be of equal length");
        }

        int distance = 0;
        for (int i = 0; i < bytes1.length; i++) {
            distance += Integer.bitCount(bytes1[i] ^ bytes2[i]);
        }
        return distance;
    }

    public static byte[] decryptRepeatingKeyXOR(byte[] ciphertext, byte[] key) {
        byte[] decrypted = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i++) {
            decrypted[i] = (byte) (ciphertext[i] ^ key[i % key.length]);
        }
        return decrypted;
    }

    public static double scoreKeySize(int keySize, byte[] ciphertext) {
        int sliceSize = 2 * keySize;

        int numSamples = ciphertext.length / sliceSize - 1;

        double score = 0;
        for (int i = 0; i < numSamples; i++) {

            // Slicing the byte array
            byte[] slice1 = new byte[keySize];
            byte[] slice2 = new byte[keySize];
            System.arraycopy(ciphertext, i * sliceSize, slice1, 0, keySize);
            System.arraycopy(ciphertext, i * sliceSize + keySize, slice2, 0, keySize);

            score += hammingDistance(slice1, slice2);
        }

        score /= keySize;

        score /= numSamples;

        return score;
    }

    public static int findKeySize(byte[] ciphertext) {
        final int MIN_LENGTH = 2;
        final int MAX_LENGTH = 30;

        return IntStream.range(MIN_LENGTH, MAX_LENGTH)
                .boxed()
                .min(Comparator.comparingDouble(a -> scoreKeySize(a, ciphertext)))
                .orElse(MIN_LENGTH);  // Default to minLength if no min value found (which is unlikely)
    }


    public static Structures.Pair<byte[],byte[]> repeatingKeyXOR(byte[] ciphertext) {
        System.out.println(findKeySize(ciphertext));

        return null;
    }
}
