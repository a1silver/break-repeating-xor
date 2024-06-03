package dev.a1silver.breakrepeatingxor;

import java.util.Arrays;
import java.util.Comparator;
import java.util.stream.IntStream;

import static dev.a1silver.breakrepeatingxor.Main.hammingDistance;

public class Vigenere {

    public static byte[] decryptRepeatingKeyXOR(byte[] ciphertext, byte[] key) {
        byte[] decrypted = new byte[ciphertext.length];
        for (int i = 0; i < ciphertext.length; i++) {
            decrypted[i] = (byte) (ciphertext[i] ^ key[i % key.length]);
        }
        return decrypted;
    }

    public static double scoreKeySize(int keySize, byte[] ciphertext) {
        String cipherString = new String(ciphertext);

        int sliceSize = 2 * keySize;

        int numSamples = ciphertext.length / sliceSize - 1;

        double score = 0;
        for (int i = 0; i < numSamples; i++) {
            int slice1Start = i* sliceSize;
            int slice1End = i* sliceSize + keySize;

            int slice2Start = i* sliceSize + keySize;
            int slice2End = i* sliceSize + 2* keySize;
            score += hammingDistance(cipherString.substring(slice1Start, slice1End), cipherString.substring(slice2Start, slice2End));
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
        System.out.println(hammingDistance("this is a test", "wokka wokka!!!"));

        return null;
    }
}
