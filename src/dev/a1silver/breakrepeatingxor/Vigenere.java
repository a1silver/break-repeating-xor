package dev.a1silver.breakrepeatingxor;

import java.util.ArrayList;
import java.util.stream.IntStream;

import static dev.a1silver.breakrepeatingxor.Main.hammingDistance;

public class Vigenere {

    /*
    Create a new partial array given an original array of bytes, a start position, and a step value
     */
    private static byte[] createPartArray(byte[] ciphertext, int start, int step) {
        int length = (ciphertext.length - start + step - 1) / step;
        byte[] part = new byte[length];
        for (int i = 0; i < length; i++) {
            part[i] = ciphertext[start + i * step];
        }
        return part;
    }

    /*
    Find the longest array out of a list of byte arrays and return its length
     */
    private static int getMaxLength(ArrayList<byte[]> arrays) {
        int maxLength = 0;
        for (byte[] array : arrays) {
            if (array.length > maxLength) {
                maxLength = array.length;
            }
        }
        return maxLength;
    }

    /*
    Find the score of a given key size when compared to an array of cipher bytes.
    This key represents the probability the decrypted content is to be an English sentence.
    Smaller key sizes are favored.
     */
    public static double scoreKeySize(int keySize, byte[] ciphertext) {
        String cipherString = new String(ciphertext);

        int sliceSize = 2 * keySize;

        int numSamples = ciphertext.length / sliceSize - 1;

        double score = 0;
        for (int i = 0; i < numSamples; i++) {
            int slice1Start = i * sliceSize;
            int slice1End = i * sliceSize + keySize;

            int slice2Start = i * sliceSize + keySize;
            int slice2End = i * sliceSize + 2 * keySize;
            score += hammingDistance(cipherString.substring(slice1Start, slice1End), cipherString.substring(slice2Start, slice2End));
        }

        score /= keySize;

        score /= numSamples;

        return score;
    }

    /*
    Determine the best key size for a given array of cipher bytes.
    The given key is scored on how likely it will decrypt the given cipher text into an English sentence.
     */
    public static int findKeySize(byte[] ciphertext) {
        final int MIN_LENGTH = 2;
        final int MAX_LENGTH = 30;

        int[] range = IntStream.range(MIN_LENGTH, MAX_LENGTH).toArray();
        double minValue = Double.MAX_VALUE;
        int minLength = Integer.MAX_VALUE;
        for (int value : range) {
            double result = scoreKeySize(value, ciphertext);
            if (result < minValue) {
                minValue = result;
                minLength = value;
            }
        }

        return minLength;
    }

    /*
    Perform a brute-force single-byte XOR attack on an array of cipher bytes.
    Used by attackRepeatingKeyXOR to perform XORs on multiple sections of the main cipher text.
     */
    public static Structures.Pair<byte[], byte[]> attackSingleByteXOR(byte[] ciphertext) {
        Structures.Pair<byte[], byte[]> best = null;
        int prevNbLetters = 0;
        for (int i = 0; i < 256; i++) { // for every possible key
            byte candidateKey = (byte) i;
            byte[] keystream = new byte[ciphertext.length];
            for (int j = 0; j < ciphertext.length; j++) {
                keystream[j] = candidateKey;
            }
            byte[] candidateMessage = Main.fixedXOR(ciphertext, keystream);
            int nbLetters = 0;
            for (byte b : candidateMessage) {
                if ((b >= 97 && b < 122) || b == 32) { // is ascii char
                    nbLetters++;
                }
            }
            if (best == null || nbLetters > prevNbLetters) {
                best = new Structures.Pair<>(candidateMessage, new byte[]{candidateKey});
                prevNbLetters = nbLetters;
            }
        }
        return best;
    }

    /*
    Perform a brute-force repeating-key XOR attack on an array of cipher bytes.
     */
    public static Structures.Pair<byte[], byte[]> attackRepeatingKeyXOR(byte[] ciphertext) {
        int keysize = findKeySize(ciphertext);
        System.out.println("Key size: " + keysize);

        // We break encryption for each character of the key
        byte[] key = new byte[keysize];
        ArrayList<byte[]> messageParts = new ArrayList<>();

        for (int i = 0; i < keysize; i++) {
            // Create the part array with a step of keysize
            byte[] partArray = createPartArray(ciphertext, i, keysize);
            Structures.Pair<byte[], byte[]> part = attackSingleByteXOR(partArray);
            byte[] partKey = part.value;
            byte[] partMessage = part.key;

            // Add the key byte to the key list
            key[i] = partKey[0];
            messageParts.add(partMessage);
        }

        // Rebuild the original message
        ArrayList<Byte> message = new ArrayList<>();
        for (int i = 0; i < getMaxLength(messageParts); i++) {
            for (byte[] part : messageParts) {
                if (part.length > i) {
                    message.add(part[i]);
                }
            }
        }

        // Convert the List<Byte> to byte[]
        byte[] messageArray = new byte[message.size()];
        for (int i = 0; i < message.size(); i++) {
            messageArray[i] = message.get(i);
        }
        return new Structures.Pair<>(messageArray, key);
    }
}
