/**
 * Hash.java
 * @author Griffin Ryan (glryan@uw.edu)
 * @version 12/7/2023
 */
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Class to compute SHA-256, cSHAKE256, and KMACXOF256 hashes.
 * @see EllipticCurveEncryptor
 * @see Keccak
 * @see Ed448Point
 */
public class Hash {

    /**
     * Method to compute SHA-256 hash.
     * @param input
     * @return
     */
    public byte[] computeSHA256(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(input);
        } catch (Exception e) {
            throw new RuntimeException("Could not compute hash.", e);
        }
    }

    /**
     * Method to compute cSHAKE256 hash.
     * @param input
     * @param outputLength
     * @param n
     * @param s
     * @return
     */
    public byte[] cSHAKE256(byte[] input, int outputLength, byte[] n, byte[] s) {
        // Encode the 'n' and 's' parameters
        byte[] encodedN = encodeString(n);
        byte[] encodedS = encodeString(s);
    
        // Concatenate encodedN, encodedS and the input message
        byte[] concatenated = new byte[encodedN.length + encodedS.length + input.length];
        System.arraycopy(encodedN, 0, concatenated, 0, encodedN.length);
        System.arraycopy(encodedS, 0, concatenated, encodedN.length, encodedS.length);
        System.arraycopy(input, 0, concatenated, encodedN.length + encodedS.length, input.length);
    
        // Initialize Keccak and absorb the padded message
        Keccak keccak = new Keccak();
        // Padding the message as per Keccak's requirements
        byte[] paddedMessage = keccak.pad(concatenated, Keccak.RATE);
        keccak.absorb(paddedMessage);
    
        // Squeeze out the hash of the desired length
        return keccak.squeeze(outputLength);
    }

    /**
     * Method to compute KMACXOF256 hash.
     * @param key
     * @param data
     * @param outputLength
     * @param s
     * @return
     */
    public byte[] KMACXOF256(byte[] key, byte[] data, int outputLength, byte[] s) {
        // newXOF is initialized with cSHAKE's padding bits 04.
        byte[] newXOF = {(byte) 0x04};
    
        // 1. Bytepad the key
        byte[] paddedKey = bytepad(encodeString(key), Keccak.RATE / 8);
    
        // 2. Concatenate bytepadded key, data, output length encoding, and newXOF
        byte[] concatenated = new byte[paddedKey.length + data.length + 8 + newXOF.length];
        System.arraycopy(paddedKey, 0, concatenated, 0, paddedKey.length);
        System.arraycopy(data, 0, concatenated, paddedKey.length, data.length);
        // Right-encode the output length in bits
        byte[] encodedOutputLength = rightEncode(outputLength * 8);
        System.arraycopy(encodedOutputLength, 0, concatenated, paddedKey.length + data.length, encodedOutputLength.length);
        System.arraycopy(newXOF, 0, concatenated, paddedKey.length + data.length + encodedOutputLength.length, newXOF.length);
    
        // 3. Call cSHAKE256 with concatenated array
        return cSHAKE256(concatenated, outputLength, new byte[0], s);
    }

    /**
     * Method to compute MAC.
     * @param key
     * @param data
     * @param customizationString
     * @return
     */
    public byte[] computeMAC(byte[] key, byte[] data, byte[] customizationString) {
        int outputLength = 256; // Define the desired output length for the MAC in bits
        return KMACXOF256(key, data, outputLength, customizationString);
    }

    /**
     * Method to compute hash.
     * @param x
     * @return
     */
    private byte[] rightEncode(int x) {
        if (x == 0) {
            return new byte[]{1, 0};
        }
        int n = (int) Math.floor(Math.log(x) / Math.log(256)) + 1;
        byte[] rightEncoded = new byte[n + 2];
        rightEncoded[0] = (byte) n;
        for (int i = n; i >= 1; i--) {
            rightEncoded[i] = (byte) (x & 0xff);
            x >>>= 8;
        }
        rightEncoded[n + 1] = (byte) 0x80; // delimiter
        return rightEncoded;
    }

    /**
     * Method to compute hash.
     * @param len
     * @return
     */
    private byte[] leftEncode(int len) {
        // Find out the number of bits needed to represent the length
        int n = 1;
        while ((1 << (8 * n)) <= len) n++;
        byte[] encoding = new byte[n + 1];
        encoding[0] = (byte) n; // The first byte is the length of the encoded bytes
        for (int i = 1; i <= n; i++) {
            encoding[i] = (byte) (len >> (8 * (n - i)));
        }
        return encoding;
    }

    /**
     * Method to compute hash.
     * @param str
     * @return
     */
    private byte[] encodeString(byte[] str) {
        byte[] len = leftEncode(str.length * 8); // Length is encoded in bits
        byte[] encoding = new byte[len.length + str.length];
        System.arraycopy(len, 0, encoding, 0, len.length);
        System.arraycopy(str, 0, encoding, len.length, str.length);
        return encoding;
    }

    /**
     * Method to compute hash.
     * @param X
     * @param w
     * @return
     */
    private byte[] bytepad(byte[] X, int w) {
        byte[] z = new byte[((X.length + w - 1) / w) * w];
        byte[] encodedW = leftEncode(w); // w is encoded as a left-encoded string
        System.arraycopy(encodedW, 0, z, 0, encodedW.length);
        System.arraycopy(X, 0, z, encodedW.length, X.length);
        return z;
    }
    
    /**
     * Keccak implementation.
     * 
     * Implements the state initilization with the five step mappings
     * theta, rho, pi, chi, and iota, and the permutation function.
     */
    private class Keccak {
    
        private static final int PERMUTATION_WIDTH = 1600;
        private static final int LANE_WIDTH = 64;
        private static final int RATE = 1088; // For SHA-3, cSHAKE
        private static final int CAPACITY = PERMUTATION_WIDTH - RATE;
        private static final int NUM_ROUNDS = 24;

        private long[] state = new long[PERMUTATION_WIDTH / LANE_WIDTH];

        // Constants for iota
        private static final long[] ROUND_CONSTANTS = {
            0x0000000000000001L, 0x0000000000008082L,
            0x800000000000808AL, 0x8000000080008000L,
            0x000000000000808BL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L,
            0x000000000000008AL, 0x0000000000000088L,
            0x0000000080008009L, 0x000000008000000AL,
            0x000000008000808BL, 0x800000000000008BL,
            0x8000000000008089L, 0x8000000000008003L,
            0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800AL, 0x800000008000000AL,
            0x8000000080008081L, 0x8000000000008080L,
            0x0000000080000001L, 0x8000000080008008L
        };        

        /**
         * Constructor for Keccak.
         */
        public Keccak() {
            // Initialize the state array
            Arrays.fill(state, 0);
        }

        /**
         * Method to perform theta step.
         */
        private void theta() {
            long[] C = new long[5];
            long[] D = new long[5];
        
            // Calculate the parity of each column
            for (int x = 0; x < 5; x++) {
                C[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            }
        
            // Calculate the D values which are used to XOR with the lanes
            for (int x = 0; x < 5; x++) {
                D[x] = C[(x + 4) % 5] ^ rotateLeft(C[(x + 1) % 5], 1);
            }
        
            // Apply the D values to the state
            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    int index = x + 5 * y;
                    state[index] ^= D[x];
                }
            }
        }        

        /**
         * Method to perform rho step.
         */
        private void rho() {
            // Define the rotation offsets for each position
            int[][] offsets = {
                {0, 36, 3, 41, 18},
                {1, 44, 10, 45, 2},
                {62, 6, 43, 15, 61},
                {28, 55, 25, 21, 56},
                {27, 20, 39, 8, 14}
            };
        
            // Rotate each lane by its designated offset
            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    int index = x + 5 * y;
                    state[index] = rotateLeft(state[index], offsets[x][y]);
                }
            }
        }

        /**
         * Method to perform pi step.
         */
        private void pi() {
            long[] tempState = Arrays.copyOf(state, state.length);
        
            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    int newX = y;
                    int newY = (2 * x + 3 * y) % 5;
                    state[newX + 5 * newY] = tempState[x + 5 * y];
                }
            }
        }        

        /**
         * Method to perform chi step.
         */
        private void chi() {
            long[] tempState = Arrays.copyOf(state, state.length);
        
            for (int x = 0; x < 5; x++) {
                for (int y = 0; y < 5; y++) {
                    int index = x + 5 * y;
                    state[index] = tempState[index] ^ ((~tempState[(x + 1) % 5 + 5 * y]) & tempState[(x + 2) % 5 + 5 * y]);
                }
            }
        }

        /**
         * Method to perform iota step.
         * @param round
         */
        private void iota(int round) {
            // Implementation of the iota step for the given round
            state[0] ^= ROUND_CONSTANTS[round];
        }

        /**
         * Method to pad the message.
         * @param message
         * @param rateInBytes
         * @return
         */
        public byte[] pad(byte[] message, int rateInBytes) {
            // Determine the length of padding needed to extend the message so that
            // it is a multiple of the rate (in bytes)
            int paddingLength = rateInBytes - (message.length % rateInBytes);
            if (paddingLength == 1) {
                paddingLength += rateInBytes;
            }
        
            // Create a new array with the size of the message + padding
            byte[] paddedMessage = new byte[message.length + paddingLength];
            // Copy the message into the new array
            System.arraycopy(message, 0, paddedMessage, 0, message.length);
            // The Keccak padding is 1 followed by a number of 0s and a final 1
            // We've already put 0s by initializing the array
            paddedMessage[message.length] = 1; // Add the first 1 bit
            paddedMessage[paddedMessage.length - 1] |= 0x80; // Add the final 1 bit in the last byte
        
            return paddedMessage;
        }

        /**
         * Method to absorb the message.
         * @param message
         */
        private void absorb(byte[] message) {
            int blockSize = RATE / 8; // Convert rate from bits to bytes
        
            for (int i = 0; i < message.length; i += blockSize) {
                // XOR each block of the message with the state
                for (int j = 0; j < blockSize && i + j < message.length; j++) {
                    state[j / LANE_WIDTH] ^= (long) (message[i + j] & 0xFF) << (8 * (j % LANE_WIDTH));
                }
                // Apply the permutation function
                permutation();
            }
        }

        /**
         * Method to squeeze the message.
         * @param outputLength
         * @return
         */
        private byte[] squeeze(int outputLength) {
            int blockSize = RATE / 8; // Convert rate from bits to bytes
            byte[] output = new byte[outputLength / 8];
        
            int outputProduced = 0;
            while (outputProduced < output.length) {
                int bytesToCopy = Math.min(blockSize, output.length - outputProduced);
                for (int i = 0; i < bytesToCopy; i++) {
                    output[outputProduced + i] = (byte) ((state[i / LANE_WIDTH] >>> (8 * (i % LANE_WIDTH))) & 0xFF);
                }
                outputProduced += bytesToCopy;
        
                if (outputProduced < output.length) {
                    permutation();
                }
            }
        
            return output;
        }

        /**
         * Method to perform the permutation.
         */
        public void permutation() {
            for (int round = 0; round < NUM_ROUNDS; round++) {
                theta();
                rho();
                pi();
                chi();
                iota(round);
            }
        }

        /**
         * Method to rotate left.
         * @param l
         * @param offset
         * @return
         */
        private long rotateLeft(long l, int offset) {
            return (l << offset) | (l >>> (64 - offset));
        }

        /**
         * Method to compute the Keccak hash.
         * @param message
         * @param outputLength
         * @return
         */
        public byte[] keccak(byte[] message, int outputLength) {
            // Perform the keccak hash calculation
            absorb(message);
            return squeeze(outputLength);
        }
    }
    
}
