/**
 * EllipticCurveEncryptor.java
 * @author Griffin Ryan (glryan@uw.edu)
 */
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;

public class EllipticCurveEncryptor {

    public static final Ed448Point basePoint = new Ed448Point();

    public static byte[] signData(byte[] data, BigInteger privateKey) throws Exception {
        SecureRandom random = new SecureRandom();
        // Step 1: Generate random scalar k
        BigInteger k = new BigInteger(448, random);
        // Step 2: Compute R = k * G
        Ed448Point R = basePoint.scalarMultiply(k);
        // Step 3: Compute hash e = H(R || publicKey || data)
        BigInteger e = hashData(concatenate(R.toBytes(), derivePublicKey(privateKey).toBytes(), data));
        // Step 4: Compute s = k - e * privateKey
        BigInteger s = k.subtract(e.multiply(privateKey)).mod(Ed448Point.P);

        // Combine R and s into a signature (this is a simplified example)
        return concatenate(R.toBytes(), s.toByteArray());
    }

    private static BigInteger hashData(byte[] data) throws Exception {
        Hash hash = new Hash();
        byte[] hashBytes = hash.computeSHA256(data);
        return new BigInteger(1, hashBytes);
    }

    private static Ed448Point derivePublicKey(BigInteger privateKey) {
        // Assuming basePoint is the base point of the curve
        return basePoint.scalarMultiply(privateKey);
    }

    private static byte[] concatenate(byte[]... arrays) {
        // First, calculate the total length of the combined array
        int totalLength = 0;
        for (byte[] array : arrays) {
            totalLength += array.length;
        }
    
        // Allocate a new array of that total length
        byte[] combined = new byte[totalLength];
    
        // Copy each array into the combined array
        int start = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, combined, start, array.length);
            start += array.length;
        }
    
        return combined;
    }    

    public static byte[] decryptData(byte[] encryptedDataWithPublicKeyAndTag, BigInteger recipientPrivateKey) {
        try {
            // Extract the ephemeral public key and encrypted data
            Ed448Point ephemeralPublicKey = extractEphemeralPublicKey(encryptedDataWithPublicKeyAndTag);
            byte[] encryptedData = extractEncryptedData(encryptedDataWithPublicKeyAndTag);
            byte[] extractedTag = extractAuthenticationTag(encryptedDataWithPublicKeyAndTag);
        
            // Perform key agreement to get shared secret
            BigInteger sharedSecret = performKeyAgreement(recipientPrivateKey, ephemeralPublicKey);
        
            // Derive keys using KMACXOF256
            Hash hash = new Hash();
            byte[] decryptionKey = hash.KMACXOF256(sharedSecret.toByteArray(), "ENCRYPTION".getBytes(), 256, new byte[0]);
            byte[] authenticationKey = hash.KMACXOF256(sharedSecret.toByteArray(), "AUTHENTICATION".getBytes(), 256, new byte[0]);
        
            // Decrypt data using the derived decryption key
            byte[] decryptedData = symmetricDecrypt(encryptedData, decryptionKey);
        
            // Recompute the authentication tag
            byte[] recomputedTag = hash.KMACXOF256(encryptedData, authenticationKey, 256, new byte[0]);
        
            // Verify the authentication tag
            if (!Arrays.equals(extractedTag, recomputedTag)) {
                throw new SecurityException("Authentication tag verification failed.");
            }
        
            return decryptedData;
        } catch (Exception e) {
            throw new SecurityException("Error extracting public key: " + e.getMessage());
        }
    }

    private static byte[] symmetricDecrypt(byte[] encryptedData, byte[] key) throws Exception {
        // Ensure the key is of valid AES key length, e.g., 256 bits
        byte[] keyBytes = Arrays.copyOf(key, 32); // for AES-256
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
    
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(new byte[16])); // Zero IV for simplicity
    
        return cipher.doFinal(encryptedData);
    }    

    private static Ed448Point extractEphemeralPublicKey(byte[] data) throws Exception {
        // Assuming the ephemeral public key is at the beginning and has a fixed length
        // If using compressed format: publicKeyLength = 56;
        // If using uncompressed format: publicKeyLength = 112;
        int publicKeyLength = 112; // Set the appropriate length for the public key
        byte[] publicKeyBytes = Arrays.copyOfRange(data, 0, publicKeyLength);
        return new Ed448Point(publicKeyBytes); // Assuming Ed448Point has a constructor that accepts byte array
    }
    
    private static byte[] extractEncryptedData(byte[] data) {
        int publicKeyLength = 112; // Same as used in extractEphemeralPublicKey
        int tagLength = 32; // Assuming a 256-bit tag
    
        int encryptedDataLength = data.length - publicKeyLength - tagLength;
        return Arrays.copyOfRange(data, publicKeyLength, publicKeyLength + encryptedDataLength);
    }

    private static byte[] extractAuthenticationTag(byte[] data) {
        int tagLength = 32; // Assuming a 256-bit tag
        return Arrays.copyOfRange(data, data.length - tagLength, data.length);
    }

    public static byte[] encryptData(byte[] data, Ed448Point recipientPublicKey) throws Exception {
        // 1. Generate ephemeral key pair
        KeyPair ephemeralKeyPair = generateEphemeralKeyPair();
        Ed448Point ephemeralPublicKey = ephemeralKeyPair.publicKey;
        BigInteger ephemeralPrivateKey = ephemeralKeyPair.privateKey;

        // 2. Perform key agreement to get shared secret
        BigInteger sharedSecret = performKeyAgreement(ephemeralPrivateKey, recipientPublicKey);

        // 3. Derive keys using KMACXOF256
        Hash hash = new Hash();
        byte[] encryptionKey = hash.KMACXOF256(sharedSecret.toByteArray(), "ENCRYPTION".getBytes(), 256, new byte[0]);
        byte[] authenticationKey = hash.KMACXOF256(sharedSecret.toByteArray(), "AUTHENTICATION".getBytes(), 256, new byte[0]);

        // 4. Encrypt data using the derived encryption key
        byte[] encryptedData = symmetricEncrypt(data, encryptionKey);

        // 5. Optionally, generate an authentication tag
        byte[] authenticationTag = hash.KMACXOF256(encryptedData, authenticationKey, 256, new byte[0]);

        // 6. Combine ephemeral public key, encrypted data, and authentication tag
        return combineEphemeralPublicKeyAndData(ephemeralPublicKey, encryptedData, authenticationTag);
    }

    private static KeyPair generateEphemeralKeyPair() throws Exception {
        // Generate a random private key
        // Assuming basePoint is the generator point of the curve
        // Calculate the corresponding public key
        BigInteger privateKey = new BigInteger(448, new SecureRandom());
        Ed448Point publicKey = basePoint.scalarMultiply(privateKey);
        return new KeyPair(privateKey, publicKey);
    }

    private static BigInteger performKeyAgreement(BigInteger privateKey, Ed448Point publicKey) {
        // Multiply the public key with the private key to get the shared secret
        Ed448Point sharedSecretPoint = publicKey.scalarMultiply(privateKey);
        return sharedSecretPoint.getY(); // Assuming getY() returns the y-coordinate
    }

    private static byte[] symmetricEncrypt(byte[] data, byte[] key) throws Exception {
        SecretKey secretKey = new SecretKeySpec(key, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(new byte[16])); // Zero IV for simplicity
        return cipher.doFinal(data);
    }

    private static byte[] combineEphemeralPublicKeyAndData(Ed448Point ephemeralPublicKey, byte[] encryptedData, byte[] authenticationTag) {
        byte[] publicKeyBytes = ephemeralPublicKey.toBytes(); // Assuming toBytes() serializes the point
        byte[] combined = new byte[publicKeyBytes.length + encryptedData.length + authenticationTag.length];
        
        System.arraycopy(publicKeyBytes, 0, combined, 0, publicKeyBytes.length);
        System.arraycopy(encryptedData, 0, combined, publicKeyBytes.length, encryptedData.length);
        System.arraycopy(authenticationTag, 0, combined, publicKeyBytes.length + encryptedData.length, authenticationTag.length);
        
        return combined;
    }

    // Method to generate a key pair from a passphrase.
    public static KeyPair generateKeyPair(String passphrase) throws Exception {
        BigInteger privateKey = derivePrivateKey(passphrase);
        Ed448Point publicKey = basePoint.scalarMultiply(privateKey);

        // Encrypt and store the private key
        byte[] encryptedPrivateKey = encryptPrivateKey(privateKey.toByteArray(), passphrase);
        Files.write(Paths.get("private_key.bin"), encryptedPrivateKey);

        // Store the public key
        Files.write(Paths.get("public_key.bin"), publicKey.toBytes());

        return new KeyPair(privateKey, publicKey);
    }

    public static BigInteger derivePrivateKey(String passphrase) throws Exception {
        // Use PBKDF2 with HMAC-SHA256 as the PRF
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), new byte[16], 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        return new BigInteger(1, tmp.getEncoded());
    }

    private static byte[] encryptPrivateKey(byte[] privateKey, String passphrase) throws Exception {
    // Generate a key for encryption
        SecretKey secret = deriveSecretKey(passphrase);

        // Ensure the key is of valid AES key length, e.g., 256 bits
        byte[] keyBytes = Arrays.copyOf(secret.getEncoded(), 32); // for AES-256
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");

        // Encrypt the private key
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(new byte[16])); // Zero IV for simplicity
        return cipher.doFinal(privateKey);
    }


    private static SecretKey deriveSecretKey(String passphrase) throws Exception {
        // Use PBKDF2 with HMAC-SHA256 as the PRF
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(passphrase.toCharArray(), new byte[16], 65536, 256);
        return factory.generateSecret(spec);
    }

    // Method to generate a random salt for key derivation
    private static byte[] getSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    // Method to generate a random IV for AES encryption
    private static byte[] getIV() {
        byte[] iv = new byte[16]; // AES block size
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    // Additional methods for writing keys to files, encrypting data, etc.
    // Write the public key to a file
    public static void writePublicKeyToFile(Ed448Point publicKey, String filePath) throws Exception {
        String publicKeyString = publicKey.toString(); // Convert to a string or byte format as needed
        Files.write(Paths.get(filePath), publicKeyString.getBytes(), StandardOpenOption.CREATE);
    }

    // Write the encrypted private key to a file
    public static void writeEncryptedPrivateKeyToFile(byte[] encryptedPrivateKey, String filePath) throws Exception {
        Files.write(Paths.get(filePath), encryptedPrivateKey, StandardOpenOption.CREATE);
    }

    // Inner class to hold key pair
    public static class KeyPair {
        public final BigInteger privateKey;
        public final Ed448Point publicKey;

        public KeyPair(BigInteger privateKey, Ed448Point publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }
    }

}
