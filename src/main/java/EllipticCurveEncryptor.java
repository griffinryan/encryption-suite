/**
 * EllipticCurveEncryptor.java
 * @author Griffin Ryan (glryan@uw.edu)
 * @version 12/7/2023
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

/**
 * Class to perform Elliptic Curve Cryptography (ECC) operations.
 * 
 * Able to encrypt and decrypt data, sign and verify data, and generate key pairs.
 * 
 * This class uses the Ed448 curve, which is defined by the equation: -x² + y² = 1 - 39081x²y²
 * The curve is defined over the finite field of integers modulo P, where P = 2^448 - 2^224 - 1
 * The base point is (x0, y0) where x0 is the square root of (1 - y0²)/(1 - 39081y0²) modulo P
 * @see Ed448Point
 */
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

    public static boolean verifySignature(byte[] data, byte[] signature, Ed448Point publicKey) throws Exception {
        // Extract R and s from the signature
        // This depends on how you serialized them in the signData method
        Ed448Point R = extractR(signature);
        BigInteger s = extractS(signature);

        // Hash computation
        Hash hash = new Hash();
        byte[] concatenatedData = concatenate(R.toBytes(), publicKey.toBytes(), data);
        BigInteger e = new BigInteger(1, hash.computeSHA256(concatenatedData));

        // Verification equation
        Ed448Point G = basePoint; // Assuming basePoint is the base point of the curve
        Ed448Point leftSide = G.scalarMultiply(s);
        Ed448Point rightSide = publicKey.scalarMultiply(e).add(R);

        return leftSide.equals(rightSide);
    }

    private static Ed448Point extractR(byte[] signature) throws Exception {
        // Assuming R is the first part of the signature and has a fixed length
        int rLength = 112; // Adjust based on your R representation (56 for compressed, 112 for uncompressed)
        byte[] rBytes = Arrays.copyOfRange(signature, 0, rLength);
        return new Ed448Point(rBytes); // Constructing R from bytes
    }    

    private static BigInteger extractS(byte[] signature) {
        int rLength = 112; // Must match the length used in extractR
        int sLength = 56; // Length of s scalar for Ed448
        byte[] sBytes = Arrays.copyOfRange(signature, rLength, rLength + sLength);
        return new BigInteger(1, sBytes); // Constructing s from bytes
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

    private static byte[] getSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private static byte[] getIV() {
        byte[] iv = new byte[16]; // AES block size
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static void writePublicKeyToFile(Ed448Point publicKey, String filePath) throws Exception {
        String publicKeyString = publicKey.toString(); // Convert to a string or byte format as needed
        Files.write(Paths.get(filePath), publicKeyString.getBytes(), StandardOpenOption.CREATE);
    }

    public static void writeEncryptedPrivateKeyToFile(byte[] encryptedPrivateKey, String filePath) throws Exception {
        Files.write(Paths.get(filePath), encryptedPrivateKey, StandardOpenOption.CREATE);
    }

    private static byte[] toByteArrayFixedLength(BigInteger number, int length) {
        byte[] byteArray = number.toByteArray();
    
        // If the byteArray length is less than the required length, pad it with zeros
        if (byteArray.length < length) {
            byte[] paddedArray = new byte[length];
            System.arraycopy(byteArray, 0, paddedArray, length - byteArray.length, byteArray.length);
            return paddedArray;
        } else if (byteArray.length > length) {
            // If the byteArray length is more than the required length, truncate it
            return Arrays.copyOfRange(byteArray, byteArray.length - length, byteArray.length);
        }
    
        // If the length is already correct, return the array as is
        return byteArray;
    }
    
    public static class KeyPair {
        public final BigInteger privateKey;
        public final Ed448Point publicKey;

        /**
         * Constructor for a key pair.
         * @param privateKey
         * @param publicKey
         */
        public KeyPair(BigInteger privateKey, Ed448Point publicKey) {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }
    }

}
