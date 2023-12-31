/**
 * Main.java
 * @author Griffin Ryan (glryan@uw.edu)
 * @version 12/7/2023
 */
import java.util.Scanner;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.math.BigInteger;

/**
 * Main class to run the program.
 * The encryption-suite project is a command-line tool for encrypting, decrypting, signing, and verifying data.
 * It uses the Ed448 curve and the EdDSA signature scheme.
 * 
 * Do the signature, then encrypt, then decrypt, then verify.
 * @see EllipticCurveEncryptor
 */
public class Main {

    public static void main(String[] args) throws IOException {
        Scanner scanner = new Scanner(System.in);

        while (true) {
            System.out.println("Would you like to encrypt (E), decrypt (D), sign (S), verify (V), or generate key pair (G)?");
            String action = scanner.nextLine().trim().toUpperCase();

            switch (action) {
                case "E":
                    handleEncryption(scanner);
                    break;
                case "D":
                    handleDecryption(scanner);
                    break;
                case "S":
                    handleSigning(scanner);
                    break;
                case "V":
                    handleVerification(scanner);
                    break;
                case "G":
                    handleKeyPairGeneration(scanner);
                    break;
                case "Q":
                    // Assuming 'Q' is the option to quit
                    return;
                default:
                    System.out.println("Invalid option. Please enter a valid choice.");
                    break;
            }
        }
    }

    /**
     * Method to handle decryption.
     * @param scanner
     */
    private static void handleDecryption(Scanner scanner) {
        try {
            System.out.println("Enter the path to the encrypted file:");
            String encryptedFilePath = scanner.nextLine();
            byte[] encryptedData = Files.readAllBytes(Paths.get(encryptedFilePath));
    
            System.out.println("Enter your passphrase:");
            String passphrase = scanner.nextLine();
    
            BigInteger privateKey = EllipticCurveEncryptor.derivePrivateKey(passphrase);
    
            byte[] decryptedData = EllipticCurveEncryptor.decryptData(encryptedData, privateKey);
    
            System.out.println("Enter the path for the decrypted file:");
            String decryptedFilePath = scanner.nextLine();
            Files.write(Paths.get(decryptedFilePath), decryptedData);
    
            System.out.println("Decrypted data has been written to: " + decryptedFilePath);
        } catch (Exception e) {
            System.out.println("Decryption error: " + e.getMessage());
            e.printStackTrace();
        }
    }    

    /**
     * Method to handle encryption.
     * @param scanner
     */
    private static void handleEncryption(Scanner scanner) {
        try {
            System.out.println("Encrypt from file (F) or text input (T)?");
            String source = scanner.nextLine().trim().toUpperCase();
    
            byte[] dataToEncrypt;
            if (source.equals("F")) {
                System.out.println("Enter the path to the file:");
                String filePath = scanner.nextLine();
                dataToEncrypt = Files.readAllBytes(Paths.get(filePath));
            } else if (source.equals("T")) {
                System.out.println("Enter the text to encrypt:");
                String text = scanner.nextLine();
                dataToEncrypt = text.getBytes(StandardCharsets.UTF_8);
            } else {
                System.out.println("Invalid option.");
                return;
            }
    
            System.out.println("Enter the passphrase to retrieve your public key:");
            String passphrase = scanner.nextLine();
    
            EllipticCurveEncryptor.KeyPair keyPair = EllipticCurveEncryptor.generateKeyPair(passphrase);
            Ed448Point publicKey = keyPair.publicKey;
    
            byte[] encryptedData = EllipticCurveEncryptor.encryptData(dataToEncrypt, publicKey);
            Files.write(Paths.get("encrypted_data.bin"), encryptedData);
    
            System.out.println("Data encrypted and stored in 'encrypted_data.bin'.");
        } catch (Exception e) {
            System.out.println("Encryption error: " + e.getMessage());
            e.printStackTrace();
        }
    }    

    /**
     * Method to handle key pair generation.
     * @param scanner
     */
    private static void handleKeyPairGeneration(Scanner scanner) {
        try {
            System.out.println("Enter a passphrase for key pair generation:");
            String passphrase = scanner.nextLine();

            EllipticCurveEncryptor.generateKeyPair(passphrase);
            System.out.println("Key pair generated and stored successfully.");
        } catch (Exception e) {
            System.out.println("Error generating key pair: " + e.getMessage());
        }
    }

    /**
     * Method to handle signing.
     * @param scanner
     */
    private static void handleSigning(Scanner scanner) {
        try {
            System.out.println("Enter the path to the data file to sign:");
            String filePath = scanner.nextLine();
            byte[] data = Files.readAllBytes(Paths.get(filePath));

            System.out.println("Enter your passphrase:");
            String passphrase = scanner.nextLine();
            BigInteger privateKey = EllipticCurveEncryptor.derivePrivateKey(passphrase);

            byte[] signature = EllipticCurveEncryptor.signData(data, privateKey);

            System.out.println("Signature (hex format): " + bytesToHex(signature));

            // Prompt for the path to save the signature
            System.out.println("Enter the path to save the signature file:");
            String signatureFilePath = scanner.nextLine();
            Files.write(Paths.get(signatureFilePath), signature);

            System.out.println("Signature has been written to: " + signatureFilePath);
        } catch (Exception e) {
            System.out.println("Signing error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Method to handle verification.
     * @param scanner
     */
    private static void handleVerification(Scanner scanner) {
        try {
            System.out.println("Enter the path to the data file to verify:");
            String dataFilePath = scanner.nextLine();
            byte[] data = Files.readAllBytes(Paths.get(dataFilePath));
    
            System.out.println("Enter the path to the signature file:");
            String signatureFilePath = scanner.nextLine();
            byte[] signature = Files.readAllBytes(Paths.get(signatureFilePath));
    
            System.out.println("Enter the path to the public key file:");
            String publicKeyFilePath = scanner.nextLine();
            byte[] publicKeyBytes = Files.readAllBytes(Paths.get(publicKeyFilePath));
            Ed448Point publicKey = new Ed448Point(publicKeyBytes); // Construct the public key
    
            boolean isValid = EllipticCurveEncryptor.verifySignature(data, signature, publicKey);
            if (isValid) {
                System.out.println("Signature is valid.");
            } else {
                System.out.println("Signature is invalid.");
            }
        } catch (Exception e) {
            System.out.println("Verification error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Method to convert a byte array to a hex string.
     * @param bytes
     * @return
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }

}
