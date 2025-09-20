import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

public class Password {
    private static final String FILE_NAME = "passwords.dat";
    private static final String ALGORITHM = "AES";
    private static SecretKey secretKey;
    private static Map<String, String> passwordStore = new HashMap<>();

    // Generate AES key (used for encryption/decryption)
    private static void initKey() throws Exception {
        File keyFile = new File("secret.key");
        if (keyFile.exists()) {
            byte[] keyBytes = new byte[(int) keyFile.length()];
            try (FileInputStream fis = new FileInputStream(keyFile)) {
                fis.read(keyBytes);
            }
            secretKey = new SecretKeySpec(keyBytes, ALGORITHM);
        } else {
            KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
            keyGen.init(128); // AES key size
            secretKey = keyGen.generateKey();
            try (FileOutputStream fos = new FileOutputStream(keyFile)) {
                fos.write(secretKey.getEncoded());
            }
        }
    }

    // Encrypt text
    private static String encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    // Decrypt text
    private static String decrypt(String encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] decoded = Base64.getDecoder().decode(encryptedData);
        byte[] decrypted = cipher.doFinal(decoded);
        return new String(decrypted);
    }

    // Save passwords to file
    private static void savePasswords() throws Exception {
        try (ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(FILE_NAME))) {
            oos.writeObject(passwordStore);
        }
    }

    // Load passwords from file
    private static void loadPasswords() throws Exception {
        File file = new File(FILE_NAME);
        if (file.exists()) {
            try (ObjectInputStream ois = new ObjectInputStream(new FileInputStream(file))) {
                passwordStore = (HashMap<String, String>) ois.readObject();
            }
        }
    }

    public static void main(String[] args) {
        try {
            initKey();
            loadPasswords();
            Scanner scanner = new Scanner(System.in);

            while (true) {
                System.out.println("\n--- Password Manager ---");
                System.out.println("1. Add Account");
                System.out.println("2. Retrieve Password");
                System.out.println("3. Exit");
                System.out.print("Enter choice: ");
                int choice = scanner.nextInt();
                scanner.nextLine();

                switch (choice) {
                    case 1:
                        System.out.print("Enter account name: ");
                        String account = scanner.nextLine();
                        System.out.print("Enter password: ");
                        String password = scanner.nextLine();
                        passwordStore.put(account, encrypt(password));
                        savePasswords();
                        System.out.println("Password saved securely!");
                        break;

                    case 2:
                        System.out.print("Enter account name: ");
                        String acc = scanner.nextLine();
                        if (passwordStore.containsKey(acc)) {
                            String decryptedPass = decrypt(passwordStore.get(acc));
                            System.out.println("Password for " + acc + " is: " + decryptedPass);
                        } else {
                            System.out.println("Account not found!");
                        }
                        break;

                    case 3:
                        System.out.println("Exiting Password Manager...");
                        savePasswords();
                        scanner.close();
                        return;

                    default:
                        System.out.println("Invalid choice, try again.");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
