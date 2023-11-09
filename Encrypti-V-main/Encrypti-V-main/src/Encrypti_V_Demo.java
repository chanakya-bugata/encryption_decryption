import javax.crypto.*;
import javax.crypto.spec.*;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.sql.*;
import java.util.*;

public class Encrypti_V_Demo extends JFrame {

    // Database connection and user ID
    private Connection connection;
    private int userId;

    public Encrypti_V_Demo() {

        // Attempt to connect to the database
        if (!connectToDatabase()) {
            showMessage("Connection failed. Try again later.");
            return;
        }
        setupUI();
    }

    // Set up the user interface
    private void setupUI() {

        // Disable maximizing
        setResizable(false);

        // Set up the main GUI window
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(400, 250);
        setLocationRelativeTo(null);

        // Load the GIF image
        ImageIcon backgroundImage = new ImageIcon("C:\\Users\\chana\\Downloads\\Encrypti-V-main\\Encrypti-V-main\\src\\background.gif");
        JLabel backgroundLabel = new JLabel(backgroundImage);

        // Position the background label to cover the entire JFrame
        backgroundLabel.setBounds(0, 0, 400, 250);

        // Add the background label to the JFrame's content pane
        getContentPane().add(backgroundLabel);
        
        // Create and configure UI components (labels, text fields, buttons)
        JLabel titleLabel = new JLabel("Welcome to Encrypti V");
        titleLabel.setFont(new Font("Arial", Font.BOLD, 24));
        titleLabel.setForeground(Color.WHITE);
        titleLabel.setBounds(65, 20, 300, 40);
        JLabel appName = new JLabel("Encrypti V");
        appName.setFont(new Font("Arial", Font.BOLD, 24));
        appName.setForeground(Color.WHITE);
        appName.setBounds(135, 20, 200, 40);
        JLabel usernameLabel = new JLabel("Username:");
        usernameLabel.setForeground(Color.WHITE);
        usernameLabel.setBounds(50, 80, 80, 20);
        JLabel passwordLabel = new JLabel("Password:");
        passwordLabel.setForeground(Color.WHITE);
        passwordLabel.setBounds(50, 120, 80, 20);
        JTextField usernameField = new JTextField();
        usernameField.setBounds(140, 80, 200, 25);
        JPasswordField passwordField = new JPasswordField();
        passwordField.setBounds(140, 120, 200, 25);
        JButton loginButton = new JButton("Login");
        loginButton.setBounds(140, 160, 90, 30);
        JButton registerButton = new JButton("Register");
        registerButton.setBounds(250, 160, 90, 30);
        JButton encryptFileButton = new JButton("Encrypt");
        encryptFileButton.setBounds(50, 100, 120, 50);
        JButton decryptFileButton = new JButton("Decrypt");
        decryptFileButton.setBounds(220, 100, 120, 50);

        // Add components to the panel
        addComponents(backgroundLabel, titleLabel, usernameLabel, usernameField, passwordLabel, passwordField, loginButton, registerButton, appName, encryptFileButton, decryptFileButton);

        // Hide some components initially
        hideComponents(appName, encryptFileButton, decryptFileButton);

        // Add action listeners for buttons
        loginButton.addActionListener(e -> {
            // Handle login button click
            String username = usernameField.getText();
            String password = new String(passwordField.getPassword());
            userId = login(username, password);
            if (userId == -1) {
                showMessage("Login failed. Invalid username or password.");
            } else {
                hideComponents(titleLabel, usernameLabel, usernameField, passwordField, passwordLabel, loginButton, registerButton);
                showComponents(appName, encryptFileButton, decryptFileButton);
            }
        });

        registerButton.addActionListener(e -> {
            // Handle register button click
            String username = usernameField.getText();
            String password = new String(passwordField.getPassword());
            if (register(username, password)) {
                showMessage("Registration successful. You can now log in.");
            }
        });

        encryptFileButton.addActionListener(e -> encryptFile());
        decryptFileButton.addActionListener(e -> decryptFile());
    }

    private void showMessage(String message) {
        JOptionPane.showMessageDialog(this, message);
    }

    private void addComponents(Container container, JComponent... components) {
        Arrays.stream(components).forEach(container::add);
    }

    private void hideComponents(JComponent... components) {
        Arrays.stream(components).forEach(component -> component.setVisible(false));
    }

    private void showComponents(JComponent... components) {
        Arrays.stream(components).forEach(component -> component.setVisible(true));
    }

    // Connect to the database
    private boolean connectToDatabase() {
        String jdbcUrl = "jdbc:mysql://localhost:3306/encryptiv_db";
        String username = "root";
        String password = "Chanakya@2022";

        try {
            connection = DriverManager.getConnection(jdbcUrl, username, password);
            return connection != null;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return false;
    }

    // Register a new user
    private boolean register(String username, String password) {
        if (username == null || password == null) {
            showMessage("Enter a Valid Username and password.");
        } else if (isStrongPassword(password)) {
            try {
                String insertQuery = "INSERT INTO users (username, password) VALUES (?, ?)";
                PreparedStatement preparedStatement = connection.prepareStatement(insertQuery);
                preparedStatement.setString(1, username);
                preparedStatement.setString(2, hashPassword(password));
                preparedStatement.executeUpdate();
                return true;
            } catch (SQLException e) {
                e.printStackTrace();
            }
        } else {
            showMessage("Enter a Strong password.");
        }
        return false;
    }

    // Login a user
    private int login(String username, String password) {
        try {
            String query = "SELECT user_id FROM users WHERE username = ? AND password = ?";
            PreparedStatement preparedStatement = connection.prepareStatement(query);
            preparedStatement.setString(1, username);
            preparedStatement.setString(2, hashPassword(password));
            ResultSet resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {
                return resultSet.getInt("user_id");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return -1;
    }

    // Check if a password meets strong password criteria
    private boolean isStrongPassword(String password) {
        return password != null && password.matches("^(?=.*[A-Z])(?=.*[a-z])(?=.*\\d)(?=.*[_@#$%^&+=!]).{8,}$");
    }

    // Hash a password using SHA-256
    private static String hashPassword(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hashedBytes = md.digest(password.getBytes());
            StringBuilder hexStringBuilder = new StringBuilder();
            for (byte b : hashedBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexStringBuilder.append('0');
                hexStringBuilder.append(hex);
            }
            return hexStringBuilder.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    // Check if an entered password matches a hashed password
    public static boolean checkPassword(String enteredPassword, String hashedPassword) {
        String hashedEnteredPassword = hashPassword(enteredPassword);
        if (hashedEnteredPassword == null) {
            return false;
        }
        return hashedEnteredPassword.equals(hashedPassword);
    }

    // Pick a file using a file chooser dialog
    private File pickFile() {
        JFileChooser fileChooser = new JFileChooser();
        int returnValue = fileChooser.showOpenDialog(null);
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            return fileChooser.getSelectedFile();
        } else {
            return null;
        }
    }

    // Pick a directory using a file chooser dialog
    private File pickDir() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Select Directory");
        fileChooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        int returnValue = fileChooser.showDialog(null, "Select Directory");
        if (returnValue == JFileChooser.APPROVE_OPTION) {
            return fileChooser.getSelectedFile();
        } else {
            return null;
        }
    }

    // Store encryption key and IV in the database
    private void storeKeyInDatabase(byte[] fileId, String fileName, byte[] keyBytes, byte[] iv) {
        try {
            String query = "INSERT INTO files (user_Id, file_id, file_name, encryption_key, iv) VALUES (?, ?, ?, ?, ?)";
            PreparedStatement preparedStatement = connection.prepareStatement(query);
            preparedStatement.setInt(1, userId);
            preparedStatement.setBytes(2, fileId);
            preparedStatement.setString(3, fileName);
            preparedStatement.setBytes(4, keyBytes);
            preparedStatement.setBytes(5, iv);
            preparedStatement.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // Encrypt a file
    private void encryptFile() {
        File selectedFile = pickFile();
        if (selectedFile == null) {
            return;
        }
        try {
            ArrayList<JCheckBox> checkBoxes = new ArrayList<>();
            JCheckBox keepOriginalNameCheckBox = new JCheckBox("Keep Original File Name", true);
            JCheckBox saveInPreviousLocationCheckBox = new JCheckBox("Save in Previous Location", true);
            checkBoxes.add(keepOriginalNameCheckBox);
            checkBoxes.add(saveInPreviousLocationCheckBox);
            int optionResult = JOptionPane.showOptionDialog(
                this,
                checkBoxes.toArray(),
                "Encryption Options",
                JOptionPane.YES_NO_CANCEL_OPTION,
                JOptionPane.QUESTION_MESSAGE,
                null,
                new String[]{"Encrypt", "Cancel"},
                "Encrypt");
            if (optionResult == 0) {
                File selectedDir = (saveInPreviousLocationCheckBox.isSelected()) ? selectedFile.getParentFile() : pickDir();
                String originalFileName = selectedFile.getName();
                byte[] fileId = generateRandomKey();
                String fileName = (keepOriginalNameCheckBox.isSelected()) ? originalFileName.substring(0, originalFileName.lastIndexOf('.')) : generateRandomFileName();
                byte[] keyBytes = generateRandomKey();
                byte[] fileBytes = Files.readAllBytes(selectedFile.toPath());
                Object[] encryptedData = encryptBytes(fileBytes, keyBytes);
                byte[] encryptedFileBytes = (byte[]) encryptedData[0];
                byte[] iv = (byte[]) encryptedData[1];
                byte[] cipher = new byte[32 + encryptedFileBytes.length];
                storeKeyInDatabase(fileId, originalFileName, keyBytes, iv);
                System.arraycopy(fileId, 0, cipher, 0, 32);
                System.arraycopy(encryptedFileBytes, 0, cipher, 32, encryptedFileBytes.length);
                Files.write(Paths.get(selectedDir.getAbsolutePath(), fileName + ".V"), cipher);
                selectedFile.delete();
                showMessage("File encrypted successfully.");
            }
        } catch (IOException e) {
            e.printStackTrace();
            showMessage("Error encrypting file.");
        }
    }

    // Retrieve file details from the database
    public Object[] fileDetails(byte[] fileId) {
        try {
            String query = "SELECT file_name,encryption_key,iv FROM files WHERE file_id = ? AND user_id = ?";
            PreparedStatement preparedStatement = connection.prepareStatement(query);
            preparedStatement.setBytes(1, fileId);
            preparedStatement.setInt(2, userId);
            ResultSet resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {
                String fileName = resultSet.getString("file_name");
                byte[] key = resultSet.getBytes("encryption_key");
                byte[] iv = resultSet.getBytes("iv");
                return new Object[]{fileName, key, iv};
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    // Delete a record from the database
    private void deleteRecord(byte[] fileId) {
        try {
            String query = "DELETE FROM files WHERE file_id = ? AND user_id = ?";
            PreparedStatement preparedStatement = connection.prepareStatement(query);
            preparedStatement.setBytes(1, fileId);
            preparedStatement.setInt(2, userId);
            preparedStatement.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // Decrypt a file
    private void decryptFile() {
        File selectedFile = pickFile();
        if (selectedFile == null) {
            return;
        }
        try {
            byte[] cipher = Files.readAllBytes(selectedFile.toPath());
            byte[] fileId = new byte[32];
            System.arraycopy(cipher, 0, fileId, 0, 32);
            int DataLength = cipher.length - 32;
            byte[] encryptedFileBytes = new byte[DataLength];
            System.arraycopy(cipher, 32, encryptedFileBytes, 0, DataLength);
            Object[] details = fileDetails(fileId);
            String originalFileName = (String) details[0];
            byte[] keyBytes = (byte[]) details[1];
            byte[] iv = (byte[]) details[2];
            byte[] decryptedBytes = decryptBytes(encryptedFileBytes, keyBytes, iv);
            if (decryptedBytes != null) {
                File originalDir = selectedFile.getParentFile();
                File decryptedFile = new File(originalDir, originalFileName);
                Files.write(decryptedFile.toPath(), decryptedBytes);
                selectedFile.delete();
                deleteRecord(fileId);
                showMessage("File decrypted successfully and saved as " + decryptedFile.getName());
            } else {
                showMessage("Error decrypting file. Please make sure you selected the correct encryption key.");
            }
        } catch (IOException e) {
            e.printStackTrace();
            showMessage("Error decrypting file.");
        }
    }

    // Generate a random encryption key
    private byte[] generateRandomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return key;
    }

    // Encrypt a byte array using AES/GCM encryption
    private Object[] encryptBytes(byte[] bytes, byte[] key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            byte[] iv = new byte[12];
            new SecureRandom().nextBytes(iv);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, parameterSpec);
            byte[] encryptedBytes = cipher.doFinal(bytes);
            return new Object[]{encryptedBytes, iv};
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // Decrypt a byte array using AES/GCM decryption
    private byte[] decryptBytes(byte[] encryptedText, byte[] key, byte[] iv) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, parameterSpec);
            return cipher.doFinal(encryptedText);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // Generate a random file name
    private String generateRandomFileName() {
        SecureRandom random = new SecureRandom();
        StringBuilder fileNameBuilder = new StringBuilder();
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        int length = 12;
        for (int i = 0; i < length; i++) {
            int randomIndex = random.nextInt(characters.length());
            char randomChar = characters.charAt(randomIndex);
            fileNameBuilder.append(randomChar);
        }
        return fileNameBuilder.toString();
    }

    // Main Function
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            Encrypti_V_Demo mainSwing = new Encrypti_V_Demo();
            mainSwing.setVisible(true);
        });
    }
}
