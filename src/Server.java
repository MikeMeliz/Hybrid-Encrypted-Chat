import java.net.*;
import java.io.*;
import javax.crypto.*;
import java.security.*;
import java.security.spec.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class Server {

    public static void main(String[] args) throws IOException,
            NoSuchAlgorithmException, NoSuchProviderException,
            NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException, ClassNotFoundException, InvalidKeySpecException {

        ServerSocket serverSocket = null;
        try {
            serverSocket = new ServerSocket(44430);
        } catch (IOException e) {
            System.err.println("Could not listen on port: 44430.");
            System.exit(1);
        }

        Socket clientSocket = null;
        try {
            clientSocket = serverSocket.accept();
        } catch (IOException e) {
            System.err.println("Accept failed.");
            System.exit(1);
        }

        PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(
                new InputStreamReader(
                        clientSocket.getInputStream()));

        BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
        String inputLine, outputLine;

        if (Debugger.isEnabled())
            Debugger.log("Server started");

        // Generate AES Key
        KeyGenerator AES_keygen = KeyGenerator.getInstance("AES");
        AES_keygen.init(256, new SecureRandom());
        SecretKey AES_Key = AES_keygen.generateKey();
        
        // Convert to Byte
        byte[] data = AES_Key.getEncoded();
        
        //Encode Key
        String aeskeyencoded = Base64.getEncoder().encodeToString(data);
        
        if (Debugger.isEnabled()) {
            Debugger.log("1. Generate Key: " + AES_Key);
            Debugger.log("2. Convert Key to Byte:" + data);
            Debugger.log("3. Encode Key:" + aeskeyencoded);
            Debugger.log("3. Binary Key:" + aeskeyencoded.getBytes());
        }

        // Check for keys & Create them
        if (!areKeysPresent()) {
            if (Debugger.isEnabled()) {
                Debugger.log("\n "
                    + "-------------------------------------------\n"
                    + "    Didn't find Private and Public Keys!!  \n"
                    + "            Generating now..               \n"
                    + "-------------------------------------------\n");
            }
            CreateKeys();
            if (!areKeysPresent()) {
                if (Debugger.isEnabled())
                    Debugger.log("Something going wrong with keys :(");
            }
        }

        // Encrypt AES Key with Server's Private RSA Key
        ObjectInputStream inputStream = null;
        inputStream = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
        // TODO: Fix java.math.BigInteger cannot be cast to java.security.PrivateKey
        final PrivateKey privateKey = (PrivateKey) inputStream.readObject();
        final byte[] cryptoaeskey = encrypt(aeskeyencoded, privateKey);
        
        if (Debugger.isEnabled()) {
            Debugger.log("4. Encrypt with Server's Private Key(1): " + cryptoaeskey);
            Debugger.log("4. String of it: " + cryptoaeskey.toString());
        }

        // Encrypt AES Key with Client's Public RSA Key
        ObjectInputStream inputStream2 = null;
        inputStream2 = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
        final PublicKey publicKey = (PublicKey) inputStream2.readObject();
        final byte[] cryptoaeskey2 = encrypt2(cryptoaeskey.toString(), publicKey);
        String encodeaeskey = Base64.getEncoder().encodeToString(cryptoaeskey2);
        
        if (Debugger.isEnabled()) {
            Debugger.log("6. Encrypt with Client's Public Key(2): " + cryptoaeskey2);
            Debugger.log("7. Encode Key:" + encodeaeskey);
            Debugger.log("7. Binary Key:" + encodeaeskey.getBytes());
            Debugger.log("8. Sending Key: " + encodeaeskey);
        }

        // Send Encrypted AES Key
        out.println(encodeaeskey);
        
        while ((inputLine = in.readLine()) != null) {

            Cipher AES_Cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
            AES_Cipher.init(Cipher.DECRYPT_MODE, AES_Key);
            byte[] decoded = Base64.getDecoder().decode(inputLine);
            byte[] plaintext = AES_Cipher.doFinal(decoded);

            System.out.println("Server receive : " + new String(plaintext, StandardCharsets.UTF_8));

            System.out.println("type message :");
            outputLine = stdIn.readLine();
            byte[] plaintext2 = outputLine.getBytes(StandardCharsets.UTF_8);
            AES_Cipher.init(Cipher.ENCRYPT_MODE, AES_Key);
            byte ciphertext[] = AES_Cipher.doFinal(plaintext2);
            String encoded = Base64.getEncoder().encodeToString(ciphertext);

            out.println(encoded);
        }

        out.close();
        in.close();
        clientSocket.close();
        serverSocket.close();
    }

    // String to hold name of the encryption algorithm.
    public static final String ALGORITHM2 = "RSA/None/NoPadding";
    public static final String ALGORITHM = "RSA/ECB/PKCS1Padding";
    //String to hold the name of the private key file.
    public static final String PRIVATE_KEY_FILE = "cliepublic.key";
    //String to hold name of the public key file.
    public static final String PUBLIC_KEY_FILE = "servprivate.key";

    // Generate Keys and Save them
    public static void CreateKeys() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.genKeyPair();
        //Key publicKey = kp.getPublic();
        //Key privateKey = kp.getPrivate();
        KeyFactory fact = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pub = fact.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
        RSAPrivateKeySpec priv = fact.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);

        saveToFile("servpublic.key", pub.getModulus(), pub.getPublicExponent());
        saveToFile("servprivate.key", priv.getModulus(), priv.getPrivateExponent());

    }

    public static void saveToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {
        ObjectOutputStream oout = new ObjectOutputStream(
                new BufferedOutputStream(new FileOutputStream(fileName)));
        try {
            oout.writeObject(mod);
            oout.writeObject(exp);
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        } finally {
            oout.close();
        }
    }

    // Check if keys exists on the wanted location
    public static boolean areKeysPresent() {

        File privateKey = new File(PRIVATE_KEY_FILE);
        File publicKey = new File(PUBLIC_KEY_FILE);

        if (privateKey.exists() && publicKey.exists()) {
            return true;
        }
        return false;
    }

    //Encryption with Client's Public Key (text, key)
    public static byte[] encrypt2(String text, PublicKey key) {
        byte[] cipherText = null;
        try {
            // get an RSA cipher object and print the provider
            final Cipher cipher = Cipher.getInstance(ALGORITHM);

            // encrypt the plain text using the public key
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipherText = cipher.doFinal(text.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return cipherText;
    }

    //Encryption with Server Private Key (text, key)
    public static byte[] encrypt(String text, PrivateKey key) {
        byte[] cipherText2 = null;
        try {
            // get an RSA cipher object and print the provider
            final Cipher cipher = Cipher.getInstance(ALGORITHM2);

            // encrypt the plain text using the public key
            cipher.init(Cipher.ENCRYPT_MODE, key);
            cipherText2 = cipher.doFinal(text.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return cipherText2;
    }

}

class Debugger{
    public static boolean isEnabled(){
        return true;
    }

    public static void log(Object o){
        System.out.println(o.toString());
    }
    /*  
    if (Debugger.isEnabled())
        Debugger.log("");
    */
}
