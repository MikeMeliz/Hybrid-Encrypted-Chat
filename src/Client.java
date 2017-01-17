import java.io.*;
import java.net.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Scanner;

public class Client {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, NoSuchProviderException,
            NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException,
            InvalidAlgorithmParameterException, ClassNotFoundException, InvalidKeySpecException {

        Socket mySocket = null;
        PrintWriter out = null;
        BufferedReader in = null;

        try {
            mySocket = new Socket("localhost", 44430);
            out = new PrintWriter(mySocket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(mySocket.getInputStream()));
        } catch (UnknownHostException e) {
            System.err.println("Don't know about host");
            System.exit(1);
        } catch (IOException e) {
            System.err.println("Couldn't get I/O for the connection to: localhost.");
            System.exit(1);
        }

        BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
        String fromServer = null;
        String fromUser;

        System.out.println("Client run ");

        // Generate RSA Keys
        //CreateKeys();

        String cryptoaes3 = in.readLine();

        System.out.println("Download Key: " + cryptoaes3);

        // Decode Key
        byte[] cryptoaes = Base64.getDecoder().decode(cryptoaes3);
        System.out.println("Decode Key: " + cryptoaes);

        // Decrypt AES Key with Client's Private Key
        ObjectInputStream inputStream = null;
        inputStream = new ObjectInputStream(new FileInputStream(PRIVATE_KEY_FILE));
        final PrivateKey privateKey = (PrivateKey) inputStream.readObject();
        final String uncryaes = decrypt(cryptoaes, privateKey);
        System.out.println("Decrypt with Client's Private Key(2):" + uncryaes);

        // Decrypt AES Key with Server's Public Key
        ObjectInputStream inputStream2 = null;
        inputStream2 = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
        final PublicKey publicKey = (PublicKey) inputStream2.readObject();
        final String uncryaes2 = decrypt2(uncryaes.getBytes(), publicKey);
        System.out.println("Decrypt with Server's Public Key(1):" + uncryaes2);

        SecretKeySpec secretKeySpec = new SecretKeySpec(uncryaes2.getBytes(), "AES");
        System.out.println("Symmetrical Key: " + secretKeySpec);

        while (true) {

            Scanner keyboard = new Scanner(System.in);
            System.out.println("Enter Message:");
            fromUser = keyboard.nextLine();

            byte[] plaintext = fromUser.getBytes(StandardCharsets.UTF_8);

            if (fromUser != null) {

                Cipher AES_Cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
                AES_Cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
                byte ciphertext[] = AES_Cipher.doFinal(plaintext);

                String encoded = Base64.getEncoder().encodeToString(ciphertext);

                out.println(encoded);

            } else {
                break;
            }

            fromServer = in.readLine();
            if (fromServer != null) {
                Cipher AES_Cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC");
                AES_Cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

                byte[] decoded = Base64.getDecoder().decode(fromServer);
                byte[] plaintext2 = AES_Cipher.doFinal(decoded);

                System.out.println("Client receive :" + new String(plaintext2, StandardCharsets.UTF_8));

            } else {
                break;
            }
        }

        out.close();
        in.close();
        stdIn.close();
        mySocket.close();
    }

    // String to hold name of the encryption algorithm.
    public static final String ALGORITHM2 = "RSA/None/NoPadding";
    public static final String ALGORITHM = "RSA/ECB/PKCS1Padding";
    // String to hold the name of the private key file.
    public static final String PRIVATE_KEY_FILE = "keys/clientpriv.key";
    // String to hold name of the public key file.
    public static final String PUBLIC_KEY_FILE = "keys/clientpub.key";

    // Generate Keys and Save them
    public void CreateKeys() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.genKeyPair();
        Key publicKey = kp.getPublic();
        Key privateKey = kp.getPrivate();
        KeyFactory fact = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pub = fact.getKeySpec(kp.getPublic(), RSAPublicKeySpec.class);
        RSAPrivateKeySpec priv = fact.getKeySpec(kp.getPrivate(), RSAPrivateKeySpec.class);

        saveToFile("servpublic.key", pub.getModulus(), pub.getPublicExponent());
        saveToFile("servprivate.key", priv.getModulus(), priv.getPrivateExponent());

    }

    public void saveToFile(String fileName, BigInteger mod, BigInteger exp) throws IOException {
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

    // Decrypt (text, key)
    public static String decrypt(byte[] text, PrivateKey key) {
        byte[] dectyptedText = null;
        try {
            // get an RSA cipher object and print the provider
            final Cipher cipher = Cipher.getInstance(ALGORITHM);

            // decrypt the text using the private key
            cipher.init(Cipher.DECRYPT_MODE, key);
            dectyptedText = cipher.doFinal(text);

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return new String(dectyptedText);
    }

    // Decrypt (text, key)
    public static String decrypt2(byte[] text2, PublicKey key2) {
        byte[] dectyptedText2 = null;
        try {
            // get an RSA cipher object and print the provider
            final Cipher cipher = Cipher.getInstance(ALGORITHM2);

            // decrypt the text using the public key
            cipher.init(Cipher.DECRYPT_MODE, key2);
            dectyptedText2 = cipher.doFinal(text2);

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return new String(dectyptedText2);
    }

}
