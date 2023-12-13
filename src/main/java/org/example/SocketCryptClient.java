package org.example;

import com.google.gson.Gson;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

public class SocketCryptClient extends Socket{
    public Socket socket;
    private final ObjectOutputStream objOut;
    private Cipher cipherEncrypt;
    private Cipher cipherDecrypt;
    private final Gson gson;
    private final PrintWriter output;
    private final BufferedReader input;

    public SocketCryptClient(String host, int port) throws IOException {
        super(host, port);
        socket = this;
        input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        output = new PrintWriter(socket.getOutputStream(), true);
        objOut = new ObjectOutputStream(socket.getOutputStream());
        gson = new Gson();
        startCom();
    }

    public void sendMessage(String message)
    {
        try {
            byte[] encrypt = cipherEncrypt.doFinal(message.getBytes());
            String base64Data = Base64.getEncoder().encodeToString(encrypt);
            output.println(gson.toJson(base64Data));
            System.out.println("The actual string that was sent: '"+base64Data +"'\nthe String that we sent: "+message);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }
    public String getMessage()
    {
        try {
            String base64 = gson.fromJson(input.readLine(),String.class);
            byte[] decodedData = Base64.getDecoder().decode(base64);
            byte[] decrypted = cipherDecrypt.doFinal(decodedData);
            System.out.println("The actual string that was received: '"+base64+"'\nThe message from server: "+new String(decrypted));
            return new String(decrypted);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }

    private void startCom()
    {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
            objOut.writeObject(publicKey);
            objOut.flush();

            String base64 = gson.fromJson(input.readLine(),String.class);
            byte[] encryptedMessage = Base64.getDecoder().decode(base64);
            byte[] decryptedMessage = decryptCipher.doFinal(encryptedMessage);

            cipherDecrypt = Cipher.getInstance("AES");
            cipherDecrypt.init(Cipher.DECRYPT_MODE,  new SecretKeySpec(decryptedMessage, "AES"));
            cipherEncrypt= Cipher.getInstance("AES");
            cipherEncrypt.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(decryptedMessage, "AES"));
        }catch (NoSuchAlgorithmException | NoSuchPaddingException e)
        {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }
}
