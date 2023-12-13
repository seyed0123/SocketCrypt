package org.example;

import com.google.gson.Gson;

import javax.crypto.*;
import java.io.*;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

public class SocketCryptServer{

    public Socket socket;
    private Cipher cipherEncrypt;
    private Cipher cipherDecrypt;
    private Gson gson;

    private BufferedReader input ;
    private PrintWriter output ;

    private ObjectInputStream objIn;


    public SocketCryptServer(Socket socket) {
        this.socket = socket;
        try {
            objIn = new ObjectInputStream(socket.getInputStream());
            input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            output = new PrintWriter(socket.getOutputStream(), true);
            gson = new Gson();
            setKeys();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void sendMessage(String message)
    {
        try {
            byte[] encrypt = cipherEncrypt.doFinal(message.getBytes());
            String base64Data = Base64.getEncoder().encodeToString(encrypt);
            output.println(gson.toJson(base64Data));
            System.out.println("The actual string that was sent: '"+base64Data+"'\nthe String that we sent: "+message);
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
            System.out.println("The actual string that was received: '"+base64+"'\nThe message from client: "+new String(decrypted));
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

    private void setKeys()
    {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey secretKey = keyGen.generateKey();

            Cipher encryptCipher = Cipher.getInstance("RSA");

            RSAPublicKey publicKey = (RSAPublicKey) objIn.readObject();
            //objIn.close();
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);


            byte[] encrypted = encryptCipher.doFinal(secretKey.getEncoded());
            String base64Data = Base64.getEncoder().encodeToString(encrypted);
            output.println(gson.toJson(base64Data));

            cipherEncrypt = Cipher.getInstance("AES");
            cipherEncrypt.init(Cipher.ENCRYPT_MODE, secretKey);
            cipherDecrypt = Cipher.getInstance("AES");
            cipherDecrypt.init(Cipher.DECRYPT_MODE, secretKey);


        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchPaddingException e) {
            throw new RuntimeException(e);
        } catch (InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (IllegalBlockSizeException e) {
            throw new RuntimeException(e);
        } catch (BadPaddingException e) {
            throw new RuntimeException(e);
        } catch (ClassNotFoundException e) {
            throw new RuntimeException(e);
        }
    }

}
