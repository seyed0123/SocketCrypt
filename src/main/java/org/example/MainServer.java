package org.example;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class MainServer {

    public static void main(String[] args) throws IOException {
        try (ServerSocket serverSocket = new ServerSocket(6548)) {
            Socket clientSocket = serverSocket.accept();
            SocketCryptServer s = new SocketCryptServer(clientSocket);
            System.out.println("Client connected." + clientSocket.getLocalSocketAddress());
            s.getMessage();
            s.sendMessage("hi encrypted client");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
