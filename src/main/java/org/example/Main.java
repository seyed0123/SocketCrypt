package org.example;

import java.io.IOException;

public class Main {
    public static void main(String[] args) throws IOException {
       SocketCryptClient s = new SocketCryptClient("localhost",6548);
       s.sendMessage("hello encrypted server");
       s.getMessage();
    }
}