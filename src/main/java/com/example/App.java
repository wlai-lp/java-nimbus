package com.example;

/**
 * Hello world!
 */
public final class App {
    private App() {
    }

    /**
     * Says hello to the world.
     * @param args The arguments of the program.
     */
    public static void main(String[] args) {
        System.out.println("Hello World!");
        EncryptedJWTTest test = new EncryptedJWTTest();
        try {
            
            test.testEncryptAndDecrypt();
        } catch (Exception e) {
            // TODO: handle excesption
            System.err.println(e);
        }
    }
}
