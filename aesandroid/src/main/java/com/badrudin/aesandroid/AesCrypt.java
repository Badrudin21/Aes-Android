package com.badrudin.aesandroid;

import android.util.Base64;

import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesCrypt {
    private static String CIPHER_NAME = "AES/CBC/PKCS5PADDING";
    private static int CIPHER_KEY_LEN = 16; //128 bits

    public static String encrypt(String key, String iv, String data, boolean encryptOnly) {
        try {
            if (key.length() < AesCrypt.CIPHER_KEY_LEN) {
                int numPad = AesCrypt.CIPHER_KEY_LEN - key.length();

                StringBuilder keyBuilder = new StringBuilder(key);
                for(int i = 0; i < numPad; i++){
                    keyBuilder.append("0"); //0 pad to len 16 bytes
                }
                key = keyBuilder.toString();

            } else if (key.length() > AesCrypt.CIPHER_KEY_LEN) {
                key = key.substring(0, CIPHER_KEY_LEN); //truncate to 16 bytes
            }

            if (iv.length() < AesCrypt.CIPHER_KEY_LEN) {
                int numPad = AesCrypt.CIPHER_KEY_LEN - iv.length();

                StringBuilder ivBuilder = new StringBuilder(iv);
                for(int i = 0; i < numPad; i++){
                    ivBuilder.append("0"); //0 pad to len 16 bytes
                }
                iv = ivBuilder.toString();

            } else if (iv.length() > AesCrypt.CIPHER_KEY_LEN) {
                iv = iv.substring(0, CIPHER_KEY_LEN); //truncate to 16 bytes
            }

            IvParameterSpec initVector = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec sKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

            Cipher cipher = Cipher.getInstance(AesCrypt.CIPHER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, sKeySpec, initVector);

            byte[] encryptedData = cipher.doFinal((data.getBytes()));

            String base64_EncryptedData = Base64.encodeToString(encryptedData,Base64.DEFAULT);
            String base64_IV = Base64.encodeToString(iv.getBytes(StandardCharsets.UTF_8),Base64.DEFAULT);

            if (encryptOnly)
                return base64_EncryptedData;
            else
                return base64_EncryptedData + ":" + base64_IV;

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String key, String data) {
        if (key.length()==16) {
            try {
                String[] parts = data.split(":");
                IvParameterSpec iv = new IvParameterSpec(Base64.decode(parts[1], Base64.DEFAULT));

                SecretKeySpec sKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

                Cipher cipher = Cipher.getInstance(AesCrypt.CIPHER_NAME);
                cipher.init(Cipher.DECRYPT_MODE, sKeySpec, iv);

                byte[] decodedEncryptedData = Base64.decode(parts[0], Base64.DEFAULT);

                byte[] original = cipher.doFinal(decodedEncryptedData);
                return new String(original);
            } catch (Exception ex) {
                ex.printStackTrace();
            }
            return null;
        }
        return null;
    }

    public static String decrypt(String key, String iv, String data) {
        if (key.length()==CIPHER_KEY_LEN) {
            try {
                String[] parts = data.split(":");

                if (iv.length() < AesCrypt.CIPHER_KEY_LEN) {
                    int numPad = AesCrypt.CIPHER_KEY_LEN - iv.length();

                    StringBuilder ivBuilder = new StringBuilder(iv);
                    for(int i = 0; i < numPad; i++){
                        ivBuilder.append("0"); //0 pad to len 16 bytes
                    }
                    iv = ivBuilder.toString();

                } else if (iv.length() > AesCrypt.CIPHER_KEY_LEN) {
                    iv = iv.substring(0, CIPHER_KEY_LEN); //truncate to 16 bytes
                }

                IvParameterSpec initVector = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));

                SecretKeySpec sKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

                Cipher cipher = Cipher.getInstance(AesCrypt.CIPHER_NAME);

                cipher.init(Cipher.DECRYPT_MODE, sKeySpec, initVector);
                byte[] decodedEncryptedData = Base64.decode(parts[0], Base64.DEFAULT);

                byte[] original = cipher.doFinal(decodedEncryptedData);
                return new String(original);
            } catch (Exception ex) {
                ex.printStackTrace();
                return null;
            }
        }
        return null;
    }
}