package com.badrudin.aesandroid;

import android.util.Base64;

import org.jetbrains.annotations.Nullable;

import java.nio.charset.StandardCharsets;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesCrypt {
    private static String CIPHER_NAME = "AES/CBC/PKCS5PADDING";
    private static int CIPHER_KEY_LEN = 16; //128 bits

    public static String encrypt(String key, String iv, String data, boolean encryptOnly, @Nullable String type) {
        try {
            if (key.length() < CIPHER_KEY_LEN) {
                int numPad = CIPHER_KEY_LEN - key.length();

                StringBuilder keyBuilder = new StringBuilder(key);
                for (int i = 0; i < numPad; i++) {
                    keyBuilder.append("0"); //0 pad to len 16 bytes
                }
                key = keyBuilder.toString();

            } else if (key.length() > CIPHER_KEY_LEN) {
                key = key.substring(0, CIPHER_KEY_LEN); //truncate to 16 bytes
            }

            if (iv.length() < CIPHER_KEY_LEN) {
                int numPad = CIPHER_KEY_LEN - iv.length();

                StringBuilder ivBuilder = new StringBuilder(iv);
                for (int i = 0; i < numPad; i++) {
                    ivBuilder.append("0"); //0 pad to len 16 bytes
                }
                iv = ivBuilder.toString();

            } else if (iv.length() > CIPHER_KEY_LEN) {
                iv = iv.substring(0, CIPHER_KEY_LEN); //truncate to 16 bytes
            }

            IvParameterSpec initVector = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));
            SecretKeySpec sKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

            Cipher cipher = Cipher.getInstance(CIPHER_NAME);
            cipher.init(Cipher.ENCRYPT_MODE, sKeySpec, initVector);

            byte[] encryptedData = cipher.doFinal((data.getBytes()));

            String base64_EncryptedData = "";
            String base64_IV = "";
            if (type == null || type.isEmpty() || type.equalsIgnoreCase("Default")) {
                base64_EncryptedData = Base64.encodeToString(encryptedData, Base64.DEFAULT);
                base64_IV = Base64.encodeToString(iv.getBytes(StandardCharsets.UTF_8), Base64.DEFAULT);
            } else {
                if (type.equalsIgnoreCase("CRLF")) {
                    base64_EncryptedData = Base64.encodeToString(encryptedData, Base64.CRLF);
                    base64_IV = Base64.encodeToString(iv.getBytes(StandardCharsets.UTF_8), Base64.CRLF);
                } else if (type.equalsIgnoreCase("NO_CLOSE")) {
                    base64_EncryptedData = Base64.encodeToString(encryptedData, Base64.NO_CLOSE);
                    base64_IV = Base64.encodeToString(iv.getBytes(StandardCharsets.UTF_8), Base64.NO_CLOSE);
                } else if (type.equalsIgnoreCase("NO_PADDING")) {
                    base64_EncryptedData = Base64.encodeToString(encryptedData, Base64.NO_PADDING);
                    base64_IV = Base64.encodeToString(iv.getBytes(StandardCharsets.UTF_8), Base64.NO_PADDING);
                } else if (type.equalsIgnoreCase("NO_WRAP")) {
                    base64_EncryptedData = Base64.encodeToString(encryptedData, Base64.NO_WRAP);
                    base64_IV = Base64.encodeToString(iv.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
                } else if (type.equalsIgnoreCase("URL_SAFE")) {
                    base64_EncryptedData = Base64.encodeToString(encryptedData, Base64.URL_SAFE);
                    base64_IV = Base64.encodeToString(iv.getBytes(StandardCharsets.UTF_8), Base64.URL_SAFE);
                } else {
                    base64_EncryptedData = Base64.encodeToString(encryptedData, Base64.DEFAULT);
                    base64_IV = Base64.encodeToString(iv.getBytes(StandardCharsets.UTF_8), Base64.DEFAULT);
                }
            }
            if (encryptOnly)
                return base64_EncryptedData;
            else
                return base64_EncryptedData + ":" + base64_IV;

        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public static String decrypt(String key, String data, @Nullable String type) {
        if (key.length() == 16) {
            try {
                String[] parts = data.split(":");

                IvParameterSpec iv = null;

                byte[] decodedEncryptedData = new byte[0];

                if (type == null || type.isEmpty() || type.equalsIgnoreCase("Default")) {
                    iv = new IvParameterSpec(Base64.decode(parts[1], Base64.DEFAULT));
                    decodedEncryptedData = Base64.decode(parts[0], Base64.DEFAULT);
                } else {
                    if (type.equalsIgnoreCase("CRLF")) {
                        iv = new IvParameterSpec(Base64.decode(parts[1], Base64.CRLF));
                        decodedEncryptedData = Base64.decode(parts[0], Base64.CRLF);
                    } else if (type.equalsIgnoreCase("NO_CLOSE")) {
                        iv = new IvParameterSpec(Base64.decode(parts[1], Base64.NO_CLOSE));
                        decodedEncryptedData = Base64.decode(parts[0], Base64.NO_CLOSE);
                    } else if (type.equalsIgnoreCase("NO_PADDING")) {
                        iv = new IvParameterSpec(Base64.decode(parts[1], Base64.NO_PADDING));
                        decodedEncryptedData = Base64.decode(parts[0], Base64.NO_PADDING);
                    } else if (type.equalsIgnoreCase("NO_WRAP")) {
                        iv = new IvParameterSpec(Base64.decode(parts[1], Base64.NO_WRAP));
                        decodedEncryptedData = Base64.decode(parts[0], Base64.NO_WRAP);
                    } else if (type.equalsIgnoreCase("URL_SAFE")) {
                        iv = new IvParameterSpec(Base64.decode(parts[1], Base64.URL_SAFE));
                        decodedEncryptedData = Base64.decode(parts[0], Base64.URL_SAFE);
                    } else {
                        iv = new IvParameterSpec(Base64.decode(parts[1], Base64.DEFAULT));
                        decodedEncryptedData = Base64.decode(parts[0], Base64.DEFAULT);
                    }
                }

                SecretKeySpec sKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

                Cipher cipher = Cipher.getInstance(CIPHER_NAME);
                cipher.init(Cipher.DECRYPT_MODE, sKeySpec, iv);

                byte[] original = cipher.doFinal(decodedEncryptedData);
                return new String(original);
            } catch (Exception ex) {
                ex.printStackTrace();
            }
            return null;
        }
        return null;
    }

    public static String decrypt(String key, String iv, String data, @Nullable String type) {
        if (key.length() == CIPHER_KEY_LEN) {
            try {
                String[] parts = data.split(":");

                if (iv.length() < CIPHER_KEY_LEN) {
                    int numPad = CIPHER_KEY_LEN - iv.length();

                    StringBuilder ivBuilder = new StringBuilder(iv);
                    for (int i = 0; i < numPad; i++) {
                        ivBuilder.append("0"); //0 pad to len 16 bytes
                    }
                    iv = ivBuilder.toString();

                } else if (iv.length() > CIPHER_KEY_LEN) {
                    iv = iv.substring(0, CIPHER_KEY_LEN); //truncate to 16 bytes
                }

                IvParameterSpec initVector = new IvParameterSpec(iv.getBytes(StandardCharsets.UTF_8));

                SecretKeySpec sKeySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");

                Cipher cipher = Cipher.getInstance(CIPHER_NAME);

                cipher.init(Cipher.DECRYPT_MODE, sKeySpec, initVector);
                byte[] decodedEncryptedData = new byte[0];

                if (type == null || type.isEmpty() || type.equalsIgnoreCase("Default")) {
                    decodedEncryptedData = Base64.decode(parts[0], Base64.DEFAULT);
                } else {
                    if (type.equalsIgnoreCase("CRLF")) {
                        decodedEncryptedData = Base64.decode(parts[0], Base64.CRLF);
                    } else if (type.equalsIgnoreCase("NO_CLOSE")) {
                        decodedEncryptedData = Base64.decode(parts[0], Base64.NO_CLOSE);
                    } else if (type.equalsIgnoreCase("NO_PADDING")) {
                        decodedEncryptedData = Base64.decode(parts[0], Base64.NO_PADDING);
                    } else if (type.equalsIgnoreCase("NO_WRAP")) {
                        decodedEncryptedData = Base64.decode(parts[0], Base64.NO_WRAP);
                    } else if (type.equalsIgnoreCase("URL_SAFE")) {
                        decodedEncryptedData = Base64.decode(parts[0], Base64.URL_SAFE);
                    } else {
                        decodedEncryptedData = Base64.decode(parts[0], Base64.DEFAULT);
                    }
                }

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