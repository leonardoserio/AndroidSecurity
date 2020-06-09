package com.lnascimento.androidsecurity;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

 class KitSecurity {
    private static void generateKeyStore() {
        loadKeyStore();

        KeyPairGenerator keyGenerator = null;
        try {
            keyGenerator = KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");

            keyGenerator.initialize(
                    new KeyGenParameterSpec.Builder("MyKeyAlias",
                            KeyProperties.PURPOSE_ENCRYPT |
                                    KeyProperties.PURPOSE_DECRYPT)
                            .setDigests(KeyProperties.DIGEST_SHA256,
                                    KeyProperties.DIGEST_SHA512)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
                            .setUserAuthenticationRequired(false)
                            .build());
            keyGenerator.generateKeyPair();
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException | NoSuchProviderException e) {
            Log.e("keyGenerator Error", Objects.requireNonNull(e.getMessage()));
        }

    }
    private static KeyStore loadKeyStore(){
        KeyStore keyStore
                = null;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            Log.e("Error load keystore", Objects.requireNonNull(e.getMessage()));
        }
        return keyStore;
    }

    public static String decrypt(String chave){
        KeyStore keyStore = loadKeyStore();
        if(keyStore!=null) {
            try {
                PrivateKey key = (PrivateKey) keyStore.getKey("MyKeyAlias", null);
                Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                cipher.init(Cipher.DECRYPT_MODE, key);
                byte[] bytes = Base64.decode(chave, Base64.NO_WRAP);
                String decoded = new String(cipher.doFinal(bytes));

                Log.d("Decrypt Successful", decoded);
                return decoded;
            } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
                Log.e("Decrypt Error", Objects.requireNonNull(e.getMessage()));
            }

        }
        return null;

    }

    public static String encrypt(String value) throws KeyStoreException, CertificateException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException {
        generateKeyStore();
        KeyStore keyStore
                = KeyStore.getInstance("AndroidKeyStore");
        keyStore.load(null);
        Cipher cipher = null;

        PublicKey key = keyStore.getCertificate("MyKeyAlias").getPublicKey();
        PublicKey unrestrictedPublicKey = null;
        try {
            unrestrictedPublicKey = KeyFactory.getInstance(key.getAlgorithm()).generatePublic(
                    new X509EncodedKeySpec(key.getEncoded()));
        } catch (InvalidKeySpecException e) {
            Log.e("PublicKey error", Objects.requireNonNull(e.getMessage()));
        }
        OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1",
                MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
        try {
            cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

            cipher.init(Cipher.ENCRYPT_MODE, unrestrictedPublicKey, spec);
        } catch (NoSuchPaddingException | InvalidAlgorithmParameterException e) {
            Log.e("Cipher Error", Objects.requireNonNull(e.getMessage()));
        } catch (InvalidKeyException e) {
            Log.e("InvalidKeyException", Objects.requireNonNull(e.getMessage()));
        }

        byte[] bytes = cipher.doFinal(value.getBytes());
        String encoded = Base64.encodeToString(bytes, Base64.NO_WRAP);
        Log.d("Encrypt Successful",encoded);

        return encoded;

    }
}
