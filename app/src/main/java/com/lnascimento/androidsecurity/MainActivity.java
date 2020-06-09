package com.lnascimento.androidsecurity;

import androidx.appcompat.app.AppCompatActivity;

import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;

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
import javax.crypto.IllegalBlockSizeException;


public class MainActivity extends AppCompatActivity {
    String chave = null;
    Button btnEncrypt, btnDecrypt;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        btnEncrypt = findViewById(R.id.btn_encrypt);
        btnDecrypt = findViewById(R.id.btn_decrypt);
        btnDecrypt.setEnabled(false);

        btnEncrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    KitSecurity.encrypt("Leonardo");
                    btnDecrypt.setEnabled(true);
                } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException | BadPaddingException | IllegalBlockSizeException e) {
                    Log.e("btnEncrypt Error", Objects.requireNonNull(e.getMessage()));
                }
            }
        });
        btnDecrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                KitSecurity.decrypt("asdf");
            }
        });
    }

}
