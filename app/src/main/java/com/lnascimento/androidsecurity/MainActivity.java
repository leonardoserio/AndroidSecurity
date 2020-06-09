package com.lnascimento.androidsecurity;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Objects;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;


public class MainActivity extends AppCompatActivity {
    EditText edtInputValue;
    TextView tvDecrypt, tvEncrypt;
    Button btnEncrypt, btnDecrypt;
    SharedPreferences preferences;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        btnEncrypt = findViewById(R.id.btn_encrypt);
        btnDecrypt = findViewById(R.id.btn_decrypt);
        tvDecrypt = findViewById(R.id.tvDecrypt);
        tvEncrypt = findViewById(R.id.tvEncrypt);
        edtInputValue = findViewById(R.id.edtValue);

        btnDecrypt.setEnabled(false);
        tvDecrypt.setVisibility(View.GONE);
        edtInputValue.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {

                    tvEncrypt.setText(R.string.result_label);
                    tvDecrypt.setText(R.string.result_label);
                    btnDecrypt.setEnabled(false);
                    tvDecrypt.setVisibility(View.GONE);
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override
            public void afterTextChanged(Editable s) {
            }
        });


        preferences = getSharedPreferences("user_preferences",MODE_PRIVATE);

        btnEncrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                String value = edtInputValue.getText().toString();
                try {
                    if(!value.equals("")) {
                        String valueEncrypted = KitSecurity.encrypt(value);
                        tvEncrypt.setText(valueEncrypted);
                        saveDataEncrypted(preferences, valueEncrypted);
                        btnDecrypt.setEnabled(true);
                        tvDecrypt.setVisibility(View.VISIBLE);
                    }else{
                        Toast.makeText(MainActivity.this, R.string.input_empty, Toast.LENGTH_SHORT).show();
                    }
                } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException | BadPaddingException | IllegalBlockSizeException e) {
                    Log.e("btnEncrypt Error", Objects.requireNonNull(e.getMessage()));
                }
            }
        });
        btnDecrypt.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {

                String valueDecrypted = KitSecurity.decrypt(getValueSharedPrefence(preferences));
                if(valueDecrypted!=null){
                    tvDecrypt.setText(valueDecrypted);

                }
            }
        });
    }
    private String getValueSharedPrefence(SharedPreferences preferences){
        return preferences.getString("valueEncrypted","");
    }

    private void saveDataEncrypted( SharedPreferences preferences, String data){

        SharedPreferences.Editor editor= preferences.edit();
        editor.putString("valueEncrypted",data);
        editor.apply();

    }

}
