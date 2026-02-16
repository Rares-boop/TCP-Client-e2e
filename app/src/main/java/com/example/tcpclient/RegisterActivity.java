package com.example.tcpclient;

import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.view.View;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.Toast;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;

import com.google.android.material.snackbar.Snackbar;
import com.google.gson.Gson;
import com.google.gson.JsonElement;

import java.security.KeyPair;
import java.util.Base64;

import chat.ChatDtos;
import chat.CryptoHelper;
import chat.NetworkPacket;
import chat.PacketType;
import chat.User;

public class RegisterActivity extends AppCompatActivity {
    private ConfigReader config;
    private SharedPreferences preferences;
    private final Gson gson = new Gson();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_register);

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        config = new ConfigReader(this);

        try {
            preferences = SecureStorage.getEncryptedPrefs(getApplicationContext());
        } catch (Exception e) {
            preferences = getSharedPreferences("ChatPrefs", MODE_PRIVATE);
        }
    }

    public void handleAccount(View view) {
        EditText usernameField = findViewById(R.id.editTextText);
        EditText passwordField = findViewById(R.id.editTextTextPassword2);
        EditText confirmedPasswordField = findViewById(R.id.editTextTextPassword3);
        CheckBox checkBox = findViewById(R.id.checkBoxKeepSignedInRegister);

        String username = usernameField.getText().toString().trim();
        String password = passwordField.getText().toString().trim();
        String confirmedPassword = confirmedPasswordField.getText().toString().trim();

        if (username.isEmpty() || password.isEmpty() || confirmedPassword.isEmpty()) {
            Toast.makeText(this, "Completeaza toate campurile!", Toast.LENGTH_SHORT).show();
            return;
        }

        if (!password.equals(confirmedPassword)) {
            Toast.makeText(this, "Parolele nu coincid!", Toast.LENGTH_SHORT).show();
            return;
        }

        Toast.makeText(this, "Inregistrare...", Toast.LENGTH_SHORT).show();
        view.setEnabled(false);

        new Thread(() -> {
            try {
                TcpConnection.close();

                TcpConnection.connect(config.getServerIp(), config.getServerPort());

                ChatDtos.AuthDto registerData = new ChatDtos.AuthDto(username, password);
                NetworkPacket request = new NetworkPacket(PacketType.REGISTER_REQUEST, 0, registerData);

                TcpConnection.sendPacket(request);

                NetworkPacket responsePacket = TcpConnection.readNextPacket();

                runOnUiThread(() -> {
                    view.setEnabled(true);

                    if (responsePacket != null && responsePacket.getType() == PacketType.REGISTER_RESPONSE) {
                        handleRegisterResponse(responsePacket, username, password, checkBox.isChecked());
                    } else {
                        showSnackbar("Eroare server: Raspuns invalid.");
                    }
                });

            } catch (Exception e) {
                e.printStackTrace();
                TcpConnection.close();
                runOnUiThread(() -> {
                    view.setEnabled(true);
                    showSnackbar("Eroare Conexiune: " + e.getMessage());
                });
            }
        }).start();
    }

    private void handleRegisterResponse(NetworkPacket packet, String userStr, String passStr, boolean save) {
        try {
            JsonElement payload = packet.getPayload();

            if (payload.isJsonObject()) {
                User user = gson.fromJson(payload, User.class);

                if (user != null && user.getUsername() != null) {
                    TcpConnection.setCurrentUser(user);
                    TcpConnection.setCurrentUserId(user.getId());

                    SharedPreferences.Editor editor = preferences.edit();
                    if (save) {
                        editor.putString("username", userStr);
                        editor.putString("password", passStr);
                    } else {
                        editor.remove("username");
                        editor.remove("password");
                    }
                    editor.apply();

                    Toast.makeText(this, "Cont creat cu succes!", Toast.LENGTH_SHORT).show();

                    new Thread(() -> {
                        try {
                            ClientKeyManager clientKeyManager = new ClientKeyManager(this);

                            KeyPair identityKP = CryptoHelper.generateDilithiumKeys();
                            KeyPair preKeyKP = CryptoHelper.generateKyberKeys();

                            String ikPub = android.util.Base64.encodeToString(identityKP.getPublic().getEncoded(), android.util.Base64.NO_WRAP);
                            String ikPriv = android.util.Base64.encodeToString(identityKP.getPrivate().getEncoded(), android.util.Base64.NO_WRAP);

                            String spkPub = android.util.Base64.encodeToString(preKeyKP.getPublic().getEncoded(), android.util.Base64.NO_WRAP);
                            String spkPriv = android.util.Base64.encodeToString(preKeyKP.getPrivate().getEncoded(), android.util.Base64.NO_WRAP);

                            byte[] signatureBytes = CryptoHelper.signData(
                                    identityKP.getPrivate(),
                                    preKeyKP.getPublic().getEncoded()
                            );
                            String signatureBase64 = android.util.Base64.encodeToString(signatureBytes, android.util.Base64.NO_WRAP);

                            clientKeyManager.saveMyIdentityKeys(ikPub, ikPriv, spkPub, spkPriv);

                            ChatDtos.PublishKeysDto dto = new ChatDtos.PublishKeysDto(ikPub, spkPub, signatureBase64);
                            TcpConnection.sendPacket(new NetworkPacket(PacketType.PUBLISH_KEYS, user.getId(), dto));

                            System.out.println("✅ Chei generate si trimise!");

                            runOnUiThread(() -> {
                                Toast.makeText(this, "Cont Securizat Activat!", Toast.LENGTH_SHORT).show();
                                Intent intent = new Intent(RegisterActivity.this, MainActivity.class);
                                startActivity(intent);
                                finish();
                            });

                        } catch (Exception e) {
                            e.printStackTrace();
                            runOnUiThread(() -> {
                                showSnackbar("Eroare critica la generarea cheilor: " + e.getMessage());
                            });
                        }
                    }).start();

                }
            } else {
                String errorMsg = gson.fromJson(payload, String.class);
                showSnackbar(errorMsg);

                ((EditText)findViewById(R.id.editTextTextPassword2)).setText("");
                ((EditText)findViewById(R.id.editTextTextPassword3)).setText("");
            }
        } catch (Exception e) {
            showSnackbar("Eroare procesare raspuns server.");
        }
    }

    private void showSnackbar(String message) {
        Snackbar.make(
                findViewById(android.R.id.content),
                message,
                Snackbar.LENGTH_LONG
        ).setBackgroundTint(Color.RED).setTextColor(Color.WHITE).show();
    }
}