package com.example.tcpclient;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import androidx.security.crypto.EncryptedSharedPreferences;
import androidx.security.crypto.MasterKey;

import java.io.IOException;
import java.security.GeneralSecurityException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import chat.CryptoHelper;

public class ClientKeyManager {
    private static final String PREF_FILE_NAME = "secure_chat_keys";

    // Constante pentru cheile tale Post-Quantum (Identitatea ta)
    private static final String KEY_IK_PUB = "MY_IDENTITY_PUB_DILITHIUM";
    private static final String KEY_IK_PRIV = "MY_IDENTITY_PRIV_DILITHIUM";
    private static final String KEY_SPK_PUB = "MY_PREKEY_PUB_KYBER";
    private static final String KEY_SPK_PRIV = "MY_PREKEY_PRIV_KYBER";

    private SharedPreferences securePrefs;

    public ClientKeyManager(Context context) {
        try {
            // Folosim MasterKey pentru criptare hardware-backed (Foarte sigur!)
            MasterKey masterKey = new MasterKey.Builder(context)
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .build();

            this.securePrefs = EncryptedSharedPreferences.create(
                    context,
                    PREF_FILE_NAME,
                    masterKey,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            );

        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
            // Fallback pe shared prefs simplu daca telefonul e vechi si nu suporta criptare
            this.securePrefs = context.getSharedPreferences(PREF_FILE_NAME, Context.MODE_PRIVATE);
        }
    }

    // =============================================================
    // PARTEA 1: CHEI SESIUNE CHAT (AES - Ce aveai tu deja)
    // =============================================================

    public boolean hasKey(int chatId) {
        return securePrefs.contains(String.valueOf(chatId));
    }

    public void saveKey(int chatId, String base64Key) {
        securePrefs.edit().putString(String.valueOf(chatId), base64Key).apply();
    }

    public SecretKey getKey(int chatId) {
        String base64 = securePrefs.getString(String.valueOf(chatId), null);
        if (base64 == null) return null;

        byte[] decoded = Base64.decode(base64, Base64.NO_WRAP);
        return new SecretKeySpec(decoded, "AES");
    }

    public String generateAndSaveKey(int chatId) {
        try {
            SecretKey key = CryptoHelper.generateAESKey(256);
            String base64 = Base64.encodeToString(key.getEncoded(), Base64.NO_WRAP);

            saveKey(chatId, base64);
            return base64;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    // =============================================================
    // PARTEA 2: NOILE METODE PENTRU POST-QUANTUM (Dilithium + Kyber)
    // =============================================================

    /**
     * Salvam Identitatea noastra Post-Quantum.
     * Astea sunt generate la Register si le tinem aici ca sa putem decripta mesaje oricand.
     */
    public void saveMyIdentityKeys(String ikPub, String ikPriv, String spkPub, String spkPriv) {
        securePrefs.edit()
                .putString(KEY_IK_PUB, ikPub)
                .putString(KEY_IK_PRIV, ikPriv)
                .putString(KEY_SPK_PUB, spkPub)
                .putString(KEY_SPK_PRIV, spkPriv)
                .apply();
    }

    // Verificam daca avem identitate generata (pentru Login vs Register check)
    public boolean hasIdentity() {
        return securePrefs.contains(KEY_IK_PRIV) && securePrefs.contains(KEY_SPK_PRIV);
    }

    // --- GETTERS (Le folosim cand primim mesaje sau semnam chestii) ---

    public String getMyIdentityPublicKey() {
        return securePrefs.getString(KEY_IK_PUB, null);
    }

    public String getMyIdentityPrivateKey() {
        return securePrefs.getString(KEY_IK_PRIV, null);
    }

    public String getMyPreKeyPublicKey() {
        return securePrefs.getString(KEY_SPK_PUB, null);
    }

    public String getMyPreKeyPrivateKey() {
        return securePrefs.getString(KEY_SPK_PRIV, null);
    }

    // Sterge tot (la Logout)
    public void clearAll() {
        securePrefs.edit().clear().apply();
    }
}
