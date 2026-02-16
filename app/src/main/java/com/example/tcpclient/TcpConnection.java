package com.example.tcpclient;

import android.util.Base64;
import android.util.Log;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.SecretKey;

import chat.CryptoHelper;
import chat.NetworkPacket;
import chat.PacketType;
import chat.User;

public class TcpConnection {
    public static Socket socket;

    private static User currentUser;
    private static int currentUserId;

    private static SecretKey sessionKey = null;

    static {
        Security.removeProvider("BC");
        Security.addProvider(new BouncyCastleProvider());
    }

    public interface PacketListener {
        void onPacketReceived(NetworkPacket packet);
    }

    private static PacketListener currentListener;
    private static Thread readingThread;
    private static volatile boolean isReading = false;

    public static void setPacketListener(PacketListener listener) {
        currentListener = listener;
        Log.d("TCP", "Listener setat: " + (listener == null ? "NULL" : listener.getClass().getSimpleName()));
    }

    public static void startReading() {
        if (isReading) return;
        isReading = true;

        readingThread = new Thread(() -> {
            Log.d("TCP", "Listener Thread PORNIT.");
            try {
                while (isReading && socket != null && !socket.isClosed()) {
                    NetworkPacket packet = readNextPacket();

                    if (packet == null) {
                        Log.e("TCP", "Pachet NULL. Conexiune moarta.");
                        close();
                        break;
                    }

                    if (currentListener != null) {
                        currentListener.onPacketReceived(packet);
                    } else {
                        Log.w("TCP", "Pachet ignorat (niciun listener activ): " + packet.getType());
                    }
                }
            } catch (Exception e) {
                Log.e("TCP", "Eroare Reading Thread: " + e.getMessage());
                close();
            }
        });
        readingThread.start();
    }

    public static void stopReading() {
        isReading = false;
    }

    public static void connect(String host, int port) throws Exception {
        socket = new Socket(host, port);

        socket.setTcpNoDelay(true);

        out = new PrintWriter(socket.getOutputStream(), true);
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        if (!performHandshake()) {
            close();
            throw new Exception("Handshake Server Esuat!");
        }
    }

    private static PrintWriter out;
    private static BufferedReader in;

    private static boolean performHandshake() {
        try {
            Log.d("TCP", "Start Handshake...");


            String jsonHello = in.readLine();
            if(jsonHello==null){
                return false;
            }

            NetworkPacket helloPacket = NetworkPacket.fromJson(jsonHello);

            if (helloPacket.getType() == PacketType.KYBER_SERVER_HELLO) {
                String payload = helloPacket.getPayload().getAsString();
                String[] parts = payload.split(":");

                byte[] serverKyberBytes = Base64.decode(parts[0], Base64.NO_WRAP);
                byte[] serverECBytes    = Base64.decode(parts[1], Base64.NO_WRAP);

                // 1. Kyber
                PublicKey serverKyberPub = CryptoHelper.decodeKyberPublicKey(serverKyberBytes);
                CryptoHelper.KEMResult kyberRes = CryptoHelper.encapsulate(serverKyberPub);

                // 2. ECDH
                KeyPair myECPair = CryptoHelper.generateECKeys();
                PublicKey serverECPub = CryptoHelper.decodeECPublicKey(serverECBytes);
                byte[] ecSecret = CryptoHelper.doECDH(myECPair.getPrivate(), serverECPub);

                // 3. Combine (KDF)
                sessionKey = CryptoHelper.combineSecrets(ecSecret, kyberRes.aesKey.getEncoded());

                // 4. Raspuns: KyberCipher:MyECPub
                String kyberCipherB64 = Base64.encodeToString(kyberRes.wrappedKey, Base64.NO_WRAP);
                String myECPubB64     = Base64.encodeToString(myECPair.getPublic().getEncoded(), Base64.NO_WRAP);

                String responsePayload = kyberCipherB64 + ":" + myECPubB64;

                NetworkPacket finishPacket = new NetworkPacket(PacketType.KYBER_CLIENT_FINISH, 0, responsePayload);

                synchronized (out) {
                    out.println(finishPacket.toJson());
                    out.flush();
                }

                Log.d("TCP", "Handshake OK! Tunel AES activ.");
                return true;
            }
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static void sendPacket(NetworkPacket packet) {
        new Thread(() -> {
            try {
                if (socket != null && !socket.isClosed()) {

                    if (sessionKey != null) {
                        String clearJson = packet.toJson();
                        byte[] encryptedBytes = CryptoHelper.encryptAndPack(sessionKey, clearJson);
                        String encryptedBase64 = Base64.encodeToString(encryptedBytes, Base64.NO_WRAP);

                        NetworkPacket envelope = new NetworkPacket(PacketType.SECURE_ENVELOPE, currentUserId, encryptedBase64);

                        synchronized (out) {
                            out.println(envelope.toJson());
                            out.flush();
                        }
                    } else {
                        synchronized (out) {
                            out.println(packet.toJson());
                            out.flush();
                        }
                    }
                }
            } catch (Exception e) {
                Log.e("TCP", "Send Error: " + e.getMessage());
            }
        }).start();
    }

    public static NetworkPacket readNextPacket() throws Exception {
        String jsonRaw = in.readLine();
        if(jsonRaw==null){
            return null;
        }

        NetworkPacket packet = NetworkPacket.fromJson(jsonRaw);


        if (sessionKey != null && packet.getType() == PacketType.SECURE_ENVELOPE) {
            try {
                String encryptedPayload = packet.getPayload().getAsString();
                byte[] packedBytes = Base64.decode(encryptedPayload, Base64.NO_WRAP);

                String originalJson = CryptoHelper.unpackAndDecrypt(sessionKey, packedBytes);
                packet = NetworkPacket.fromJson(originalJson);
            } catch (Exception e) {
                Log.e("TCP", "Eroare decriptare Tunel!");
                throw e;
            }
        }

        return packet;
    }

    public static void close() {
        try {
            isReading = false;
            sessionKey = null;
            if (out != null) out.close();
            if (in != null) in.close();
            if (socket != null) socket.close();
            Log.d("TCP", "Socket inchis.");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void setCurrentUser(User user) {
        currentUser = user;
    }

    public static User getCurrentUser() {
        return currentUser;
    }

    public static void setCurrentUserId(int id) {
        currentUserId = id;
    }

    public static int getCurrentUserId() {
        return currentUserId;
    }
}

