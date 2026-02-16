package com.example.tcpclient;

import android.annotation.SuppressLint;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.Spinner;
import android.widget.Toast;
import android.window.OnBackInvokedCallback;
import android.window.OnBackInvokedDispatcher;

import androidx.activity.EdgeToEdge;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.graphics.Insets;
import androidx.core.view.ViewCompat;
import androidx.core.view.WindowInsetsCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

import chat.ChatDtos;
import chat.GroupChat;
import chat.NetworkPacket;
import chat.PacketType;
import chat.User;

public class MainActivity extends AppCompatActivity {
    RecyclerView recyclerView;
    ConversationAdapter adapter;
    private final Gson gson = new Gson();

    AlertDialog dialog;

    private Spinner pendingSpinner;
    private List<String> pendingRawUsers;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        EdgeToEdge.enable(this);
        setContentView(R.layout.activity_main);

        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.loginLayout), (v, insets) -> {
            Insets systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars());
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom);
            return insets;
        });

        recyclerView = findViewById(R.id.recyclerViewConversations);
        recyclerView.setLayoutManager(new LinearLayoutManager(this));

        adapter = new ConversationAdapter(
                this,
                LocalStorage.getCurrentUserGroupChats(),
                this::handleChatClick,
                this::handleLongChatClick
        );
        recyclerView.setAdapter(adapter);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            OnBackInvokedCallback callback = () -> {
                if (dialog != null && dialog.isShowing()) {
                    Toast.makeText(MainActivity.this, "Finalizează acțiunea înainte de a ieși!", Toast.LENGTH_SHORT).show();
                    return;
                }
                handleLogout();
            };
            getOnBackInvokedDispatcher().registerOnBackInvokedCallback(OnBackInvokedDispatcher.PRIORITY_DEFAULT, callback);
        }

        TcpConnection.startReading();
    }

    @Override
    protected void onResume() {
        super.onResume();

        Socket socket = TcpConnection.socket;
        if (socket == null || socket.isClosed() || !socket.isConnected()) {
            attemptAutoReconnect();
        } else {
            TcpConnection.setPacketListener(this::handlePacketOnUI);
            refreshConversations();
        }
    }

    private void handlePacketOnUI(NetworkPacket packet) {
        runOnUiThread(() -> handlePacket(packet));
    }

    private void handlePacket(NetworkPacket packet) {
        switch (packet.getType()) {
            case GET_CHATS_RESPONSE:
                try {
                    Type listType = new TypeToken<List<GroupChat>>(){}.getType();
                    List<GroupChat> groupChats = gson.fromJson(packet.getPayload(), listType);

                    if (groupChats == null) groupChats = new ArrayList<>();

                    LocalStorage.setCurrentUserGroupChats(groupChats);
                    adapter.setGroupChats(groupChats);
                    adapter.notifyDataSetChanged();
                } catch (Exception e) { e.printStackTrace(); }
                break;

            case GET_USERS_RESPONSE:
                try {
                    Type userListType = new TypeToken<List<String>>(){}.getType();
                    List<String> serverList = gson.fromJson(packet.getPayload(), userListType);
                    updateSpinnerData(serverList);
                } catch (Exception e) { e.printStackTrace(); }
                break;

            case CREATE_CHAT_BROADCAST:
                GroupChat newChat = gson.fromJson(packet.getPayload(), GroupChat.class);

                if (adapter != null) adapter.setEnabled(true);
                if (dialog != null && dialog.isShowing()) dialog.dismiss();

                if (newChat.getId() <= 0) {
                    Log.e("CHAT_DEBUG", "Chat primit cu ID 0 sau invalid. Ignor.");
                    refreshConversations();

                    break;
                }

                LocalStorage.getCurrentUserGroupChats().add(0, newChat);
                adapter.setGroupChats(LocalStorage.getCurrentUserGroupChats());

                adapter.notifyDataSetChanged();
                recyclerView.scrollToPosition(0);

                break;

            case RENAME_CHAT_BROADCAST:
                ChatDtos.RenameGroupDto renameDto = gson.fromJson(packet.getPayload(), ChatDtos.RenameGroupDto.class);

                List<GroupChat> currentList = LocalStorage.getCurrentUserGroupChats();
                for (int i = 0; i < currentList.size(); i++) {
                    if (currentList.get(i).getId() == renameDto.chatId) {
                        currentList.get(i).setName(renameDto.newName);
                        adapter.notifyItemChanged(i);
                        break;
                    }
                }
                break;

            case DELETE_CHAT_BROADCAST:
                int deletedId = gson.fromJson(packet.getPayload(), Integer.class);

                List<GroupChat> deleteList = LocalStorage.getCurrentUserGroupChats();
                for (int i = 0; i < deleteList.size(); i++) {
                    if (deleteList.get(i).getId() == deletedId) {
                        deleteList.remove(i);
                        adapter.notifyItemRemoved(i);
                        break;
                    }
                }
                break;
        }
    }

    private void refreshConversations() {
        NetworkPacket req = new NetworkPacket(PacketType.GET_CHATS_REQUEST, TcpConnection.getCurrentUserId());
        TcpConnection.sendPacket(req);
    }

    private void performRename(GroupChat chat, String newName) {
        ChatDtos.RenameGroupDto dto = new ChatDtos.RenameGroupDto(chat.getId(), newName);
        NetworkPacket packet = new NetworkPacket(PacketType.RENAME_CHAT_REQUEST, TcpConnection.getCurrentUserId(), dto);
        TcpConnection.sendPacket(packet);
    }

    private void performDelete(GroupChat chat) {
        NetworkPacket packet = new NetworkPacket(PacketType.DELETE_CHAT_REQUEST, TcpConnection.getCurrentUserId(), chat.getId());
        TcpConnection.sendPacket(packet);
    }

    private void performCreateChat(int targetId, String groupName) {
        ChatDtos.CreateGroupDto dto = new ChatDtos.CreateGroupDto(targetId, groupName);
        NetworkPacket req = new NetworkPacket(PacketType.CREATE_CHAT_REQUEST, TcpConnection.getCurrentUserId(), dto);
        TcpConnection.sendPacket(req);
    }

    private void performLogout() {
        NetworkPacket p = new NetworkPacket(PacketType.LOGOUT, TcpConnection.getCurrentUserId());
        TcpConnection.sendPacket(p);

        new android.os.Handler().postDelayed(() -> {
            TcpConnection.stopReading();
            TcpConnection.close();
            runOnUiThread(() -> {
                SharedPreferences prefs = SecureStorage.getEncryptedPrefs(MainActivity.this);
                prefs.edit().clear().apply();
                goToLogin();
            });
        }, 300);
    }

    private void loadUsersForSpinner(Spinner spinner, List<String> rawUserStrings) {
        this.pendingSpinner = spinner;
        this.pendingRawUsers = rawUserStrings;
        NetworkPacket req = new NetworkPacket(PacketType.GET_USERS_REQUEST, TcpConnection.getCurrentUserId());
        TcpConnection.sendPacket(req);
    }

    private void updateSpinnerData(List<String> serverList) {
        if (pendingSpinner == null || pendingRawUsers == null) return;
        pendingRawUsers.clear();
        pendingRawUsers.addAll(serverList);
        List<String> displayNames = new ArrayList<>();
        for (String s : serverList) {
            String[] parts = s.split(",");
            if (parts.length > 1) displayNames.add(parts[1]);
            else displayNames.add(s);
        }
        setupSpinner(pendingSpinner, displayNames.toArray(new String[0]));
    }

    @SuppressLint({"GestureBackNavigation", "MissingSuperCall"})
    @Override
    public void onBackPressed() {
        if (dialog != null && dialog.isShowing()) {
            Toast.makeText(this, "Finalizează acțiunea înainte de a ieși!", Toast.LENGTH_SHORT).show();
            return;
        }
        handleLogout();
    }

    public void handleChatClick(GroupChat chat) {
        Intent intent = new Intent(this, ConversationActivity.class);
        intent.putExtra("CHAT_ID", chat.getId());
        intent.putExtra("CHAT_NAME", chat.getName());

        int partnerId = 0;
        intent.putExtra("PARTNER_ID", partnerId);

        startActivity(intent);
    }

    public void handleLongChatClick(GroupChat chat) {
        String[] options = {"Rename ", "Delete "};
        ArrayAdapter<String> adapter = new ArrayAdapter<>(this, R.layout.dialog_option_item, options);
        new AlertDialog.Builder(MainActivity.this, R.style.DialogSmecher)
                .setTitle(chat.getName())
                .setAdapter(adapter, (dialog, which) -> {
                    if (which == 0) renameChat(chat);
                    else deleteChat(chat);
                })
                .setNegativeButton("Cancel", (dialog, which) -> dialog.cancel())
                .show();
    }

    public void renameChat(GroupChat chat) {
        EditText input = new EditText(this);
        input.setTextColor(Color.WHITE);
        input.setHintTextColor(Color.LTGRAY);
        input.setHint("Enter the new name ");
        new AlertDialog.Builder(this, R.style.DialogSmecher)
                .setTitle("Rename " + chat.getName())
                .setView(input)
                .setPositiveButton("Save ", (dialog, which) -> {
                    String newName = input.getText().toString().trim();
                    if (!newName.isEmpty()) performRename(chat, newName);
                })
                .setNegativeButton("Cancel ", (dialog, which) -> dialog.cancel())
                .show();
    }

    public void deleteChat(GroupChat chat) {
        new AlertDialog.Builder(this, R.style.DialogSmecher)
                .setTitle("Delete chat ")
                .setMessage("Are you sure you want to delete \"" + chat.getName() + "\"?")
                .setPositiveButton("Delete ", (dialog, which) -> performDelete(chat))
                .setNegativeButton("Cancel ", (dialog, which) -> dialog.cancel())
                .show();
    }

    public void handleAddConversation(View view) {
        adapter.setEnabled(false);
        LayoutInflater inflater = getLayoutInflater();
        View dialogView = inflater.inflate(R.layout.dialog_with_spinner, null);
        EditText editGroupName = dialogView.findViewById(R.id.editGroupName);
        Spinner spinner = dialogView.findViewById(R.id.mySpinner);
        editGroupName.setTextColor(Color.WHITE);
        editGroupName.setHintTextColor(Color.LTGRAY);
        setupSpinner(spinner, new String[]{"Loading...", "Please wait"});
        List<String> rawUserStrings = new ArrayList<>();

        dialog = new AlertDialog.Builder(MainActivity.this, R.style.DialogSmecher)
                .setTitle("Add a new conversation")
                .setView(dialogView)
                .setNegativeButton("Cancel", (d, w) -> { adapter.setEnabled(true); d.cancel(); })
                .setPositiveButton("OK", (d, w) -> {
                    String groupName = editGroupName.getText().toString().trim();
                    if (groupName.isEmpty()) { Toast.makeText(this, "Enter a group name!", Toast.LENGTH_SHORT).show(); adapter.setEnabled(true); return; }
                    int index = spinner.getSelectedItemPosition();
                    if (index < 0 || index >= rawUserStrings.size()) { Toast.makeText(this, "No user selected!", Toast.LENGTH_SHORT).show(); adapter.setEnabled(true); return; }
                    String selectedRaw = rawUserStrings.get(index);
                    int targetId = Integer.parseInt(selectedRaw.split(",")[0]);
                    performCreateChat(targetId, groupName);
                }).create();
        dialog.setCancelable(false);
        dialog.setCanceledOnTouchOutside(false);
        dialog.show();
        loadUsersForSpinner(spinner, rawUserStrings);
    }

    private void setupSpinner(Spinner spinner, String[] items) {
        ArrayAdapter<String> adapter = new ArrayAdapter<String>(this, android.R.layout.simple_spinner_item, items) {
            @Override public View getView(int position, View convertView, android.view.ViewGroup parent) {
                android.widget.TextView view = (android.widget.TextView) super.getView(position, convertView, parent);
                view.setTextColor(Color.WHITE);
                return view;
            }
            @Override public View getDropDownView(int position, View convertView, android.view.ViewGroup parent) {
                android.widget.TextView view = (android.widget.TextView) super.getDropDownView(position, convertView, parent);
                view.setTextColor(Color.WHITE);
                view.setBackgroundColor(Color.parseColor("#1c2630"));
                return view;
            }
        };
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);
        spinner.setAdapter(adapter);
    }

    public void handleLogout() {
        if (adapter != null) adapter.setEnabled(false);
        AlertDialog d = new AlertDialog.Builder(MainActivity.this, R.style.DialogSmecher)
                .setTitle("Do you wish to logout ")
                .setNegativeButton("NO ", (dialog, which) -> { if (adapter != null) adapter.setEnabled(true); dialog.cancel(); })
                .setPositiveButton("YES ", (dialog, which) -> performLogout()).create();
        d.setCancelable(false);
        d.show();
    }

    private void goToLogin() {
        Intent intent = new Intent(MainActivity.this, LoginActivity.class);
        intent.addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP | Intent.FLAG_ACTIVITY_NEW_TASK);
        startActivity(intent);
        finish();
    }

    private void attemptAutoReconnect() {
        SharedPreferences preferences = SecureStorage.getEncryptedPrefs(getApplicationContext());
        String savedUser = preferences.getString("username", null);
        String savedPassword = preferences.getString("password", null);
        if (savedUser == null || savedPassword == null) { goToLogin(); return; }

        new Thread(() -> {
            try {
                ConfigReader configReader = new ConfigReader(this);
                TcpConnection.connect(configReader.getServerIp(), configReader.getServerPort());

                ChatDtos.AuthDto authDto = new ChatDtos.AuthDto(savedUser, savedPassword);
                NetworkPacket req = new NetworkPacket(PacketType.LOGIN_REQUEST, 0, authDto);
                TcpConnection.sendPacket(req);

                NetworkPacket resp = TcpConnection.readNextPacket();

                if (resp.getType() == PacketType.LOGIN_RESPONSE) {
                    User user = gson.fromJson(resp.getPayload(), User.class);
                    if (user != null) {
                        TcpConnection.setCurrentUser(user);
                        TcpConnection.setCurrentUserId(user.getId());
                        runOnUiThread(() -> {
                            Toast.makeText(this, "Reconectat automat!", Toast.LENGTH_SHORT).show();

                            TcpConnection.startReading();
                            TcpConnection.setPacketListener(this::handlePacketOnUI);
                            refreshConversations();
                        });
                    } else runOnUiThread(this::goToLogin);
                } else runOnUiThread(this::goToLogin);

            } catch (Exception e) {
                e.printStackTrace();
                runOnUiThread(this::goToLogin);
            }
        }).start();
    }
}
