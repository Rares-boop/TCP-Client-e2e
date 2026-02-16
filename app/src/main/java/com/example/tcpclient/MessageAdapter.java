package com.example.tcpclient;

import android.content.Context;
import android.text.format.DateUtils;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;


import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Locale;

import chat.Message;

public class MessageAdapter extends RecyclerView.Adapter<MessageAdapter.MessageViewHolder> {
    private final List<Message> messages;
    private final int currentUserId;
    private final Context context;

    private static final int VIEW_TYPE_MINE = 1;
    private static final int VIEW_TYPE_FRIEND = 2;

    private final OnMessageLongClickListener longClickListener;

    public interface OnMessageLongClickListener{
        void onMessageLongClick(Message message);
    }

    public MessageAdapter(Context context, List<Message> messages, int currentUserId,
                          OnMessageLongClickListener longClickListener) {
        this.context = context;
        this.messages = messages;
        this.currentUserId = currentUserId;
        this.longClickListener = longClickListener;
    }

    @Override
    public int getItemViewType(int position) {
        Message message = messages.get(position);
        return (message.getSenderId() == currentUserId) ? VIEW_TYPE_MINE : VIEW_TYPE_FRIEND;
    }

    @NonNull
    @Override
    public MessageViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view;
        if (viewType == VIEW_TYPE_MINE) {
            view = LayoutInflater.from(context).inflate(R.layout.item_message_right, parent, false);
        } else {
            view = LayoutInflater.from(context).inflate(R.layout.item_message_left, parent, false);
        }
        return new MessageViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull MessageViewHolder holder, int position) {
        Message message = messages.get(position);
        holder.messageText.setText(new String(message.getContent()));

        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm", Locale.getDefault());
        String time = sdf.format(new Date(message.getTimestamp()));

        holder.messageTime.setText(time);

        long currentTs = message.getTimestamp();
        long previousTs = 0;

        if (position > 0) {
            previousTs = messages.get(position - 1).getTimestamp();
        }

        if (position == 0 || !isSameDay(currentTs, previousTs)) {
            holder.dateHeader.setVisibility(View.VISIBLE);
            holder.dateHeader.setText(getFormattedDate(currentTs));
        } else {
            holder.dateHeader.setVisibility(View.GONE);
        }

        if(message.getSenderId() == currentUserId){
            holder.itemView.setOnLongClickListener(v->{
                longClickListener.onMessageLongClick(message);
                return true;
            });
        }
        else{
            holder.itemView.setOnLongClickListener(null);
        }
    }

    private boolean isSameDay(long ts1, long ts2) {
        Calendar cal1 = Calendar.getInstance();
        Calendar cal2 = Calendar.getInstance();
        cal1.setTimeInMillis(ts1);
        cal2.setTimeInMillis(ts2);
        return cal1.get(Calendar.YEAR) == cal2.get(Calendar.YEAR) &&
                cal1.get(Calendar.DAY_OF_YEAR) == cal2.get(Calendar.DAY_OF_YEAR);
    }

    private String getFormattedDate(long timestamp) {
        if (DateUtils.isToday(timestamp)) {
            return "Azi";
        } else if (DateUtils.isToday(timestamp + DateUtils.DAY_IN_MILLIS)) {
            return "Ieri";
        } else {
            SimpleDateFormat sdf = new SimpleDateFormat("dd MMM yyyy", Locale.getDefault());
            return sdf.format(new Date(timestamp));
        }
    }

    @Override
    public int getItemCount() {
        return messages.size();
    }

    static class MessageViewHolder extends RecyclerView.ViewHolder {
        TextView messageText;
        TextView messageTime;
        TextView dateHeader;
        MessageViewHolder(View itemView) {
            super(itemView);
            messageText = itemView.findViewById(R.id.message_text);
            messageTime = itemView.findViewById(R.id.message_time);

            dateHeader = itemView.findViewById(R.id.text_date_header);
        }
    }
}
