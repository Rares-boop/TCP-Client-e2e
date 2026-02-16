package com.example.tcpclient;

import android.content.Context;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class ConfigReader {
    private Properties properties;

    public ConfigReader(Context context) {
        properties = new Properties();
        try {
            InputStream inputStream = context.getAssets().open("server_config.properties");
            properties.load(inputStream);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String getServerIp() {
        return properties.getProperty("server_ip", "127.0.0.1");
    }

    public int getServerPort() {
        String port = properties.getProperty("server_port", "12345");
        return Integer.parseInt(port);
    }
}
