package com.xd.hufei.transmission;


import lombok.Getter;
import lombok.Setter;
import org.apache.log4j.Logger;

import java.io.IOException;
import java.net.*;
import java.util.ArrayList;
import java.util.List;

public class UdpMessenger implements Messenger{

    @Getter
    @Setter
    private int port;

    private DatagramSocket socket;


    private boolean closing = false;

    private static final String DEFAULT_ADDRESS = "0.0.0.0";

    private static Logger logger = Logger.getLogger(UdpMessenger.class);

    public UdpMessenger(int port) throws SocketException, UnknownHostException {
        this(port, InetAddress.getByName(DEFAULT_ADDRESS));
    }
    public UdpMessenger(int port, InetAddress address) throws SocketException {
        this.port = port;
        socket = new DatagramSocket(this.port, address);
        socket.setSoTimeout(0);
    }

    public void closeConnection() {
        closing = true;
        socket.close();
    }

    @Override
    public UdpMessage receive() {

        if(closing){
            logger.error("");
            return null;
        }

        DatagramPacket response = new DatagramPacket(new byte[512], 512);
        // 阻塞，一旦出现值，则向监听者进行通知
        try{
            socket.receive(response);
            UdpMessage message = new UdpMessage();
            message.setAddress(response.getAddress());
            message.setPort(response.getPort());
            byte[] buffer = new byte[response.getLength()];
            System.arraycopy(response.getData(), 0, buffer, 0,
                    buffer.length);
            message.setMessage(buffer);

            return message;
        } catch (Exception se) {
            logger.error(se.getMessage(), se);
        }
        return null;
    }


    @Override
    public void send(UdpMessage message) throws IOException {
        DatagramPacket packet = new DatagramPacket(message.getMessage(),
                message.getMessage().length, message.getAddress(),
                message.getPort());
        socket.send(packet);
        try {
            Thread.sleep(1);
        } catch (InterruptedException e) {
            logger.error(e.getMessage(), e);
        }
    }

}
