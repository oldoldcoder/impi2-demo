package com.xd.hufei.transmission;

import lombok.Data;

import java.net.InetAddress;

/**
 * @author heqi
 * @date 2024/04/23
 * @desc 发布-订阅者模式，每当UDP收到了信息，就通知监听者
 * */
@Data
public class UdpMessage {

    private int port;

    // 消息传送过的地址
    private InetAddress address;

    private byte[] message;

}
