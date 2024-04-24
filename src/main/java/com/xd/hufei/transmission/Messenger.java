package com.xd.hufei.transmission;

import java.io.IOException;

/**
 * @author heqi
 * @date 2024/04/23
 * @desc 信使类，传递发送的信息
 * */
public interface Messenger {
    /**
     * @param message - 发送{@link UdpMessage}
     * */
    void send(UdpMessage message) throws IOException;

    /**
     * @return 封装好的信息返回
     * */
    UdpMessage receive();


}
