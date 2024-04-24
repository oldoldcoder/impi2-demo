package com.xd.hufei.connection.state;

/**
 * @author heqi
 * @date 2024/04/25
 * @desc 抽象出连接时候的状态,遵循ipmi2.0定义的状态转换
 * */
public enum State {
    Uninitialized,
    AuthCap,
    AuthCapWaiting,
    Ciphers,
    CiphersWaiting,
    OpenSessionWaiting,
    OpenSessionComplete,
    Rakp1Complete,
    Rakp1Waiting,
    Rakp3Complete,
    Rakp3Waiting,
    SessionValid,
}
