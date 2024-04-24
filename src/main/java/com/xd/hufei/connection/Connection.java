package com.xd.hufei.connection;

import com.xd.hufei.coding.Decoder;
import com.xd.hufei.coding.Encoder;
import com.xd.hufei.coding.commands.IpmiVersion;
import com.xd.hufei.coding.commands.PrivilegeLevel;
import com.xd.hufei.coding.commands.chassis.GetChassisStatus;
import com.xd.hufei.coding.commands.chassis.GetChassisStatusResponseData;
import com.xd.hufei.coding.commands.session.*;
import com.xd.hufei.coding.payload.lan.IPMIException;
import com.xd.hufei.coding.protocol.AuthenticationType;
import com.xd.hufei.coding.protocol.PayloadType;
import com.xd.hufei.coding.protocol.decoder.PlainCommandv20Decoder;
import com.xd.hufei.coding.protocol.decoder.ProtocolDecoder;
import com.xd.hufei.coding.protocol.decoder.Protocolv15Decoder;
import com.xd.hufei.coding.protocol.decoder.Protocolv20Decoder;
import com.xd.hufei.coding.protocol.encoder.Protocolv15Encoder;
import com.xd.hufei.coding.protocol.encoder.Protocolv20Encoder;
import com.xd.hufei.coding.rmcp.RmcpDecoder;
import com.xd.hufei.coding.rmcp.RmcpMessage;
import com.xd.hufei.coding.security.CipherSuite;
import com.xd.hufei.common.Constants;
import com.xd.hufei.common.TypeConverter;
import com.xd.hufei.connection.state.State;
import com.xd.hufei.transmission.Messenger;
import com.xd.hufei.transmission.UdpMessage;
import org.apache.log4j.Logger;

import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * @author hufei
 * @date 2024/04/24
 * @desc 一次连接，主要工作在connection进行
 * */

// TODO 所有的异常抛出信息暂时未定义，同时调用端也没有处理

public class Connection {

    // 信使，消息发送者
    private Messenger messenger;

    // 当前状态
    private State state;

    // 当前连接编号
    private int handle;

    private InetAddress address;

    private boolean initialized = false;

    // 单线程下增量计数的一个sessionTag
    private int sessionTag = 0;
    // sessionId
    private int sessionId = 1001;
    //
    private int managedSeqNum = 0;
    private Logger logger = Logger.getLogger(Connection.class);


    public Connection(Messenger messenger, int handle){
        this.messenger = messenger;
        this.handle = handle;
    }

    // 进行连接远端
    public void connect(InetAddress address){
        this.address = address;
        this.state = State.Uninitialized;
        this.initialized = true;
    }

    // 获取发送消息，申请获取加密套件
    public List<CipherSuite> getAvailableCipherSuites() throws Exception{
        // 目前的状态不是出于未初始化阶段
        if(this.state != State.Uninitialized){
            throw new Exception("");
        }
        ArrayList<byte[]> rawCipherSuites = new ArrayList<byte[]>();

        int seqN = getSequenceNumber();
        byte index = 0;
        while (true) {
            Thread.sleep(300);
            GetChannelCipherSuites cipherSuites = new GetChannelCipherSuites(
                    TypeConverter.intToByte(0xE), index);
            index ++;
            try {
                this.sendMessage(Encoder.encode(
                        new Protocolv20Encoder(), cipherSuites,
                        seqN, 0));
            } catch (Exception e) {
                // 报错
                throw new Exception("");
            }

            this.state = State.CiphersWaiting;
            // 收到返回的包
            UdpMessage receive = this.messenger.receive();
            // 检查返回的包内容
            GetChannelCipherSuitesResponseData data = null;
            try {
                data = (GetChannelCipherSuitesResponseData) Decoder.decode(
                        receive.getMessage(), new Protocolv20Decoder(CipherSuite.getEmpty()),
                        new GetChannelCipherSuites());
            } catch (IllegalArgumentException | IPMIException | NoSuchAlgorithmException | InvalidKeyException e1) {
                logger.error(e1.getMessage(), e1);
                throw new Exception("");
            }
            assert data != null;
            if (data.getCipherSuiteData() != null) {
                if(data.getCipherSuiteData().length < 16)
                    break;
                rawCipherSuites.add(data.getCipherSuiteData());
            }
        }
        this.state = State.Ciphers;

        int length = 0;

        for (byte[] partial : rawCipherSuites) {
            length += partial.length;
        }

        byte[] csRaw = new byte[length];

        index = 0;

        for (byte[] partial : rawCipherSuites) {
            System.arraycopy(partial, 0, csRaw, index, partial.length);
            index += partial.length;
        }

        return CipherSuite.getCipherSuites(csRaw);

    }
    // 进行身份验证
    public GetChannelAuthenticationCapabilitiesResponseData getChannelAuthenticationCapabilities(CipherSuite cs, PrivilegeLevel level) throws Exception{
        if (this.state != State.Ciphers) {
            throw new Exception("");
        }
        GetChannelAuthenticationCapabilities authCap = new GetChannelAuthenticationCapabilities(
                IpmiVersion.V15, IpmiVersion.V20, cs,
               level, TypeConverter.intToByte(0xe));
        try {
            this.sendMessage(Encoder.encode(
                    new Protocolv15Encoder(), authCap, this.getSequenceNumber(), 0));
        } catch (Exception e) {
            throw new Exception("");
        }

        this.state = State.AuthCapWaiting;
        UdpMessage receive = this.messenger.receive();
        GetChannelAuthenticationCapabilitiesResponseData data = null;

        try {
            // TODO 这里是v15版本的验证，可能会出错
            data = (GetChannelAuthenticationCapabilitiesResponseData) Decoder
                    .decode(receive.getMessage(), new Protocolv15Decoder(),
                            new GetChannelAuthenticationCapabilities(
                                    IpmiVersion.V15, IpmiVersion.V20, cs));
        }catch (IllegalArgumentException | IPMIException | NoSuchAlgorithmException | InvalidKeyException e1) {
            logger.error(e1.getMessage(), e1);
            throw new Exception("");
        }
        this.state = State.AuthCap;
        // TODO 是否应该UDP返回接受到Authentication的数据
        return data;
    }

    // 开启session
    public void startSession(int tag, CipherSuite cipherSuite,
                             PrivilegeLevel privilegeLevel, String username, String password,
                             byte[] bmcKey) throws Exception {
        if (this.state != State.AuthCap) {
            throw new Exception("");
        }
        // 获取Tag
        int sessionTag = this.getSequenceNumber();
        OpenSession openSession = new OpenSession(this.getSessionId(),
                privilegeLevel, cipherSuite);

        try {
            this.sendMessage(Encoder.encode(
                    new Protocolv20Encoder(), openSession,
                    sessionTag, 0));
        } catch (Exception e) {
           throw new Exception();
        }
        this.state = State.OpenSessionWaiting;
        UdpMessage receive = messenger.receive();
        OpenSessionResponseData data = null;

        try {
            data = (OpenSessionResponseData) Decoder.decode(receive.getMessage(),
                    new PlainCommandv20Decoder(CipherSuite.getEmpty()),
                    new OpenSession(CipherSuite.getEmpty()));
        }catch (IllegalArgumentException | IPMIException | NoSuchAlgorithmException | InvalidKeyException e1) {
            logger.error(e1.getMessage(), e1);
            throw new Exception("");
        }
        this.state = State.OpenSessionComplete;


        this.managedSeqNum = data.getManagedSystemSessionId();
        // RAKP 1阶段认证
        Rakp1 rakp1 = new Rakp1(managedSeqNum,
                privilegeLevel, username,
                password, bmcKey,
                cipherSuite);
        try {
            this.sendMessage(Encoder.encode(
                    new Protocolv20Encoder(), rakp1,
                    sessionTag, 0));
        } catch (Exception e) {
            throw new Exception("");
        }
        this.state = State.Rakp1Waiting;
        receive = messenger.receive();
        Rakp1ResponseData r1Resp = null;
        try {
            r1Resp = (Rakp1ResponseData) Decoder.decode(receive.getMessage(),
                    new PlainCommandv20Decoder(CipherSuite.getEmpty()), rakp1);
        }catch (IllegalArgumentException | IPMIException | NoSuchAlgorithmException | InvalidKeyException e1) {
            logger.error(e1.getMessage(), e1);
            throw new Exception("");
        }
        this.state = State.Rakp1Complete;
        // 初始化CS
        try {
            cipherSuite.initializeAlgorithms(rakp1.calculateSik(r1Resp));
        } catch (NoSuchPaddingException e) {
            logger.error(e.getMessage(), e);
        }
        // RAKP 3阶段认证

        Rakp3 rakp3 = new Rakp3((byte) 0,
                managedSeqNum, cipherSuite, rakp1, r1Resp);

        try {
            this.sendMessage(Encoder.encode(
                    new Protocolv20Encoder(), rakp3,
                    sessionTag, 0));
        } catch (Exception e) {
           throw new Exception("");
        }
        this.state = State.Rakp3Waiting;
        receive = messenger.receive();
        Rakp3ResponseData r3Resp = null;

        try {
            r3Resp = (Rakp3ResponseData) Decoder.decode(receive.getMessage(),
                    new PlainCommandv20Decoder(CipherSuite.getEmpty()),
                    new Rakp3(cipherSuite, rakp1, r1Resp));
        }catch (IllegalArgumentException | IPMIException | NoSuchAlgorithmException | InvalidKeyException e1) {
            logger.error(e1.getMessage(), e1);
            throw new Exception("");
        }
        // this.state = State.Rakp3Complete;
        // ...设置session开启
        this.state = State.SessionValid;
    }

    // 执行一次chassisStatus命令
    public void getChassisStatus(GetChassisStatus request,CipherSuite cs) throws Exception{
        if(this.state != State.SessionValid){
            throw new Exception("");
        }
        byte [] outmsg = Encoder.encode(new Protocolv20Encoder(), request, getSequenceNumber(),
                this.managedSeqNum);
        this.sendMessage(outmsg);

        UdpMessage receive = messenger.receive();

        GetChassisStatusResponseData data = null;

        try {
            data = (GetChassisStatusResponseData) Decoder.decode(receive.getMessage(),
                    new Protocolv20Decoder(cs), new GetChassisStatus(
                            IpmiVersion.V20, cs, AuthenticationType.RMCPPlus));
        } catch (IllegalArgumentException | IPMIException | NoSuchAlgorithmException | InvalidKeyException e1) {
            logger.error(e1.getMessage(), e1);
            throw new Exception("");
        }

        logger.info(data.getPowerRestorePolicy());
        logger.info(data.isPowerControlFault());
        logger.info(data.isPowerFault());
        logger.info(data.isInterlock());
        logger.info(data.isPowerOverload());
        logger.info(data.isPowerOn());

        logger.info("________");

        logger.info(data.wasIpmiPowerOn());
        logger.info(data.wasPowerFault());
        logger.info(data.wasInterlock());
        logger.info(data.wasPowerOverload());

        logger.info("________");

        logger.info(data.isChassisIdentifyCommandSupported());
        if (data.isChassisIdentifyCommandSupported()) {
            logger.info(data.getChassisIdentifyState());
        }
        logger.info(data.coolingFaultDetected());
        logger.info(data.driveFaultDetected());
        logger.info(data.isFrontPanelLockoutActive());
        logger.info(data.isChassisIntrusionActive());

        logger.info("________");

        logger.info(data.isFrontPanelButtonCapabilitiesSet());

        if (data.isFrontPanelButtonCapabilitiesSet()) {
            try {
                logger.info(data.isStandbyButtonDisableAllowed());
                logger.info(data
                        .isDiagnosticInterruptButtonDisableAllowed());
                logger.info(data.isResetButtonDisableAllowed());
                logger.info(data.isPowerOffButtonDisableAllowed());
                logger.info(data.isStandbyButtonDisabled());
                logger.info(data.isDiagnosticInterruptButtonDisabled());
                logger.info(data.isResetButtonDisabled());
                logger.info(data.isPowerOffButtonDisabled());
            } catch (IllegalAccessException e) {
                logger.error(e.getMessage(), e);
            }

        }

        logger.info("---------------------------------------------");


    }

    /**
     * 调用Messenger发送信息
     * */
    public void sendMessage(byte[] message) throws IOException {
        UdpMessage udpMessage = new UdpMessage();
        udpMessage.setAddress(address);
        udpMessage.setPort(Constants.IPMI_PORT);
        udpMessage.setMessage(message);
        messenger.send(udpMessage);
    }

    /**
     * 返回一个sessionTag
     * */
    private int getSequenceNumber(){
        return (++sessionTag) % 60;
    }
    /**
     * 返回一个sessionId
     * */
    private int getSessionId(){
        return (++sessionId ) % (Integer.MAX_VALUE >> 2);
    }
}
