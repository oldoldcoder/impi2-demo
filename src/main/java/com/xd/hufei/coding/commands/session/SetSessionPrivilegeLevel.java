package com.xd.hufei.coding.commands.session;

import com.xd.hufei.coding.commands.*;
import com.xd.hufei.coding.payload.CompletionCode;
import com.xd.hufei.coding.payload.IpmiPayload;
import com.xd.hufei.coding.payload.lan.IPMIException;
import com.xd.hufei.coding.payload.lan.IpmiLanRequest;
import com.xd.hufei.coding.payload.lan.IpmiLanResponse;
import com.xd.hufei.coding.payload.lan.NetworkFunction;
import com.xd.hufei.coding.protocol.AuthenticationType;
import com.xd.hufei.coding.protocol.IpmiMessage;
import com.xd.hufei.coding.security.CipherSuite;
import com.xd.hufei.common.TypeConverter;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Wrapper class for Set Session Privilege Level command
 */
public class SetSessionPrivilegeLevel extends IpmiCommandCoder {

    private PrivilegeLevel privilegeLevel;

    /**
     * Initiates {@link SetSessionPrivilegeLevel} for encoding and decoding
     * @param version
     * - IPMI version of the command.
     * @param cipherSuite
     * - {@link CipherSuite} containing authentication, confidentiality and integrity algorithms for this session.
     * @param authenticationType
     * - Type of authentication used. Must be RMCPPlus for IPMI v2.0.
     * @param privilegeLevel
     * - Requested {@link PrivilegeLevel} to acquire. Can not be higher than level declared during starting session.
     */
    public SetSessionPrivilegeLevel(IpmiVersion version, CipherSuite cipherSuite,
            AuthenticationType authenticationType, PrivilegeLevel privilegeLevel) {
        super(version, cipherSuite, authenticationType);
        this.privilegeLevel = privilegeLevel;
    }

    @Override
    public byte getCommandCode() {
        return CommandCodes.SET_SESSION_PRIVILEGE_LEVEL;
    }

    @Override
    public NetworkFunction getNetworkFunction() {
        return NetworkFunction.ApplicationRequest;
    }

    @Override
    protected IpmiPayload preparePayload(int sequenceNumber) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] requestData = new byte[1];

        requestData[0] = TypeConverter.intToByte(getRequestedPrivilegeLevelEncoded());

        return new IpmiLanRequest(getNetworkFunction(), getCommandCode(), requestData,
                TypeConverter.intToByte(sequenceNumber % 64));
    }

    @Override
    public ResponseData getResponseData(IpmiMessage message) throws IllegalArgumentException, IPMIException,
            NoSuchAlgorithmException, InvalidKeyException {
        if (!isCommandResponse(message)) {
            throw new IllegalArgumentException("This is not a response for Get SEL Entry command");
        }
        if (!(message.getPayload() instanceof IpmiLanResponse)) {
            throw new IllegalArgumentException("Invalid response payload");
        }
        if (((IpmiLanResponse) message.getPayload()).getCompletionCode() != CompletionCode.Ok) {
            throw new IPMIException(((IpmiLanResponse) message.getPayload()).getCompletionCode());
        }

        return new SetSessionPrivilegeLevelResponseData();
    }

    private byte getRequestedPrivilegeLevelEncoded() {
        switch (privilegeLevel) {
        case MaximumAvailable:
            return 0;
        case Callback:
            return TypeConverter.intToByte(0x1);
        case User:
            return TypeConverter.intToByte(0x2);
        case Operator:
            return TypeConverter.intToByte(0x3);
        case Administrator:
            return TypeConverter.intToByte(0x4);
        default:
            throw new IllegalArgumentException("Invalid privilege level");
        }
    }
}
