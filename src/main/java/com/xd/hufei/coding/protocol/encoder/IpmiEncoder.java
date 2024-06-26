/*
 * IpmiEncoder.java 
 * Created on 2011-07-21
 *
 * Copyright (c) Verax Systems 2011.
 * All rights reserved.
 *
 * This software is furnished under a license. Use, duplication,
 * disclosure and all other uses are restricted to the rights
 * specified in the written license agreement.
 */
package com.xd.hufei.coding.protocol.encoder;

import com.xd.hufei.coding.protocol.IpmiMessage;

import java.security.InvalidKeyException;

/**
 * Encodes IPMI message.
 */
public interface IpmiEncoder {
    /**
     * Encodes IPMI message.
     * @param ipmiMessage
     * - IPMI message to encode.
     * @return IPMI message encoded into byte array.
     * @throws InvalidKeyException 
	 *             - when initiation of the confidentiality algorithm fails
     * @see IpmiMessage
     */
    byte[] encode(IpmiMessage ipmiMessage) throws InvalidKeyException;
}
