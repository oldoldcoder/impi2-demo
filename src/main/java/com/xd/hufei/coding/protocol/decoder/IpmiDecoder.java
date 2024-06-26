/*
 * IpmiDecoder.java 
 * Created on 2011-08-01
 *
 * Copyright (c) Verax Systems 2011.
 * All rights reserved.
 *
 * This software is furnished under a license. Use, duplication,
 * disclosure and all other uses are restricted to the rights
 * specified in the written license agreement.
 */
package com.xd.hufei.coding.protocol.decoder;

import com.xd.hufei.coding.protocol.IpmiMessage;
import com.xd.hufei.coding.rmcp.RmcpMessage;

import java.security.InvalidKeyException;

/**
 * Decodes IPMI session header and retrieves encrypted payload.
 */
public interface IpmiDecoder {
    
    /**
     * Decodes IPMI message.
     * @param rmcpMessage
     * - RMCP message to decode.
     * @see IpmiMessage
     * @return Decoded IPMI message
     * @throws IllegalArgumentException
     * when delivered RMCP message does not contain encapsulated IPMI message.
     * @throws InvalidKeyException 
	 *             - when initiation of the integrity algorithm fails
     */
    IpmiMessage decode(RmcpMessage rmcpMessage) throws IllegalArgumentException, InvalidKeyException;
}
