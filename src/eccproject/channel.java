package eccproject;

public interface channel {
	
//	short encode(AESKey secretKey, byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff);
//	
//	short decode(AESKey secretKey, byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff);
//	
//	short processingData(ECPrivateKey privKey, byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff);
	
	/* receive cipher data from APDU
	 * @param inBuf cipher data buffer
	 * @param inOff cipher data offset 
	 * @param inLen length of cipher data
	 */
	short send(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff);
	
	/* send cipher data to APDU
	 * @param inBuf cipher data buffer
	 * @param inOff cipher data offset 
	 * @param inLen length of cipher data
	 */
	short receive(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff);
}
