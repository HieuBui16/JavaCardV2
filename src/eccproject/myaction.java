package eccproject;

import javacard.security.ECPrivateKey;

public interface myaction {
	/* Ham tra ve private key 
	 * @ param privBuf: buffer chua output cua private key
	 * @ param privOff: offset bat dau cua private key
	 * @ return: size cua private key
	 */
	short genpriv(byte[] privBuf, short privOff, short privLen);

	/* Ham tra ve public theo private key co san 
	 * input: buffer private key
	 * output: buffer chua public key
	 */
	short getpub(byte[] pubBuf, short pubOff, byte[] privBuf, short privOff, short privLen);
	
	/* Ham tra ve public theo private key co san 
	 * input: buffer private key
	 * output: buffer chua public key
	 */
	short getpub(byte[] pubBuf, short pubOff, ECPrivateKey priv);

	//void sign();

}

