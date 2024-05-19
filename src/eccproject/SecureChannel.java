package eccproject;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacardx.crypto.Cipher;

public class SecureChannel implements channel{
	
	byte[] tempPub;
	byte[] tempShare;
	byte[] share;

	MessageDigest sha256;
	
	private Cipher cipher;
	private AESKey secretKey;
	private SECP256k1 secp256k1;
	private ECPrivateKey p1PrivateKey;
	private ECPublicKey p1PublicKey;
	
	SecureChannel(){
		this.sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
		this.secp256k1 = new SECP256k1();
		this.tempPub = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_DESELECT);
		this.share = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
		this.tempShare = JCSystem.makeTransientByteArray((short) 66, JCSystem.CLEAR_ON_DESELECT);
		this.secretKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
		this.p1PrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256k1.SECP256K1_KEY_SIZE, false);
		this.p1PublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, SECP256k1.SECP256K1_KEY_SIZE, false);
		this.cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
		this.p1PrivateKey.setS(new byte[] {(byte) 0xe9, (byte) 0x6c, (byte) 0x2b, (byte) 0x06, (byte) 0xfc, (byte) 0x82, (byte) 0xd8, (byte) 0x62, (byte) 0x43, (byte) 0x2f,
		  	 	  (byte) 0x85, (byte) 0x57, (byte) 0xaa, (byte) 0xbd, (byte) 0xc1, (byte) 0x8e, (byte) 0xf4, (byte) 0x85, (byte) 0xd1, (byte) 0x13, (byte) 0xcd, (byte) 0x54,
		  	 	  (byte) 0x52, (byte) 0xa8, (byte) 0xe6, (byte) 0x1a, (byte) 0x01, (byte) 0xa3, (byte) 0x7d, (byte) 0x28, (byte) 0x11, (byte) 0xd9}, (short) 0, (short) 32);
		this.p1PublicKey.setW(new byte[] {(byte) 0x04, (byte) 0x31, (byte) 0x27, (byte) 0x2b, (byte) 0x6d, (byte) 0x37, (byte) 0xab, (byte) 0x55, (byte) 0x8c, (byte) 0xd0, (byte) 0x82, (byte) 0xdc, 
				 (byte) 0x20, (byte) 0x1b, (byte) 0x74, (byte) 0x75, (byte) 0xeb, (byte) 0x68, (byte) 0xfb, (byte) 0x15, (byte) 0x2b, (byte) 0x02, (byte) 0x6a, (byte) 0x8f,
				 (byte) 0xb8, (byte) 0x3e, (byte) 0x84, (byte) 0x10, (byte) 0xfd, (byte) 0x1a, (byte) 0x97, (byte) 0xbb, (byte) 0x6f, (byte) 0x0d, (byte) 0x47, (byte) 0x18,
				 (byte) 0xf5, (byte) 0x16, (byte) 0x38, (byte) 0xa0, (byte) 0xea, (byte) 0x30, (byte) 0xf6, (byte) 0x2a, (byte) 0x95, (byte) 0x47, (byte) 0x12, (byte) 0x96,
				 (byte) 0xe8, (byte) 0x65, (byte) 0x5c, (byte) 0x64, (byte) 0x79, (byte) 0x03, (byte) 0xba, (byte) 0x3d, (byte) 0x50, (byte) 0x4c, (byte) 0x8e, (byte) 0xe3,
				 (byte) 0xad, (byte) 0x71, (byte) 0xac, (byte) 0x6b, (byte) 0xa9}, (short) 0, (short) 65);
		//this.secretKey.setKey(new byte[] { (byte) 0x62, (byte) 0x75, (byte) 0x69, (byte) 0x74, (byte) 0x72, (byte) 0x75, (byte) 0x6e, (byte) 0x67, (byte) 0x68,
		//								   (byte) 0x69, (byte) 0x65, (byte) 0x75, (byte) 0x31, (byte) 0x36, (byte) 0x36, (byte) 0x31}, (short) 0);
		secp256k1.setCurveParameters(p1PrivateKey);
		secp256k1.setCurveParameters(p1PublicKey);
	}
	
	public void commitSecretKey(byte[] inBuff, short inOff) {
		Util.arrayCopyNonAtomic(inBuff, (short) (inOff + 1), tempPub, (short) 0, (short) 65);
		secp256k1.deriveShareKey(p1PrivateKey, tempPub, tempShare, (short) 0);
		
		Util.arrayFillNonAtomic(tempShare, (short) 65, (short) 1, inBuff[0]);
		
		sha256.doFinal(tempShare, (short) 0, (short) 66, tempShare, (short) 0);
		
		Util.arrayCopyNonAtomic(tempShare, (short) 0, share, (short) 0, (short) 16);
		
		secretKey.setKey(tempShare, (short) 0);	
	}
	
	public short receive(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff) {
		if (!secretKey.isInitialized()) {
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
		}
		return decode(inBuf, (short) inOff, (short) inLen, outBuf,  outOff);
	}
	
	public short send(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff) {
		return encode(inBuf, inOff, inLen, outBuf,  outOff);
	}
	
	private short encode(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff) {
		cipher.init(secretKey, Cipher.MODE_ENCRYPT);
		if (inLen == (short) 70) {
			Util.arrayFillNonAtomic(inBuf, inLen, (short) 10, (byte) 0x00);
		} else if(inLen == (short) 71) {
			Util.arrayFillNonAtomic(inBuf, inLen, (short) 9, (byte) 0x00);
		} else Util.arrayFillNonAtomic(inBuf, inLen, (short) 8, (byte) 0x00);
		return cipher.doFinal(inBuf, inOff, (short) 80, outBuf, outOff);
	}
	
	private short decode(byte[] inBuf, short inOff, short inLen, byte[] outBuf, short outOff) {
	
		cipher.init(secretKey, Cipher.MODE_DECRYPT);
		short m1 = cipher.update(inBuf, inOff, inLen, outBuf, outOff);
		short m2 = cipher.doFinal(inBuf, (short) (inOff + 16) , (short) (inLen - 16), outBuf, (short) (outOff + 16));
		return (short) (m1 + m2);
	}
}
