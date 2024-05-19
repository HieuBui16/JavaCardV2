package eccproject;

import javacard.framework.*;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

public class EccAes extends Applet {
	private Cipher cipher;
	
	private ECPrivateKey privateKey;
	private ECPrivateKey ciphertextPrivKey;
	private ECPublicKey publicKey;
	private ECPublicKey ciphertextPubKey;
	private AESKey sharedECCKey;
	
	private SECP256k1 secp256k1;
	
	byte[] tempBufferPub;
	byte[] tempBufferShareEcc;
	byte[] tempBufferCipherPub;
	byte[] tempBufferPriv;
	byte[] tempBufferSecr;
	
	byte[] tempBufferMg;
	
	byte[] mg;
	
	protected EccAes() {
		tempBufferPub = JCSystem.makeTransientByteArray((short) 65 , JCSystem.CLEAR_ON_DESELECT);
		tempBufferShareEcc = JCSystem.makeTransientByteArray((short) 65 , JCSystem.CLEAR_ON_DESELECT);
		tempBufferCipherPub = JCSystem.makeTransientByteArray((short) 65 , JCSystem.CLEAR_ON_DESELECT);
		tempBufferPriv = JCSystem.makeTransientByteArray((short) 32 , JCSystem.CLEAR_ON_DESELECT);
		tempBufferSecr = JCSystem.makeTransientByteArray((short) 32 , JCSystem.CLEAR_ON_DESELECT);
		
		tempBufferMg = JCSystem.makeTransientByteArray((short) 3 , JCSystem.CLEAR_ON_DESELECT);
		
		mg = new byte[] {(byte) 0x61, (byte) 0x62, (byte) 0x63};
		
		cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
		
		secp256k1 = new SECP256k1();
		
		privateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256k1.SECP256K1_KEY_SIZE, false);
		publicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, SECP256k1.SECP256K1_KEY_SIZE, false);
		ciphertextPrivKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256k1.SECP256K1_KEY_SIZE, false);
		ciphertextPubKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, SECP256k1.SECP256K1_KEY_SIZE, false);
		sharedECCKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
		
		secp256k1.setCurveParameters(privateKey);
		secp256k1.setCurveParameters(publicKey);
		secp256k1.setCurveParameters(ciphertextPrivKey);
		secp256k1.setCurveParameters(ciphertextPubKey);
	}
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new EccAes().register(bArray, (short) (bOffset+1), bArray[bOffset]);
	}
	 
	public void process(APDU apdu) {
		byte buffer[] = apdu.getBuffer();
		
		if (selectingApplet()) {
			short off = 0;
			apdu.setOutgoingAndSend((short) 0, off);
			return;
		}
		try {
			switch(buffer[ISO7816.OFFSET_INS]) {
			case 01:
				genKey(apdu);
				return;
			case 02:
				encryptEcc(apdu);
				return;
			case 03: 
				decryptEcc(apdu);
				return;
			}
		} catch (CryptoException e) {
			ISOException.throwIt(e.getReason());
		}
	}
	
	private void genKey(APDU apdu) {
		byte buffer[] = apdu.getBuffer();
		short size = apdu.setIncomingAndReceive();
		privateKey.setS(buffer, (short) 0, size);
		Util.arrayCopyNonAtomic(buffer, (short) 0, tempBufferPriv, (short) 0, size);
		
		short size2 = secp256k1.derivePublicKey(privateKey, buffer, (short) size);
		publicKey.setW(buffer, size, size2);
		Util.arrayCopyNonAtomic(buffer, (short) size, tempBufferPub, (short) 0, size2);
		apdu.setOutgoingAndSend((short) 0, (short) (size + size2));
	}
	
	private void encryptEcc(APDU apdu) {
		byte buffer[] = apdu.getBuffer();
		
		//generate shareKey from ciphertextPrivKey and publicKey
		RandomData randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		randomData.generateData(buffer, (short) 0, (short) 32);
		ciphertextPrivKey.setS(buffer, (short) 0, (short) 32);
		
		//generate ciphertextPubKey
		short ciphertextPubKeyLen = secp256k1.derivePublicKey(ciphertextPrivKey, tempBufferCipherPub, (short) 0);
		ciphertextPubKey.setW(tempBufferCipherPub, (short) 0, ciphertextPubKeyLen);
		
		//generate shareKey
		short shareKeyLen = secp256k1.deriveShareKey(ciphertextPrivKey, tempBufferPub, buffer, (short) 0);
		
		//hashing the shareKey to 256 bit for AES algorithm using SHA256		
		MessageDigest digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
		digest.doFinal(tempBufferShareEcc, (short) 0, shareKeyLen, tempBufferSecr, (short) 0);
		
		//generate secret key
		sharedECCKey.setKey(tempBufferSecr, (short) 0);
		
		//encryption
		cipher.init(sharedECCKey, Cipher.MODE_ENCRYPT);
		short cipherTextLen = cipher.doFinal(mg, (short) 0, (short) (mg.length), buffer, (short) 0);
		Util.arrayCopyNonAtomic(buffer, (short) 0, tempBufferMg, (short) 0, cipherTextLen);
		apdu.setOutgoingAndSend((short) 0, cipherTextLen);
	}
	
	private void decryptEcc(APDU apdu) {
		byte buffer[] = apdu.getBuffer();
		
		//generate shareKey from privKey and cipherPublicKey
		short shareKeyLen = secp256k1.deriveShareKey(privateKey, tempBufferCipherPub, buffer, (short) 0);
		
		//hashing the shareKey to 256 bit for AES algorithm using SHA256		
		MessageDigest digest = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
		digest.doFinal(tempBufferShareEcc, (short) 0, shareKeyLen, tempBufferSecr, (short) 0);
		
		//generate secret key
		sharedECCKey.setKey(tempBufferSecr, (short) 0);
		
		//decryption
		cipher.init(sharedECCKey, Cipher.MODE_DECRYPT);
		short plainTextLen = cipher.doFinal(tempBufferMg, (short) 0, (short) (tempBufferMg.length), buffer, (short) 0);
		apdu.setOutgoingAndSend((short) 0, plainTextLen);
	}
}
