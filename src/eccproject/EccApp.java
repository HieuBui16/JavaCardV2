package eccproject;

import javacard.framework.*;
import javacard.security.*;

public class EccApp extends Applet {
	
	private SECP256k1 secp256k1;
	private Signature signature;
	private ECPublicKey publicKey;
	private ECPrivateKey privateKey;
	
	byte[] tempBuffer = JCSystem.makeTransientByteArray((short) 256 , JCSystem.CLEAR_ON_DESELECT);

	protected EccApp() {
		
		signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
		
		secp256k1 = new SECP256k1();
		
		publicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, SECP256k1.SECP256K1_KEY_SIZE, false);
		privateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256k1.SECP256K1_KEY_SIZE, false);
		
		secp256k1.setCurveParameters(publicKey);
		secp256k1.setCurveParameters(privateKey);
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new EccApp().register(bArray, (short) (bOffset+1) , bArray[bOffset]);
	}

	public void process(APDU apdu) {
		
		byte[] buffer = apdu.getBuffer();
		
		short size, size1;

		if (selectingApplet()) {
			short off = 0;
			apdu.setOutgoingAndSend((short) 0 , off);
			return;
		}
	
		try {
			switch (buffer[ISO7816.OFFSET_INS]) {
			case 01:
				RandomData randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
				randomData.generateData(buffer, (short) 0, (short) 32);
				privateKey.setS(buffer, (short) 0, (short) 32);
				apdu.setOutgoingAndSend((short) 0, (short) 32);
				return;
			case 02:
				size = secp256k1.derivePublicKey(privateKey, buffer, (short) 0);
				publicKey.setW(buffer, (short) 0, (short) size);
				apdu.setOutgoingAndSend((short) 0, (short) size);
				return;
			case 03:
				size1 = apdu.setIncomingAndReceive();
				Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, tempBuffer, (short) 0, size1);
				signature.init(privateKey, Signature.MODE_SIGN);
				short signLen = signature.sign(buffer, ISO7816.OFFSET_CDATA, size1, buffer, (short) 1);
				buffer[0] = (byte) signLen;
				apdu.setOutgoingAndSend((short) 0, (short) (1+signLen));
				return;
			case 04: 
				size = apdu.setIncomingAndReceive();
				signature.init(publicKey, Signature.MODE_VERIFY);
				boolean verified = signature.verify(tempBuffer, (short) 0, (short) 3, buffer, ISO7816.OFFSET_CDATA, size);
				if (verified) {
					apdu.setOutgoing();
					apdu.setOutgoingLength((short) 3);
					apdu.sendBytesLong(tempBuffer, (short) 0, (short) 3);
				}
				return;
			}
		} catch (CryptoException e) {
			ISOException.throwIt(e.getReason());
		}
	}
}

