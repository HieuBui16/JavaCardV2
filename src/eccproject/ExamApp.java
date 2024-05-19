package eccproject;

import javacard.framework.*;
import javacard.security.*;

public class ExamApp extends Applet {
	private SECP256k1 myAction;
	private Signature signature;
	private ECPublicKey publicKey;
	private ECPrivateKey privateKey;
	
	byte message;
	
	byte[] scratch256 = JCSystem.makeTransientByteArray((short)256, JCSystem.CLEAR_ON_DESELECT);

    /**
     * Only this class's install method should create the applet object.
     */
    protected ExamApp()
    {	
    	myAction = new SECP256k1();
    	
    	publicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, SECP256k1.SECP256K1_KEY_SIZE, false);
    	privateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256k1.SECP256K1_KEY_SIZE, false);
    	
    	signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    	
    	myAction.setCurveParameters(privateKey);
    	myAction.setCurveParameters(publicKey);

    	}

    /**
     * Installs this applet.
     * @param bArray the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ExamApp().register(bArray, (short) (bOffset+1) , bArray[bOffset]);
    }

    /**
     * Processes an incoming APDU.
     * @see APDU
     * @param apdu the incoming APDU
     * @exception ISOException with the response bytes per ISO 7816-4
     */

	public void process(APDU apdu)
    {
        byte buffer[] = apdu.getBuffer();
        short size1, size;

		if (selectingApplet()) {
			selectApplet(apdu);
			return;
		}

		try {
			switch (buffer[ISO7816.OFFSET_INS]) {
			case 01:
				size = apdu.setIncomingAndReceive();
				// size = myAction.genpriv(buffer, ISO7816.OFFSET_CDATA, (short) 32);
				privateKey.setS(buffer, ISO7816.OFFSET_CDATA, size);
				apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) (size));
				return;
			case 03:
//				size = apdu.setIncomingAndReceive();
//				if (size != 32)
//					ISOException.throwIt((short) 1);
				size1 = privateKey.getS(buffer, (short) 0);
				size = myAction.getpub(buffer, size1, privateKey);
				publicKey.setW(buffer, size1, size);
				apdu.setOutgoingAndSend((short) 0, (short) (size + size1));
				return;
			case 04:
				size1 = apdu.setIncomingAndReceive();
//				offset = apdu.getOffsetCdata();
				Util.arrayCopyNonAtomic(apdu.getBuffer(), ISO7816.OFFSET_CDATA, scratch256, (short) 0, (short) size1);
				signature.init(privateKey, Signature.MODE_SIGN);
				short signLength = signature.sign(buffer, ISO7816.OFFSET_CDATA, (short) size1, buffer, (short) 1);
				buffer[0] = (byte) signLength;
				apdu.setOutgoingAndSend((short) 0, (short) (signLength + 1));
				return;
			case 05:
//				size1 = publicKey.getW(buffer, (short) 0);
				size = apdu.setIncomingAndReceive();
				signature.init(publicKey, Signature.MODE_VERIFY);
				boolean verified = signature.verify(scratch256, (short) 0, (short) 3, buffer, ISO7816.OFFSET_CDATA, size);
				if (verified) {
					apdu.setOutgoing();
					apdu.setOutgoingLength((short) 3);
					apdu.sendBytesLong(scratch256, (short) 0, (short) 3);
				}
//				if (verified) apdu.setOutgoingAndSend((short) 0, (short) size);
				return;
			}
		} catch (CryptoException e) {
			ISOException.throwIt(e.getReason());
		}
   }
    
    private void selectApplet(APDU apdu) {
        short off = 0;
        apdu.setOutgoingAndSend((short) 0, off);
      }
}

