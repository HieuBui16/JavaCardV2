package eccproject;

import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;

public class SECP256k1 implements myaction {
	static final byte SECP256K1_FP[] = {
		      (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
		      (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
		      (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
		      (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,(byte)0xFF,(byte)0xFF,(byte)0xFC,(byte)0x2F
		  };
	static final byte SECP256K1_A[] = {
		      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
		      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
		      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
		      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00
		  };
	static final byte SECP256K1_B[] = {
		      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
		      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
		      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
		      (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x07
		  };
	static final byte SECP256K1_G[] = {
		      (byte)0x04,
		      (byte)0x79,(byte)0xBE,(byte)0x66,(byte)0x7E,(byte)0xF9,(byte)0xDC,(byte)0xBB,(byte)0xAC,
		      (byte)0x55,(byte)0xA0,(byte)0x62,(byte)0x95,(byte)0xCE,(byte)0x87,(byte)0x0B,(byte)0x07,
		      (byte)0x02,(byte)0x9B,(byte)0xFC,(byte)0xDB,(byte)0x2D,(byte)0xCE,(byte)0x28,(byte)0xD9,
		      (byte)0x59,(byte)0xF2,(byte)0x81,(byte)0x5B,(byte)0x16,(byte)0xF8,(byte)0x17,(byte)0x98,
		      (byte)0x48,(byte)0x3A,(byte)0xDA,(byte)0x77,(byte)0x26,(byte)0xA3,(byte)0xC4,(byte)0x65,
		      (byte)0x5D,(byte)0xA4,(byte)0xFB,(byte)0xFC,(byte)0x0E,(byte)0x11,(byte)0x08,(byte)0xA8,
		      (byte)0xFD,(byte)0x17,(byte)0xB4,(byte)0x48,(byte)0xA6,(byte)0x85,(byte)0x54,(byte)0x19,
		      (byte)0x9C,(byte)0x47,(byte)0xD0,(byte)0x8F,(byte)0xFB,(byte)0x10,(byte)0xD4,(byte)0xB8
		  };
	static final byte SECP256K1_R[] = {
		      (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
		      (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFE,
		      (byte)0xBA,(byte)0xAE,(byte)0xDC,(byte)0xE6,(byte)0xAF,(byte)0x48,(byte)0xA0,(byte)0x3B,
		      (byte)0xBF,(byte)0xD2,(byte)0x5E,(byte)0x8C,(byte)0xD0,(byte)0x36,(byte)0x41,(byte)0x41
		  };
	
	 static final byte SECP256K1_K = (byte)0x01;
	 
	 static final short SECP256K1_KEY_SIZE = 256;
	 
	 private static final byte ALG_EC_SVDP_DH_PLAIN_XY = 6; // constant from JavaCard 3.0.5
	 
	 private KeyAgreement ecPointMultiplier;
	 
	 //private Crypto crypto;
	 
	 ECPrivateKey tmpECPrivateKey;
	 ECPrivateKey privateKey;
	 ECPublicKey publicKey;
	 
	 SECP256k1() {
		    //this.crypto = crypto;
		    this.ecPointMultiplier = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN_XY, false);
		    this.tmpECPrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256K1_KEY_SIZE, false);
		    setCurveParameters(tmpECPrivateKey);
		  }
	 
	 void setCurveParameters(ECKey key) {
		    key.setA(SECP256K1_A, (short) 0x00, (short) SECP256K1_A.length);
		    key.setB(SECP256K1_B, (short) 0x00, (short) SECP256K1_B.length);
		    key.setFieldFP(SECP256K1_FP, (short) 0x00, (short) SECP256K1_FP.length);
		    key.setG(SECP256K1_G, (short) 0x00, (short) SECP256K1_G.length);
		    key.setR(SECP256K1_R, (short) 0x00, (short) SECP256K1_R.length);
		    key.setK(SECP256K1_K);
		  }
	 
	 short derivePublicKey(ECPrivateKey privateKey, byte[] pubOut, short pubOff) {
		    return multiplyPoint(privateKey, SECP256K1_G, (short) 0, (short) SECP256K1_G.length, pubOut, pubOff);
		  }
	 
	 short derivePublicKey(byte[] privateKey, short privOff, byte[] pubOut, short pubOff) {
		    tmpECPrivateKey.setS(privateKey, privOff, (short)(SECP256K1_KEY_SIZE/8));
		    return derivePublicKey(tmpECPrivateKey, pubOut, pubOff);
		  }
	 
	 short multiplyPoint(ECPrivateKey privateKey, byte[] point, short pointOff, short pointLen, byte[] out, short outOff) {
		    ecPointMultiplier.init(privateKey);
		    return ecPointMultiplier.generateSecret(point, pointOff, pointLen, out, outOff);
		  }
	 
	 //generate shareKey by point*privKey
	 short deriveShareKey(ECPrivateKey privateKey, byte[] point, byte[] pubOut, short pubOff) {
		    return multiplyPoint(privateKey, point, (short) 0, (short) (point.length), pubOut, pubOff);
		  }

//	public short genpriv(byte[] privBuf, short privOff, short privLen) {
//		RandomData randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
//		randomData.generateData(privBuf, (short) 0, (short) privLen);
////		ECPrivateKey privateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256K1_KEY_SIZE, false);
////		privateKey.setS(privBuf, (short) 0, (short) (32));
//		//privateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256k1.SECP256K1_KEY_SIZE, false);
//		return privLen;
//	}
	
	public short genpriv(byte[] privBuf, short privOff, short privLen) {
		return privLen;
	}
	
	public short getpub(byte[] pubBuf, short pubOff, byte[] privBuf, short privOff, short privLen) {
//		genpriv(privBuf, privOff, privLen);
//		RandomData randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
//		randomData.generateData(privBuf, (short) 0, (short) privLen);
//		ECPrivateKey privateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256K1_KEY_SIZE, false);
//		privateKey.setS(privBuf, (short) 0, (short) (32));
		
		ECPublicKey publicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, SECP256K1_KEY_SIZE, true);
		publicKey.setW(pubBuf, (short) 0, (short) (32));
	    return derivePublicKey(privBuf, privOff, pubBuf, pubOff); 
	}

	public short getpub(byte[] pubBuf, short pubOff, ECPrivateKey priv) {
		return derivePublicKey(priv, pubBuf, pubOff);
	}
}

