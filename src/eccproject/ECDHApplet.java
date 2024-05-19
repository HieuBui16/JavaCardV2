package eccproject;

import javacard.framework.*;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class ECDHApplet extends Applet {

	private ECPrivateKey p1PrivateKey;
	private ECPublicKey p1PublicKey;
	private ECPrivateKey p2PrivateKey;
	private ECPublicKey p2PublicKey;
	private AESKey p1ShareKey;
	private Signature signature;

	private SecureChannel secureChannel;
	Cipher cipher;
	MessageDigest sha512;
	MessageDigest sha256;
	RandomData random;

	byte[] tempP1Pub;
	byte[] tempP2Pub;

	byte[] temmg;
	byte[] temSecret;
	byte[] temSecret128;

	byte[] tempsign;

	byte[] randomBuf;

	short sigSize = 0;

	private SECP256k1 secp256k1;

	protected ECDHApplet() {

		signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
		random = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
		secp256k1 = new SECP256k1();
		secureChannel = new SecureChannel();

		sha512 = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
		sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
		cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);

		p1PrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256k1.SECP256K1_KEY_SIZE,
				false);
		p1PublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, SECP256k1.SECP256K1_KEY_SIZE,
				false);
		p2PrivateKey = (ECPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, SECP256k1.SECP256K1_KEY_SIZE,
				false);
		p2PublicKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, SECP256k1.SECP256K1_KEY_SIZE,
				false);
		p1ShareKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128,
				false);

		secp256k1.setCurveParameters(p1PrivateKey);
		secp256k1.setCurveParameters(p1PublicKey);
		secp256k1.setCurveParameters(p2PrivateKey);
		secp256k1.setCurveParameters(p2PublicKey);

		p1PrivateKey.setS(new byte[] { (byte) 0xe9, (byte) 0x6c, (byte) 0x2b, (byte) 0x06, (byte) 0xfc, (byte) 0x82,
				(byte) 0xd8, (byte) 0x62, (byte) 0x43, (byte) 0x2f, (byte) 0x85, (byte) 0x57, (byte) 0xaa, (byte) 0xbd,
				(byte) 0xc1, (byte) 0x8e, (byte) 0xf4, (byte) 0x85, (byte) 0xd1, (byte) 0x13, (byte) 0xcd, (byte) 0x54,
				(byte) 0x52, (byte) 0xa8, (byte) 0xe6, (byte) 0x1a, (byte) 0x01, (byte) 0xa3, (byte) 0x7d, (byte) 0x28,
				(byte) 0x11, (byte) 0xd9 }, (short) 0, (short) 32);

		p1PublicKey.setW(new byte[] { (byte) 0x04, (byte) 0x31, (byte) 0x27, (byte) 0x2b, (byte) 0x6d, (byte) 0x37,
				(byte) 0xab, (byte) 0x55, (byte) 0x8c, (byte) 0xd0, (byte) 0x82, (byte) 0xdc, (byte) 0x20, (byte) 0x1b,
				(byte) 0x74, (byte) 0x75, (byte) 0xeb, (byte) 0x68, (byte) 0xfb, (byte) 0x15, (byte) 0x2b, (byte) 0x02,
				(byte) 0x6a, (byte) 0x8f, (byte) 0xb8, (byte) 0x3e, (byte) 0x84, (byte) 0x10, (byte) 0xfd, (byte) 0x1a,
				(byte) 0x97, (byte) 0xbb, (byte) 0x6f, (byte) 0x0d, (byte) 0x47, (byte) 0x18, (byte) 0xf5, (byte) 0x16,
				(byte) 0x38, (byte) 0xa0, (byte) 0xea, (byte) 0x30, (byte) 0xf6, (byte) 0x2a, (byte) 0x95, (byte) 0x47,
				(byte) 0x12, (byte) 0x96, (byte) 0xe8, (byte) 0x65, (byte) 0x5c, (byte) 0x64, (byte) 0x79, (byte) 0x03,
				(byte) 0xba, (byte) 0x3d, (byte) 0x50, (byte) 0x4c, (byte) 0x8e, (byte) 0xe3, (byte) 0xad, (byte) 0x71,
				(byte) 0xac, (byte) 0x6b, (byte) 0xa9 }, (short) 0, (short) 65);

		tempP1Pub = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_DESELECT);
		tempP2Pub = JCSystem.makeTransientByteArray((short) 65, JCSystem.CLEAR_ON_DESELECT);
		temmg = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
		temSecret = JCSystem.makeTransientByteArray((short) 66, JCSystem.CLEAR_ON_DESELECT);
		temSecret128 = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
		tempsign = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
		randomBuf = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
	}

	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new ECDHApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
	}

	public void process(APDU apdu) {

		if (selectingApplet()) {
			short off = 0;
			apdu.setOutgoingAndSend((short) 0, off);
			return;
		}

		byte[] buffer = apdu.getBuffer();

		short size = apdu.setIncomingAndReceive();

		if (buffer[ISO7816.OFFSET_INS] == (byte) 0x07) {
			secureChannel.commitSecretKey(buffer, ISO7816.OFFSET_CDATA);
		} else {
			secureChannel.receive(buffer, (short) (ISO7816.OFFSET_CDATA), (short) size, buffer, ISO7816.OFFSET_CDATA);
			try {
				switch (buffer[ISO7816.OFFSET_INS]) {
				case 01:
					genParty1Key(apdu);
					break;
				case 02:
					genParty2Key(apdu);
					break;
				case 03:
					genP1SecretKey(apdu);
					break;
				case 04:
					p1EncAndSendP2(apdu);
					break;
				case 05:
					p2DecMgOfP1(apdu);
					break;
				case 06:
					processPin(apdu);
					break;
				}
			} catch (CryptoException e) {
				ISOException.throwIt(e.getReason());
			}
		}
	}

	// generate keyPair of Party 1 using ECDH Key agreement and secp256k1 curve
	private void genParty1Key(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short privLen = apdu.setIncomingAndReceive();
		p1PrivateKey.setS(buffer, ISO7816.OFFSET_CDATA, (short) privLen);
		short pubLen = secp256k1.derivePublicKey(p1PrivateKey, buffer, (short) (privLen + ISO7816.OFFSET_CDATA));
		p1PublicKey.setW(buffer, (short) (privLen + ISO7816.OFFSET_CDATA), (short) pubLen);
		Util.arrayCopyNonAtomic(buffer, (short) (privLen + ISO7816.OFFSET_CDATA), tempP1Pub, (short) 0, (short) 65);

		apdu.setOutgoingAndSend((short) ISO7816.OFFSET_CDATA, (short) (privLen + 65));
	}

	// set the keyPair of Party 2 from APDU
	private void genParty2Key(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short keyPairLen = apdu.setIncomingAndReceive();
		p2PrivateKey.setS(buffer, ISO7816.OFFSET_CDATA, (short) 32);
		p2PublicKey.setW(buffer, (short) (32 + ISO7816.OFFSET_CDATA), (short) 65);
		Util.arrayCopyNonAtomic(buffer, (short) (32 + ISO7816.OFFSET_CDATA), tempP2Pub, (short) 0, (short) 65);

		apdu.setOutgoingAndSend((short) ISO7816.OFFSET_CDATA, keyPairLen);
	}

	/*
	 * generate Secret key from priKey of party 1 and pubKey of party 2 use a random
	 * byte called 'seed' to increase the secure appended in the original secret key
	 * derived from the key pair then hash the result using sha256 algorithm to
	 * generate the 256 bits (32 bytes) key which is the final secret key
	 */
	private void genP1SecretKey(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short seed = apdu.setIncomingAndReceive();

		Util.arrayFillNonAtomic(temSecret, (short) 65, (short) 1, buffer[ISO7816.OFFSET_CDATA]);

		short p1Len = secp256k1.deriveShareKey(p1PrivateKey, tempP2Pub, buffer, (short) 0);
		Util.arrayCopyNonAtomic(buffer, (short) 0, temSecret, (short) 0, p1Len);

		short finall = sha256.doFinal(temSecret, (short) 0, (short) (p1Len + seed), buffer, (short) 0);
		p1ShareKey.setKey(buffer, (short) 0);

		apdu.setOutgoingAndSend((short) 0, (short) finall);
	}

	/*
	 * the message should be hashed by the sha256 algorithm to ensure the secure
	 * then encrypt the result using AES_CBC algorithm the input is the half of the
	 * hashed message cz the block size required 128 bits (16 bytes)
	 */
	private void p1EncAndSendP2(APDU apdu) throws CryptoException {
		byte[] buffer = apdu.getBuffer();
		short mg = apdu.setIncomingAndReceive();

		cipher.init(p1ShareKey, Cipher.MODE_ENCRYPT);
		short mgLen0 = cipher.update(buffer, ISO7816.OFFSET_CDATA, (short) 16, temmg, (short) 0);
		short mgLen = cipher.doFinal(buffer, (short) (ISO7816.OFFSET_CDATA + 16), (short) (mg - 16), temmg,
				(short) mgLen0);

		signature.init(p1PrivateKey, Signature.MODE_SIGN);
		short sig = signature.sign(temmg, (short) 0, (short) temmg.length, tempsign, (short) 0);
		sigSize = sig;

		Util.arrayCopyNonAtomic(temmg, (short) 0, buffer, (short) 0, (short) temmg.length);
		Util.arrayCopyNonAtomic(tempsign, (short) 0, buffer, (short) temmg.length, sig);

		apdu.setOutgoingAndSend((short) 0, (short) (sig + mgLen0 + mgLen));
	}

	private void processPin(APDU apdu) {
		byte[] buffer = apdu.getBuffer();

		random.generateData(randomBuf, (short) 0, (short) 32);

		short result = add(buffer, (short) 0, buffer, ISO7816.OFFSET_CDATA, randomBuf, (short) 0);

		signature.init(p1PrivateKey, Signature.MODE_SIGN);
		short sig = signature.sign(buffer, (short) 0, result, buffer, (short) 0);

		short cipherText = secureChannel.send(buffer, (short) 0, sig, buffer, (short) 0);
		apdu.setOutgoingAndSend((short) 0, (short) cipherText);
	}

	protected static short add(byte[] c, short c_off, byte[] a, short a_off, byte[] b, short b_off) {
		short ci = 0;
		for (short i = 31; i >= 0; i--) {
			ci = (short) ((short) (a[(short) (a_off + i)] & 0x00FF) + (short) (b[(short) (b_off + i)] & 0xFF) + ci);
			c[(short) (c_off + i)] = (byte) ci;
			ci = (short) (ci >> 8);
		}
		return ci;
	}

	// decrypt the cipher text
	private void p2DecMgOfP1(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short size = apdu.setIncomingAndReceive();

		short plainLen = 0;
		cipher.init(p1ShareKey, Cipher.MODE_DECRYPT);
		plainLen = cipher.doFinal(buffer, ISO7816.OFFSET_CDATA, (short) 16, buffer, (short) 0);
		apdu.setOutgoingAndSend((short) 0, plainLen);
	}
}
