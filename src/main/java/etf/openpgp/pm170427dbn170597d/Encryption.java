package etf.openpgp.pm170427dbn170597d;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;

import java.io.*;
import java.security.*;
import java.util.Arrays;

public class Encryption
{

	public static void main(String[] args) throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());

		ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(args[0].getBytes());

		PGPPublicKeyRing publicKeyRing = Util.loadPublicKeyRingFromFile("pgpkey.txt");
		PGPSecretKeyRing secretKeyRing = Util.loadSecretKeyRingFromFile("dummy.skr");
		PGPPublicKeyRing selfPublicKey = Util.loadPublicKeyRingFromFile("dummy.pkr");

		Encryptor encryptor = new Encryptor();
		encryptor.addReceiver(publicKeyRing);
		encryptor.addReceiver(selfPublicKey);
		encryptor.encrypt(byteArrayInputStream, System.out, secretKeyRing, "hello");
	}

}
