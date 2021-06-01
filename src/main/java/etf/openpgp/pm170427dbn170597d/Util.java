package etf.openpgp.pm170427dbn170597d;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

public class Util
{
	public static PGPSecretKeyRing loadSecretKeyRingFromFile(String filename) throws IOException, PGPException
	{
		ArmoredInputStream inputStream = new ArmoredInputStream(new FileInputStream(filename));

		PGPObjectFactory objectFactory = new PGPObjectFactory(inputStream, new JcaKeyFingerprintCalculator());

		Object o = objectFactory.nextObject();

		if(o instanceof PGPSecretKeyRing)
			return (PGPSecretKeyRing) o;

		throw new PGPException("Private key not provided");
	}

	public static PGPPublicKeyRing loadPublicKeyRingFromFile(String filename) throws IOException, PGPException
	{
		ArmoredInputStream inputStream = new ArmoredInputStream(new FileInputStream(filename));

		PGPObjectFactory objectFactory = new PGPObjectFactory(inputStream, new JcaKeyFingerprintCalculator());

		Object o = objectFactory.nextObject();

		if(o instanceof PGPPublicKeyRing)
			return (PGPPublicKeyRing) o;

		throw new PGPException("Public key not provided");
	}

	public static void saveKeyRingToFile(PGPKeyRing keyRing, String filename) throws IOException
	{
		ArmoredOutputStream outputStream = new ArmoredOutputStream(new FileOutputStream(filename));

		keyRing.encode(outputStream);

		outputStream.close();
	}
}
