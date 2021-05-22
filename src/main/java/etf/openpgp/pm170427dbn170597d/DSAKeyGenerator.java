package etf.openpgp.pm170427dbn170597d;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;

public class DSAKeyGenerator
{
	public static KeyPair generateKeyPair(int keysize) throws NoSuchProviderException, NoSuchAlgorithmException
	{
		KeyPairGenerator dsaKpg = KeyPairGenerator.getInstance("DSA", BouncyCastleProvider.PROVIDER_NAME);
		dsaKpg.initialize(keysize, new SecureRandom());

		return dsaKpg.generateKeyPair();
	}
}
