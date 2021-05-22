package etf.openpgp.pm170427dbn170597d;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class ElGamalKeyGenerator
{
	public static KeyPair generateKeyPair(int keysize) throws NoSuchProviderException, NoSuchAlgorithmException
	{
		KeyPairGenerator elgKpg = KeyPairGenerator.getInstance("ELGAMAL", "BC");
		elgKpg.initialize(keysize);

		return elgKpg.generateKeyPair();
	}
}
