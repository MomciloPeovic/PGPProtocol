package etf.openpgp.pm170427dbn170597d;


import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;

import java.io.*;
import java.util.Arrays;

public class Decryption
{

	public static void main(String[] args) throws Exception
	{
		Decryptor decryptor = new Decryptor();

		ArmoredInputStream inputStream = new ArmoredInputStream(new FileInputStream("generateddata.txt"));

		PGPPublicKeyRing publicKeyRing = Util.loadPublicKeyRingFromFile("dummy.pkr");
		PGPPublicKeyRing publicKeyRing1 = Util.loadPublicKeyRingFromFile("pgpkey.txt");

		PGPPublicKeyRingCollection publicKeyRingCollection = new PGPPublicKeyRingCollection(Arrays.asList(publicKeyRing, publicKeyRing1));

		PGPSecretKeyRing secretKeyRing = Util.loadSecretKeyRingFromFile("dummy.skr");
		PGPSecretKeyRingCollection secretKeyRingCollection = new PGPSecretKeyRingCollection(Arrays.asList(secretKeyRing));

		if(decryptor.decrypt(inputStream, System.out, publicKeyRingCollection, secretKeyRingCollection, "hello")) {
			System.out.println("\nSignature valid");
		}
		else {
			System.out.println("Signature invalid");
		}


	}

}
