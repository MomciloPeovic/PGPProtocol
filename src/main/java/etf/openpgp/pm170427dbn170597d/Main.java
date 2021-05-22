package etf.openpgp.pm170427dbn170597d;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.crypto.params.ElGamalPublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.*;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;

import javax.crypto.Cipher;
import javax.crypto.spec.DHParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.KeySpec;
import java.util.Date;

public class Main
{

	public static void main(String[] args) throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());

		KeyPair dsaKeyPair = DSAKeyGenerator.generateKeyPair(1024);


		PGPSignatureGenerator generator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(PGPPublicKey.DSA, HashAlgorithmTags.SHA1));
		generator.init(PGPPublicKey.DSA, new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKeyPair, new Date()).getPrivateKey());
		generator.update(args[0].getBytes());
		PGPSignature signature = generator.generate();

		System.out.println(signature.getEncoded().length);

		ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(signature.getEncoded().length);

		PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
		OutputStream o = compressedDataGenerator.open(byteArrayOutputStream, signature.getEncoded());


		PGPDataEncryptorBuilder pgpDataEncryptorBuilder = new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.TRIPLE_DES);
		PGPDataEncryptor encryptor = pgpDataEncryptorBuilder.build(new byte[]{0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16});
		o = encryptor.getOutputStream(o);




//		KeyPair elgKp = ElGamalKeyGenerator.generateKeyPair(1024);
//
//		Cipher cipher = Cipher.getInstance("ELGAMAL");
//		cipher.init(Cipher.ENCRYPT_MODE, elgKp.getPublic());
//
//		byte[] cipherText = cipher.doFinal(message.getBytes());
//
//		cipher = Cipher.getInstance("ELGAMAL");
//		cipher.init(Cipher.DECRYPT_MODE, elgKp.getPrivate());
	}

	private static void exportKeyPair(
			OutputStream secretOut,
			OutputStream publicOut,
			KeyPair dsaKp,
			KeyPair elgKp,
			String identity,
			char[] passPhrase,
			boolean armor)
			throws IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException
	{
		if (armor)
		{
			secretOut = new ArmoredOutputStream(secretOut);
		}

		PGPKeyPair dsaKeyPair = new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKp, new Date());
		PGPKeyPair elgKeyPair = new JcaPGPKeyPair(PGPPublicKey.ELGAMAL_ENCRYPT, elgKp, new Date());
		PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
		PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, dsaKeyPair,
				identity, sha1Calc, null, null, new JcaPGPContentSignerBuilder(dsaKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1), new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha1Calc).setProvider("BC").build(passPhrase));

		keyRingGen.addSubKey(elgKeyPair);

		keyRingGen.generateSecretKeyRing().encode(secretOut);

		secretOut.close();

		if (armor)
		{
			publicOut = new ArmoredOutputStream(publicOut);
		}

		keyRingGen.generatePublicKeyRing().encode(publicOut);

		publicOut.close();
	}


}
