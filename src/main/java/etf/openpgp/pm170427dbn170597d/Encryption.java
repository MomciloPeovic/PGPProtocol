package etf.openpgp.pm170427dbn170597d;

import org.bouncycastle.bcpg.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.*;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.openpgp.operator.jcajce.*;

import java.io.*;
import java.security.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

public class Encryption
{

	public static void main(String[] args) throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());

		char pass[] = {'h', 'e', 'l', 'l', 'o'};


		ArmoredInputStream privateKeyStream = new ArmoredInputStream(new FileInputStream("dummy.skr"));

		PGPObjectFactory objectFactory = new JcaPGPObjectFactory(privateKeyStream);
		PGPSecretKeyRing secretKeyRing = (PGPSecretKeyRing) objectFactory.nextObject();

		PGPPrivateKey privateKey = null;
		PGPSecretKey secretKey = null;
		Iterator<PGPSecretKey> privateIterator = secretKeyRing.iterator();
		while(privateIterator.hasNext()){
			PGPSecretKey s = privateIterator.next();

			if(s.isSigningKey()) {
				secretKey = s;
				PGPDigestCalculatorProvider sha1Calc = new BcPGPDigestCalculatorProvider();
				PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(sha1Calc).build(pass);
				privateKey = s.extractPrivateKey(decryptor);
			}
		}

		String plaintext = args[0];

		PGPSignatureGenerator generator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1));
		generator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

		Iterator<String> it = secretKey.getUserIDs();
		while(it.hasNext())
		{
			String userId = it.next();
			PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
			spGen.setSignatureCreationTime(false, new Date());
			spGen.setIssuerFingerprint(false, secretKey.getPublicKey());

			PGPSignatureSubpacketGenerator spGen2 = new PGPSignatureSubpacketGenerator();
			spGen2.setIssuerKeyID(false, secretKey.getKeyID());
			generator.setHashedSubpackets(spGen.generate());
			generator.setUnhashedSubpackets(spGen2.generate());
		}





		ArmoredInputStream publicKeyStream = new ArmoredInputStream(new FileInputStream("pgpkey.txt"));
		PGPObjectFactory publicKeyObjectFactory = new JcaPGPObjectFactory(publicKeyStream);
		PGPPublicKeyRing publicKeyRing = (PGPPublicKeyRing) publicKeyObjectFactory.nextObject();



		Iterator<PGPPublicKey> iterator = publicKeyRing.getPublicKeys();
		PGPPublicKey p = null;
		while(iterator.hasNext()) {
			PGPPublicKey publicKey = iterator.next();

			if(publicKey.getAlgorithm() == PGPPublicKey.ELGAMAL_ENCRYPT)
				p = publicKey;
		}

		ArmoredOutputStream armourOutputStream = new ArmoredOutputStream(new FileOutputStream("generateddata.txt"));


		PGPEncryptedDataGenerator dataGenerator = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.TRIPLE_DES).setWithIntegrityPacket(true));
		dataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(p));
		OutputStream encryptedDataStream = dataGenerator.open(armourOutputStream, new byte[100]);

		PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
		OutputStream compressOutput = compressedDataGenerator.open(encryptedDataStream);
		generator.generateOnePassVersion(false).encode(compressOutput);

		PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
		OutputStream literalOutput = literalDataGenerator.open(compressOutput, PGPLiteralDataGenerator.TEXT, "", args[0].length(), new Date());

		for (byte c : plaintext.getBytes()) {
			literalOutput.write(c);
			generator.update(c);
		}

		literalOutput.close();
		literalDataGenerator.close();


		generator.generate().encode(compressOutput);

		compressOutput.close();
		encryptedDataStream.close();
		armourOutputStream.close();

	}

}
