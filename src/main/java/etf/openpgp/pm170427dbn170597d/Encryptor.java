package etf.openpgp.pm170427dbn170597d;

import etf.openpgp.pm170427dbn170597d.interfaces.IEncryptor;
import org.bouncycastle.bcpg.*;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;

import java.io.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

public class Encryptor implements IEncryptor
{
	private List<PGPPublicKey> receivers = new ArrayList<>();

	public void encrypt(InputStream data, OutputStream output, PGPSecretKeyRing secretKeys, String passphrase) throws PGPException, IOException
	{
		PGPPrivateKey privateKey = null;
		PGPSecretKey secretKey = null;
		Iterator<PGPSecretKey> privateIterator = secretKeys.iterator();
		while(privateIterator.hasNext()){
			PGPSecretKey s = privateIterator.next();

			if(s.isSigningKey())
			{
				secretKey = s;
				PGPDigestCalculatorProvider sha1Calc = new BcPGPDigestCalculatorProvider();
				PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(sha1Calc).build(passphrase.toCharArray());
				privateKey = s.extractPrivateKey(decryptor);
			}
		}

		PGPSignatureGenerator generator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(secretKey.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1));
		generator.init(PGPSignature.BINARY_DOCUMENT, privateKey);

		Iterator<String> it = secretKey.getUserIDs();
		while(it.hasNext())
		{
			String userId = it.next();
			PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
			spGen.setSignatureCreationTime(false, new Date());
			spGen.setIssuerFingerprint(false, secretKey.getPublicKey());
			generator.setHashedSubpackets(spGen.generate());


			PGPSignatureSubpacketGenerator spGen2 = new PGPSignatureSubpacketGenerator();
			spGen2.setIssuerKeyID(false, secretKey.getKeyID());
			generator.setUnhashedSubpackets(spGen2.generate());
		}

		ArmoredOutputStream armourOutputStream = new ArmoredOutputStream(output);

		PGPEncryptedDataGenerator dataGenerator = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.TRIPLE_DES).setWithIntegrityPacket(true));

		for(PGPPublicKey publicKey : receivers) {
			dataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(publicKey));
		}

		OutputStream encryptedDataStream = dataGenerator.open(armourOutputStream, new byte[1024]);


		PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
		OutputStream compressOutput = compressedDataGenerator.open(encryptedDataStream);
		generator.generateOnePassVersion(false).encode(compressOutput);

		PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
		OutputStream literalOutput = literalDataGenerator.open(compressOutput, PGPLiteralDataGenerator.TEXT, "", new Date(), new byte[1024]);

		byte[] buffer = new byte[1024];
		for (int len = 0; (len = data.read(buffer)) > 0; ) {
			literalOutput.write(buffer, 0, len);
			generator.update(buffer, 0, len);
		}

		literalOutput.close();
		literalDataGenerator.close();


		generator.generate().encode(compressOutput);

		compressOutput.close();
		encryptedDataStream.close();
		armourOutputStream.close();

	}

	public Encryptor addReceiver(PGPPublicKeyRing publicKeys)
	{
		Iterator<PGPPublicKey> iterator = publicKeys.iterator();

		while(iterator.hasNext()) {
			PGPPublicKey publicKey = iterator.next();

			if(publicKey.isEncryptionKey())
				receivers.add(publicKey);
		}

		return this;
	}
}
