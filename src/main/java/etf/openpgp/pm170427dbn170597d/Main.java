package etf.openpgp.pm170427dbn170597d;

import com.sun.xml.internal.messaging.saaj.util.ByteOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.*;

import java.io.*;
import java.security.*;
import java.util.Date;

public class Main
{

	public static void main(String[] args) throws Exception
	{
		Security.addProvider(new BouncyCastleProvider());

		char[] symmetricKey = new char[16];

		String plaintext = args[0];
		ByteOutputStream byteOutputStream = new ByteOutputStream();

		KeyPair dsaKeyPair = DSAKeyGenerator.generateKeyPair(1024);
		KeyPair elGamalKeyPair = ElGamalKeyGenerator.generateKeyPair(1024);

		PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
		OutputStream o = literalDataGenerator.open(byteOutputStream, PGPLiteralDataGenerator.TEXT, "text", args[0].length(), new Date());
		o.write(plaintext.getBytes());
		o.close();

		byte[] plaintextBytes = byteOutputStream.getBytes();

		PGPSignatureGenerator generator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(PGPPublicKey.DSA, HashAlgorithmTags.SHA1));
		generator.init(PGPPublicKey.DSA, new JcaPGPKeyPair(PGPPublicKey.DSA, dsaKeyPair, new Date()).getPrivateKey());
		generator.update(plaintextBytes);
		PGPSignature signature = generator.generate();

		byteOutputStream = new ByteOutputStream();
		PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
		o = compressedDataGenerator.open(byteOutputStream);
		o.write(signature.getEncoded());
		o.write(plaintextBytes);
		o.close();

		byte[] compressedMessageWithSignature = byteOutputStream.getBytes();

		byteOutputStream = new ByteOutputStream();
		PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(new BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.TRIPLE_DES));
		encryptedDataGenerator.addMethod(new JcePBEKeyEncryptionMethodGenerator(symmetricKey));
		o = encryptedDataGenerator.open(byteOutputStream, compressedMessageWithSignature.length);
		o.write(compressedMessageWithSignature);
		o.close();

		byte[] encryptedMessage = byteOutputStream.getBytes();



		InputStream inputStream = new ByteArrayInputStream(encryptedMessage);
		inputStream = PGPUtil.getDecoderStream(inputStream);

		PGPObjectFactory objectFactory = new JcaPGPObjectFactory(inputStream);
		PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) objectFactory.nextObject();
		PGPPBEEncryptedData e = (PGPPBEEncryptedData) encryptedDataList.get(0);

		InputStream clear = e.getDataStream(new JcePBEDataDecryptorFactoryBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build(symmetricKey));




		objectFactory = new JcaPGPObjectFactory(clear);
		PGPCompressedData compressedData = (PGPCompressedData) objectFactory.nextObject();

		byte[] decompressedMessageWithSignature = new byte[1000];
		compressedData.getDataStream().read(decompressedMessageWithSignature);

		objectFactory = new JcaPGPObjectFactory(decompressedMessageWithSignature);
		PGPSignatureList signatureList = (PGPSignatureList) objectFactory.nextObject();
		PGPLiteralData literalData = (PGPLiteralData) objectFactory.nextObject();

		byte[] decodedPlaintext = new byte[100];
		literalData.getDataStream().read(decodedPlaintext);
		System.out.println(new String(decodedPlaintext));
	}

}
