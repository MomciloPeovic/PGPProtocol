package etf.openpgp.pm170427dbn170597d;


import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;

import java.io.*;

public class Decryption
{

	public static void main(String[] args) throws Exception
	{
		ArmoredInputStream privateKeyStream = new ArmoredInputStream(new FileInputStream("dummy.skr"));
		ArmoredInputStream publicKeyStream = new ArmoredInputStream(new FileInputStream("pgpkey.txt"));

		PGPObjectFactory objectFactory = new JcaPGPObjectFactory(privateKeyStream);
		PGPSecretKeyRing secretKeyRing = (PGPSecretKeyRing) objectFactory.nextObject();

		objectFactory = new JcaPGPObjectFactory(publicKeyStream);
		PGPPublicKeyRing publicKeyRing = (PGPPublicKeyRing) objectFactory.nextObject();

		ArmoredInputStream dataStream = new ArmoredInputStream(new FileInputStream("generateddata.txt"));

		objectFactory = new JcaPGPObjectFactory(PGPUtil.getDecoderStream(dataStream));

		PGPDigestCalculatorProvider sha1Calc = new BcPGPDigestCalculatorProvider();

		char pass[] = {'h', 'e', 'l', 'l', 'o'};
		PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) objectFactory.nextObject();
		PGPEncryptedData encryptedData = encryptedDataList.get(0);

		if (encryptedData instanceof PGPPublicKeyEncryptedData)
		{
			PGPPublicKeyEncryptedData publicKeyEncryptedData = (PGPPublicKeyEncryptedData) encryptedData;

			PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(sha1Calc).build(pass);
			InputStream input = publicKeyEncryptedData.getDataStream(new BcPublicKeyDataDecryptorFactory(secretKeyRing.getSecretKey(publicKeyEncryptedData.getKeyID()).extractPrivateKey(decryptor)));

			objectFactory = new PGPObjectFactory(input, new JcaKeyFingerprintCalculator());
			Object object = objectFactory.nextObject();

			PGPOnePassSignatureList onePassSignatureList = null;
			PGPSignatureList signatureList = null;
			PGPLiteralData literalData = null;
			final byte[] buf = new byte[4096];
			int index = 0;

			while (object != null)
			{
				if (object instanceof PGPCompressedData)
				{
					PGPCompressedData compressedData = (PGPCompressedData) object;
					objectFactory = new PGPObjectFactory(PGPUtil.getDecoderStream(compressedData.getDataStream()), new JcaKeyFingerprintCalculator());
					object = objectFactory.nextObject();
				}
				else if (object instanceof PGPOnePassSignatureList)
				{
					onePassSignatureList = (PGPOnePassSignatureList) object;
					object = objectFactory.nextObject();
				}
				else if (object instanceof PGPSignatureList)
				{
					signatureList = (PGPSignatureList) object;
					object = objectFactory.nextObject();
				}
				else if (object instanceof PGPLiteralData)
				{
					literalData = (PGPLiteralData) object;
					final InputStream in = literalData.getInputStream();

					for(int len = 0; (len = in.read(buf, index, 10)) > 0;) {
						index += len;
						//onePassSignature.update(buf, 0, len);
					}
					in.close();
					object = objectFactory.nextObject();
				}
				else {
					object = objectFactory.nextObject();
				}
			}

			if(onePassSignatureList == null || signatureList == null)
				System.out.println("Nema prike");
			else {
				for(int i = 0; i < onePassSignatureList.size(); i++) {
					PGPOnePassSignature onePassSignature = onePassSignatureList.get(i);
					PGPSignature signature = signatureList.get(i);
					onePassSignature.init(new JcaPGPContentVerifierBuilderProvider(), publicKeyRing.getPublicKey(onePassSignature.getKeyID()));

					for(int j = 0; j < index; j++) {
						onePassSignature.update(buf[j]);
					}

					System.out.println(new String(buf));

					if(onePassSignature.verify(signature)){
						System.out.println("Ima prike");
					}
					else {
						System.out.println("Ima prike ali ne valja");
					}

				}
			}

		}
	}

}
