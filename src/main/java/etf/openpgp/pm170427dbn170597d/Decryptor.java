package etf.openpgp.pm170427dbn170597d;

import etf.openpgp.pm170427dbn170597d.interfaces.IDecryptor;
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

public class Decryptor implements IDecryptor
{
	@Override
	public boolean decrypt(InputStream encryptedDataStream, OutputStream output, PGPPublicKeyRingCollection publicKeyRingCollection, PGPSecretKeyRingCollection secretKeyRingCollection, String passphrase) throws IOException, PGPException
	{
		PGPObjectFactory objectFactory = new JcaPGPObjectFactory(PGPUtil.getDecoderStream(encryptedDataStream));

		PGPDigestCalculatorProvider sha1Calc = new BcPGPDigestCalculatorProvider();

		PGPEncryptedDataList encryptedDataList = (PGPEncryptedDataList) objectFactory.nextObject();

		for(PGPEncryptedData encryptedData : encryptedDataList){
			if (encryptedData instanceof PGPPublicKeyEncryptedData)
			{
				PGPPublicKeyEncryptedData publicKeyEncryptedData = (PGPPublicKeyEncryptedData) encryptedData;

				PGPSecretKey secretKeyForMessage = secretKeyRingCollection.getSecretKey(publicKeyEncryptedData.getKeyID());

				if(secretKeyForMessage == null) {
					continue;
				}

				PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(sha1Calc).build(passphrase.toCharArray());
				InputStream input = publicKeyEncryptedData.getDataStream(new BcPublicKeyDataDecryptorFactory(secretKeyForMessage.extractPrivateKey(decryptor)));

				objectFactory = new PGPObjectFactory(input, new JcaKeyFingerprintCalculator());
				Object object = objectFactory.nextObject();

				PGPOnePassSignatureList onePassSignatureList = null;
				PGPSignatureList signatureList = null;
				PGPLiteralData literalData = null;
				final byte[] buf = new byte[1024];
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
				{
					output.write(buf);
					return false;
				}
				else {
					for(int i = 0; i < onePassSignatureList.size(); i++) {
						PGPOnePassSignature onePassSignature = onePassSignatureList.get(i);
						PGPSignature signature = signatureList.get(i);
						onePassSignature.init(new JcaPGPContentVerifierBuilderProvider(), publicKeyRingCollection.getPublicKey(onePassSignature.getKeyID()));

						for(int j = 0; j < index; j++) {
							onePassSignature.update(buf[j]);
						}

						if(onePassSignature.verify(signature)){
							output.write(buf);
							return true;
						}
						else {
							//System.out.println("Ima prike ali ne valja");
							throw new PGPException("Signature is not valid");
						}

					}
				}

			}
		}

		return false;
	}
}
