import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.*;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.Store;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
import org.apache.commons.cli.*;

/**
 * @author 969243
 *
 */
public class Encryptor {

	private static String JKSPassword = "";
	private static  KeyStore ks = null;
	private static  String alias = null;
	private static  X509Certificate UserCert = null;
	private static  PrivateKey UserCertPrivKey = null;
	private static  PublicKey UserCertPubKey = null;
	private static X509Certificate myPubCert = null;





	public static void main(String[] args){
		// adding bouncycastle as security provider
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		/*
		* adding cli options
		* */
		Options options = new Options();

		Option new_sc = new Option("new", true, "will return new signed content");
		options.addOption(new_sc);

		Option verify = new Option("verify", true, "verify previously generated signed content");
		options.addOption(verify);

		Option aspid = new Option("aspid", true, "ASPID or CLIENTID provided from GSP");
		aspid.setRequired(true);
		options.addOption(aspid);

		Option timestamp = new Option("timestamp", true, "date + \"%d%m%Y%H%M%S%N\" | cut -b1-20");
		timestamp.setRequired(true);
		options.addOption(timestamp);

		Option jks = new Option("jks", true, "your jks file path");
		jks.setRequired(true);
		options.addOption(jks);

		Option pass = new Option("pass", true, "password for jks file");
		pass.setRequired(false);
		options.addOption(pass);

		/*
		* parsing cli inputs
		* */
		CommandLineParser parser = new DefaultParser();
		HelpFormatter formatter = new HelpFormatter();
		CommandLine cmd;

		try {
			cmd = parser.parse(options,args);
			String cmd_aspid = cmd.getOptionValue("aspid");
			String cmd_timestamp = cmd.getOptionValue("timestamp");
			String timeAsp = cmd_aspid+cmd_timestamp;
			String jksFilePath = cmd.getOptionValue("jks");
			JKSPassword = cmd.getOptionValue("pass");

			if (cmd.hasOption("new")){
				try{

					String data =  new Encryptor().generateSignature(timeAsp, jksFilePath);
					try{
						PrintWriter writer = new PrintWriter(cmd.getOptionValue("new"), "UTF-8");
						writer.println(data);
						writer.close();

						System.out.println("done");
					} catch (IOException e) {
						// do something
						System.out.println(e.getCause());
					}
				}catch (Exception e) {
					System.out.println(e.getCause());
					e.printStackTrace();
				}
			}else if (cmd.hasOption("verify")){
				System.out.println("verifying content");
				try{
					String pathTosignedData = cmd.getOptionValue("verify");
					try(BufferedReader br = new BufferedReader(new FileReader(pathTosignedData))) {
						StringBuilder sb = new StringBuilder();
						String line = br.readLine();

						while (line != null) {
							sb.append(line);
							sb.append(System.lineSeparator());
							line = br.readLine();
						}
						String signedData = sb.toString();
						Boolean rslt = new Encryptor().verifySignedContent(signedData.toString());
						System.out.println(rslt);
					}

				}catch (Exception e){
					System.out.println("file not found");
					System.exit(1);
					return;
				}
			}else{
				formatter.printHelp("signer", options);
				System.exit(1);
				return;
			}

		}catch (ParseException e){
			System.out.println(e.getMessage());
			formatter.printHelp("signer", options);
			System.exit(1);
			return;
		}
	}

	
	public String generateSignature(String data, String jksFilePath) throws Exception
	{

			//System.out.println("in generateSignature() for data: "+data);

			try{
				//Adding Security Provider for PKCS 12
				Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
				//Setting password for the e-Token

				//logging into token
				ks = KeyStore.getInstance("jks");

				FileInputStream fileInputStream = new FileInputStream(jksFilePath);

				//Loading Keystore
	//			System.out.println("loading keystore");
				ks.load(fileInputStream, JKSPassword.toCharArray());
				Enumeration<String> e = ks.aliases();

				while (e.hasMoreElements())
				{
					alias = e.nextElement();
					//System.out.println("Alias of the e-Token : "+ alias);

					UserCert = (X509Certificate) ks.getCertificate(alias);

					UserCertPubKey = (PublicKey) ks.getCertificate(alias).getPublicKey();

	//				System.out.println("loading Private key");
					UserCertPrivKey = (PrivateKey) ks.getKey(alias, JKSPassword.toCharArray());
				}

				//Method Call to generate Signature
				return MakeSignature(data);
			}
			catch(Exception e)
			{
				System.out.println("generateSignature "+e.getCause());
				throw new Exception();
			}

		}


	public String MakeSignature(String data) throws Exception
	{

		//System.out.println("MakeSignature called on data:"+data);

		try
		{
			PrivateKey privateKey=(PrivateKey) ks.getKey(alias,JKSPassword.toCharArray());
			myPubCert=(X509Certificate) ks.getCertificate(alias);
			Store certs = new JcaCertStore(Arrays.asList(myPubCert));

			CMSSignedDataGenerator generator = new CMSSignedDataGenerator();

			generator.addSignerInfoGenerator(new JcaSimpleSignerInfoGeneratorBuilder().setProvider("BC").build("SHA256withRSA", privateKey, myPubCert));

			generator.addCertificates(certs);

			CMSTypedData data1 = new CMSProcessableByteArray(data.getBytes());

			CMSSignedData signed = generator.generate(data1,true);


		   // signed = new CMSSignedData(data1, signed.getEncoded());
		   // System.out.println("data=="+signed.toString());

			BASE64Encoder encoder = new BASE64Encoder();

			String signedContent = encoder.encode((byte[]) signed.getSignedContent().getContent());
			//System.out.println("Signed content: " + signedContent + "\n");

			String envelopedData = encoder.encode(signed.getEncoded());

			return envelopedData;
		}
		catch (Exception e)
		{
			System.out.println("MakeSignature =="+e.getCause());
			throw new Exception();
		}
	}

	public boolean verifySignedContent(String bytes)
	{
		boolean verify = false;
		try
		{
			CMSSignedData signedData = new CMSSignedData(new BASE64Decoder().decodeBuffer(bytes));
			byte[] byte_out=null;
			ByteArrayOutputStream out=null;
			out = new ByteArrayOutputStream();
			signedData.getSignedContent().write(out);;
			byte_out=out.toByteArray();
			String s = new String(byte_out);
			System.out.println("Original Content-->" +s);
			System.out.println("asp id-->" +s.substring(0, 18));
			System.out.println("timestamp-->" +s.substring(18));
			Store store = signedData.getCertificates();
			SignerInformationStore signers = signedData.getSignerInfos();
			Collection c = signers.getSigners();
			Iterator it = c.iterator();
			while (it.hasNext())
			{
				SignerInformation signer = (SignerInformation) it.next();
				System.out.println(signer);

				Collection certCollection = store.getMatches(signer.getSID());
				Iterator certIt = certCollection.iterator();
				X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
				X509Certificate cert;

				cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

				String ca="";
				String certNum=cert.getSerialNumber()+"";
				System.out.println(cert.getIssuerDN());
				String issuerDetails=cert.getIssuerDN()+"";
				String temp[]=issuerDetails.split(",");
				for(int i=0;i<temp.length;i++)
				{
					if(temp[i].startsWith("CN"))
					{
						String temp2[]=temp[i].split("=");
						ca=temp2[1];
					}
				}



				System.out.println(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert));
				if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert)))
				{
					System.out.println("verified");
					verify=true;
				}
				 System.out.println(ca);
				 System.out.println(certNum);
			}

		}
		catch (IOException e)
		{
			System.out.println(e.getCause());
			verify = false;
		}
		catch (CertificateException e)
		{
			System.out.println(e.getCause());
			verify = false;
		}
		catch (OperatorCreationException e)
		{
			System.out.println(e.getCause());
			verify = false;
		}
		catch (CMSException e)
		{
			System.out.println(e.getCause());
			verify = false;
		}
		return verify;
	}
}