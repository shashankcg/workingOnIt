
//http://stackoverflow.com/questions/16662408/correct-way-to-sign-and-verify-signature-using-bouncycastle

import sun.misc.BASE64Encoder;
import java.security.*;
import java.security.cert.CertificateException;

		/*
	public static KeyStore loadKeystore(String keystoreFile, String keystorePassword)throws IOException, KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException	 
	{
		FileInputStream fis=null;
		BufferedInputStream bis=null;
		KeyStore ks=null;
		try{
			ks = KeyStore.getInstance("JKS" , "SUN");
			fis=new FileInputStream(keystoreFile);
			bis=new BufferedInputStream(fis);
			ks.load(bis,keystorePassword.toCharArray());
		}finally{
			if(bis!=null){
				bis.close();
			}
			if(fis!=null){
				fis.close();
			}
		}
		return ks;
	}
	
	public static void main(String[] args) throws KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException, IOException, UnrecoverableEntryException{
		KeyStore ks = loadKeystore("/ise/certs/nameofKeystore.jks", "changeit");
		KeyStore.ProtectionParameter kpp = new KeyStore.PasswordProtection("changeit".toCharArray());
		KeyStore.Entry entry = ks.getEntry("tomcat", kpp); 
		Key key = ks.getKey("tomcat", "changeit".toCharArray());
		System.out.println(BASE64Encoder().encode(key.getEncoded()));
		//System.out.println(entry);
	}*/
	
	import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.apache.xmlbeans.impl.util.Base64;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedDataParser;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import sun.misc.BASE64Encoder;

	public class SignMessage {

	    static final String KEYSTORE_FILE = "/ise/certs/nameofkeystore.jks";
	    static final String KEYSTORE_INSTANCE = "JKS";
	    static final String KEYSTORE_PWD = "changeit";
	    static final String KEYSTORE_ALIAS = "tomcat";

	    @SuppressWarnings("restriction")
		public static void main(String[] args) throws Exception {

	        String text = "This is a message";

	        Security.addProvider(new BouncyCastleProvider());

	        KeyStore ks = KeyStore.getInstance(KEYSTORE_INSTANCE);
	        ks.load(new FileInputStream(KEYSTORE_FILE), KEYSTORE_PWD.toCharArray());
	        Key key = ks.getKey(KEYSTORE_ALIAS, KEYSTORE_PWD.toCharArray());


	        //Build CMS
	        X509Certificate cert = (X509Certificate) ks.getCertificate(KEYSTORE_ALIAS);
	        System.out.println(cert.getSubjectX500Principal().);
	        List certList = new ArrayList();
	        CMSTypedData msg = new CMSProcessableByteArray(text.getBytes());
	        certList.add(cert);
	        Store certs = new JcaCertStore(certList);
	        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
	        //CMSSignedDataParser
	        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(privKey);
	        gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(sha1Signer, cert));
	        gen.addCertificates(certs);
	        CMSSignedData sigData = gen.generate(msg, true);

	        BASE64Encoder encoder = new BASE64Encoder();

	        String signatureWithSignedData = encoder.encode(sigData.getEncoded());
	        System.out.println("Signature with SignedData: " + signatureWithSignedData);
	        
	        byte[] print = (byte []) sigData.getSignedContent().getContent();
	        String s = new String(print);
	        //System.out.println(s);
	        
	        
	    }
	}
