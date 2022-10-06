package com.example;


import java.io.File;
import java.io.FileReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import com.nimbusds.jose.crypto.*;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.bc.BouncyCastleProviderSingleton;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;


/**
 * Tests an encrypted JWT object. Uses test RSA keys from the JWE spec.
 *
 * @author Vladimir Dzhuvinov
 * @version 2017-07-11
 */
public class EncryptedJWTTest {


	private final static byte[] mod = { 
		(byte)177, (byte)119, (byte) 33, (byte) 13, (byte)164, (byte) 30, (byte)108, (byte)121, 
		(byte)207, (byte)136, (byte)107, (byte)242, (byte) 12, (byte)224, (byte) 19, (byte)226, 
		(byte)198, (byte)134, (byte) 17, (byte) 71, (byte)173, (byte) 75, (byte) 42, (byte) 61, 
		(byte) 48, (byte)162, (byte)206, (byte)161, (byte) 97, (byte)108, (byte)185, (byte)234, 
		(byte)226, (byte)219, (byte)118, (byte)206, (byte)118, (byte)  5, (byte)169, (byte)224, 

		(byte) 60, (byte)181, (byte) 90, (byte) 85, (byte) 51, (byte)123, (byte)  6, (byte)224, 
		(byte)  4, (byte)122, (byte) 29, (byte)230, (byte)151, (byte) 12, (byte)244, (byte)127, 
		(byte)121, (byte) 25, (byte)  4, (byte) 85, (byte)220, (byte)144, (byte)215, (byte)110, 
		(byte)130, (byte) 17, (byte) 68, (byte)228, (byte)129, (byte)138, (byte)  7, (byte)130, 
		(byte)231, (byte) 40, (byte)212, (byte)214, (byte) 17, (byte)179, (byte) 28, (byte)124,     

		(byte)151, (byte)178, (byte)207, (byte) 20, (byte) 14, (byte)154, (byte)222, (byte)113, 
		(byte)176, (byte) 24, (byte)198, (byte) 73, (byte)211, (byte)113, (byte)  9, (byte) 33, 
		(byte)178, (byte) 80, (byte) 13, (byte) 25, (byte) 21, (byte) 25, (byte)153, (byte)212, 
		(byte)206, (byte) 67, (byte)154, (byte)147, (byte) 70, (byte)194, (byte)192, (byte)183, 
		(byte)160, (byte) 83, (byte) 98, (byte)236, (byte)175, (byte) 85, (byte) 23, (byte) 97, 

		(byte) 75, (byte)199, (byte)177, (byte) 73, (byte)145, (byte) 50, (byte)253, (byte)206, 
		(byte) 32, (byte)179, (byte)254, (byte)236, (byte)190, (byte) 82, (byte) 73, (byte) 67, 
		(byte)129, (byte)253, (byte)252, (byte)220, (byte)108, (byte)136, (byte)138, (byte) 11, 
		(byte)192, (byte)  1, (byte) 36, (byte)239, (byte)228, (byte) 55, (byte) 81, (byte)113, 
		(byte) 17, (byte) 25, (byte)140, (byte) 63, (byte)239, (byte)146, (byte)  3, (byte)172,  

		(byte) 96, (byte) 60, (byte)227, (byte)233, (byte) 64, (byte)255, (byte)224, (byte)173, 
		(byte)225, (byte)228, (byte)229, (byte) 92, (byte)112, (byte) 72, (byte) 99, (byte) 97, 
		(byte) 26, (byte) 87, (byte)187, (byte)123, (byte) 46, (byte) 50, (byte) 90, (byte)202, 
		(byte)117, (byte) 73, (byte) 10, (byte)153, (byte) 47, (byte)224, (byte)178, (byte)163, 
		(byte) 77, (byte) 48, (byte) 46, (byte)154, (byte) 33, (byte)148, (byte) 34, (byte)228, 

		(byte) 33, (byte)172, (byte)216, (byte) 89, (byte) 46, (byte)225, (byte)127, (byte) 68, 
		(byte)146, (byte)234, (byte) 30, (byte)147, (byte) 54, (byte)146, (byte)  5, (byte)133, 
		(byte) 45, (byte) 78, (byte)254, (byte) 85, (byte) 55, (byte) 75, (byte)213, (byte) 86, 
		(byte)194, (byte)218, (byte)215, (byte)163, (byte)189, (byte)194, (byte) 54, (byte)  6, 
		(byte) 83, (byte) 36, (byte) 18, (byte)153, (byte) 53, (byte)  7, (byte) 48, (byte) 89, 

		(byte) 35, (byte) 66, (byte)144, (byte)  7, (byte) 65, (byte)154, (byte) 13, (byte) 97, 
		(byte) 75, (byte) 55, (byte)230, (byte)132, (byte)  3, (byte) 13, (byte)239, (byte) 71  };


	private static final byte[] exp= { 1, 0, 1 };


	private static final byte[] modPriv = { 
		(byte) 84, (byte) 80, (byte)150, (byte) 58, (byte)165, (byte)235, (byte)242, (byte)123, 
		(byte)217, (byte) 55, (byte) 38, (byte)154, (byte) 36, (byte)181, (byte)221, (byte)156, 
		(byte)211, (byte)215, (byte)100, (byte)164, (byte) 90, (byte) 88, (byte) 40, (byte)228, 
		(byte) 83, (byte)148, (byte) 54, (byte)122, (byte)  4, (byte) 16, (byte)165, (byte) 48, 
		(byte) 76, (byte)194, (byte) 26, (byte)107, (byte) 51, (byte) 53, (byte)179, (byte)165, 

		(byte) 31, (byte) 18, (byte)198, (byte)173, (byte) 78, (byte) 61, (byte) 56, (byte) 97, 
		(byte)252, (byte)158, (byte)140, (byte) 80, (byte) 63, (byte) 25, (byte)223, (byte)156, 
		(byte) 36, (byte)203, (byte)214, (byte)252, (byte)120, (byte) 67, (byte)180, (byte)167, 
		(byte)  3, (byte) 82, (byte)243, (byte) 25, (byte) 97, (byte)214, (byte) 83, (byte)133, 
		(byte) 69, (byte) 16, (byte)104, (byte) 54, (byte)160, (byte)200, (byte) 41, (byte) 83, 

		(byte)164, (byte)187, (byte) 70, (byte)153, (byte)111, (byte)234, (byte)242, (byte)158, 
		(byte)175, (byte) 28, (byte)198, (byte) 48, (byte)211, (byte) 45, (byte)148, (byte) 58, 
		(byte) 23, (byte) 62, (byte)227, (byte) 74, (byte) 52, (byte)117, (byte) 42, (byte) 90, 
		(byte) 41, (byte)249, (byte)130, (byte)154, (byte) 80, (byte)119, (byte) 61, (byte) 26, 
		(byte)193, (byte) 40, (byte)125, (byte) 10, (byte)152, (byte)174, (byte)227, (byte)225, 

		(byte)205, (byte) 32, (byte) 62, (byte) 66, (byte)  6, (byte)163, (byte)100, (byte) 99, 
		(byte)219, (byte) 19, (byte)253, (byte) 25, (byte)105, (byte) 80, (byte)201, (byte) 29, 
		(byte)252, (byte)157, (byte)237, (byte) 69, (byte)  1, (byte) 80, (byte)171, (byte)167, 
		(byte) 20, (byte)196, (byte)156, (byte)109, (byte)249, (byte) 88, (byte)  0, (byte)  3, 
		(byte)152, (byte) 38, (byte)165, (byte) 72, (byte) 87, (byte)  6, (byte)152, (byte) 71, 

		(byte)156, (byte)214, (byte) 16, (byte) 71, (byte) 30, (byte) 82, (byte) 51, (byte)103, 
		(byte) 76, (byte)218, (byte) 63, (byte)  9, (byte) 84, (byte)163, (byte)249, (byte) 91, 
		(byte)215, (byte) 44, (byte)238, (byte) 85, (byte)101, (byte)240, (byte)148, (byte)  1, 
		(byte) 82, (byte)224, (byte) 91, (byte)135, (byte)105, (byte)127, (byte) 84, (byte)171, 
		(byte)181, (byte)152, (byte)210, (byte)183, (byte)126, (byte) 24, (byte) 46, (byte)196, 

		(byte) 90, (byte)173, (byte) 38, (byte)245, (byte)219, (byte)186, (byte)222, (byte) 27, 
		(byte)240, (byte)212, (byte)194, (byte) 15, (byte) 66, (byte)135, (byte)226, (byte)178, 
		(byte)190, (byte) 52, (byte)245, (byte) 74, (byte) 65, (byte)224, (byte) 81, (byte)100, 
		(byte) 85, (byte) 25, (byte)204, (byte)165, (byte)203, (byte)187, (byte)175, (byte) 84, 
		(byte)100, (byte) 82, (byte) 15, (byte) 11, (byte) 23, (byte)202, (byte)151, (byte)107, 

		(byte) 54, (byte) 41, (byte)207, (byte)  3, (byte)136, (byte)229, (byte)134, (byte)131, 
		(byte) 93, (byte)139, (byte) 50, (byte)182, (byte)204, (byte) 93, (byte)130, (byte)89   };


	private static RSAPublicKey publicKey;


	private static RSAPrivateKey privateKey;


	static {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance("RSA");

			RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(new BigInteger(1, mod), new BigInteger(1, exp));
			RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(new BigInteger(1, mod), new BigInteger(1, modPriv));

			publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
			privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

			String prikey = "";
			// new
			// String pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA8NfTd/xoKzxNaxmMAVVj0e7AeC8CLGs/tWwTTQqp1xFvzbaGH4ui9ZA9dztAr18QRkIb/0XHD4tm/4cUVCbRSQYbBA3huGNJH7DlK2eNF4vGR4x5vkEjsfkJzDplrqcitQAqjTttFL142/fBNHqfRzEgzC7ZSa99vg+/iuoJcWsiWDHLuouoE7ijf1nhXhPqPfwCQlaU0nV8K/rfNCu5INCuJ5SZsrtx5rK/e+aZo97vObxysQTTEjWzFEAQ9GgyieByPQNw9dpccCuuyonouvuKn79QgiUfLNX+Cl118MWFGS1G3AdCr66mvpruvmFOxCtJWlf2Vge/6KzXXMvAqwIDAQAB";
			// TU
			// String pubkey = "MIIBCgKCAQEAxY+KtV1ZV85iJpzxJZLDZWvMeIIYvqYA3tqHy204G08TIaBeI/QGnDaeJnR5nVSBEpSSiafk3VLOxixj8uwTW7wwRts40V3nmZMvotfqK0PXTTzgVFZ1nDlm1TA6gbi9W1rBWjgs5IDPsD5VilETo7DJFRx+nN3JRwloZtKrJETXjbPVGfQVy4aR/OSh1CrtvCOP/URy6hQmtaxV/wjWnx8QC658FWcc7EHsbATJaoX3pXF/tT8VhVTAu53ymEeZnORHRogu+KFVJFNS1ShJtBKwVWiLVRqL6xDRHxbceZEGJHiFvWhn3XP+kqpmosheBU2iJw3IMWqNSup1TvmHcwIDAQAB";
			// publicKey = (RSAPublicKey) loadPrivateKey(pubkey);
			// privateKey = (RSAPrivateKey) loadPublicKey(pubkey);


		} catch (Exception e) {

			System.out.println(e);
		}
	}


	public void testEncryptAndDecrypt()
		throws Exception {

		// Compose the JWT claims set
		String iss = "https://openid.net";
		String sub = "alice";
		List<String> aud = new ArrayList<>();
		aud.add("https://app-one.com");
		aud.add("https://app-two.com");
		final Date NOW =  new Date(new Date().getTime() / 1000 * 1000);
		Date exp = new Date(NOW.getTime() + 1000*60*10);
		Date nbf = NOW;
		Date iat = NOW;
		String jti = UUID.randomUUID().toString();

		// System.out.println("private key: " + privateKey.);

		JWTClaimsSet jwtClaims = new JWTClaimsSet.Builder().
			issuer(iss).
			// subject(sub).
			// audience(aud).
			// expirationTime(exp).
			// notBeforeTime(NOW).
			// issueTime(NOW).
			// jwtID(jti).
			build();


		// Request JWT encrypted with RSA-OAEP and 128-bit AES/GCM
		// JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP, EncryptionMethod.A128GCM);
		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256);
		
		
		// Create the encrypted JWT object
		EncryptedJWT jwt = new EncryptedJWT(header, jwtClaims);
		
		// ECKey.parseFromPEMEn
		Path currentRelativePath = Paths.get("");
		String s = currentRelativePath.toAbsolutePath().toString();
		System.out.println("Current absolute path is: " + s);

		File file = new File("public.pem");
		if(file.exists()){
			System.out.println("i'm reading public.pem");
		}

		publicKey = readPublicKey(file);

		// Create an encrypter with the specified public RSA key
		RSAEncrypter encrypter = new RSAEncrypter(publicKey);
		encrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());
		
		// Do the actual encryption
		jwt.encrypt(encrypter);
		
		// Serialise to JWT compact form
		String jwtString = jwt.serialize();
		System.out.println(jwtString);
		

		// Parse back
		jwt = EncryptedJWT.parse(jwtString);


		// Create an decrypter with the specified private RSA key

		privateKey = readPrivateKey(new File("private.pem"));

		RSADecrypter decrypter = new RSADecrypter(privateKey);
		decrypter.getJCAContext().setProvider(BouncyCastleProviderSingleton.getInstance());

		// Decrypt
		jwt.decrypt(decrypter);

		// String decryptedJwt = jwt.serialize();
		System.out.println(jwt.getJWTClaimsSet().getIssuer());


		// now try mark's routing to see if i can use node-jose to decrypt
		System.out.println("now trying mark's routing");
		JWEObject jweObj = signAndEncrypt(jwtClaims, privateKey, publicKey);
		System.out.println(jweObj.serialize());

		// Parse back
		jwt = EncryptedJWT.parse(jweObj.serialize());
		jwt.decrypt(decrypter);
		System.out.println(jwt.getJWTClaimsSet().getIssuer());

		
		
	}
	
	
	public void testTrimWhitespace()
		throws Exception {
		
		KeyGenerator gen = KeyGenerator.getInstance("AES");
		gen.init(128);
		SecretKey key = gen.generateKey();
		
		EncryptedJWT jwt = new EncryptedJWT(new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128GCM), new JWTClaimsSet.Builder().build());
		jwt.encrypt(new DirectEncrypter(key));
		
		String jwtString = " " + jwt.serialize() + " ";
		
		jwt = EncryptedJWT.parse(jwtString);
		
		jwt.decrypt(new DirectDecrypter(key));		
	}

	public RSAPublicKey readPublicKey(File file) throws Exception {
		KeyFactory factory = KeyFactory.getInstance("RSA");
	
		try (FileReader keyReader = new FileReader(file);
		  PemReader pemReader = new PemReader(keyReader)) {
	
			PemObject pemObject = pemReader.readPemObject();
			byte[] content = pemObject.getContent();
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(content);
			return (RSAPublicKey) factory.generatePublic(pubKeySpec);
		}
	}

	public RSAPrivateKey readPrivateKey(File file) throws Exception {
		KeyFactory factory = KeyFactory.getInstance("RSA");
	
		try (FileReader keyReader = new FileReader(file);
		  PemReader pemReader = new PemReader(keyReader)) {
	
			PemObject pemObject = pemReader.readPemObject();
			byte[] content = pemObject.getContent();
			PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(content);
			return (RSAPrivateKey) factory.generatePrivate(privKeySpec);
		}
	}


	public JWEObject signAndEncrypt(JWTClaimsSet jwtCSInput, RSAPrivateKey tuciPrivateKey, RSAPublicKey lpPublicKey) throws JOSEException, NoSuchAlgorithmException {
	
		JWSSigner signer = new RSASSASigner(tuciPrivateKey);
	
		SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), jwtCSInput);
		signedJWT.sign(signer);
		JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256);
		JWEObject jweObject = new JWEObject(header, new Payload(signedJWT));
		RSAEncrypter encrypter = new RSAEncrypter(lpPublicKey);
		jweObject.encrypt(encrypter);		
		return jweObject;
	}
	

}
