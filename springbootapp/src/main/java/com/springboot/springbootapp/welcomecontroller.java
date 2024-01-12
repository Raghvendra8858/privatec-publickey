package com.springboot.springbootapp;

import java.security.SecureRandom;
import java.util.Base64;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.spec.X509EncodedKeySpec;
@RestController
public class welcomecontroller {
	@GetMapping("/welcome")
	public String welcome() {
		return "welcome tp spring boot app development";
	
	}
	
	
	@GetMapping("/GetKeys")
	public String getKeys() {
		
		String pfxFilePath = "E:\\GAURAV_CHAUBEY_1.pfx";
        String pfxPassword = "123";
        String pubFilePath="E:\\public_key.pem";
        String privateFilePath="E:\\private_key.pem";
        
        
        try {
            // Load the PFX file
            FileInputStream fis = new FileInputStream(pfxFilePath);
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(fis, pfxPassword.toCharArray());

            // Get the private key
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(keyStore.aliases().nextElement(), pfxPassword.toCharArray());

            // Get the certificate (contains the public key)
            Certificate cert = keyStore.getCertificate(keyStore.aliases().nextElement());
            PublicKey publicKey = cert.getPublicKey();

            // Print the private and public keys in PEM format (you may want to save them to files)
            System.out.println("Private Key (PEM):");
            System.out.println(privateKey);
            welcomecontroller.savePrivateKeyToPEM(privateKey,privateFilePath);
            
            
            System.out.println("Public Key (PEM):");
            System.out.println(publicKey);
            welcomecontroller.savePublicKeyToPEM(publicKey,pubFilePath);
            fis.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
		return "successfull";
		
	}


	private static void savePublicKeyToPEM(PublicKey publicKey, String outputFilePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(outputFilePath);
             PrintWriter writer = new PrintWriter(new OutputStreamWriter(fos));
             PemWriter pemWriter = new PemWriter(writer)) {

            PemObject pemObject = new PemObject("PUBLIC KEY", publicKey.getEncoded());
            pemWriter.writeObject(pemObject);
        }
    }
	

	private static void savePrivateKeyToPEM(PrivateKey privateKey, String outputFilePath) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(outputFilePath);
             PrintWriter writer = new PrintWriter(new OutputStreamWriter(fos));
             PemWriter pemWriter = new PemWriter(writer)) {

            PemObject pemObject = new PemObject("PRIVATE KEY", privateKey.getEncoded());
            pemWriter.writeObject(pemObject);
        }
    }
	
//	 private static String convertKeyToPem(Key key) throws Exception {
//	        byte[] keyBytes = key.getEncoded();
//	        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
//	        KeyFactory keyFactory = KeyFactory.getInstance(key.getAlgorithm());
//	        PublicKey publicKey = keyFactory.generatePublic(spec);
//	        return KeyUtils.getPEMFromKey(publicKey); // You need to implement this method
//	    }
	
	
	
	
	
	String iv;
	String ivKey;
	 public static String generateRandomKey() {
	        SecureRandom secureRandom = new SecureRandom();
	        byte[] key = new byte[16];
	        secureRandom.nextBytes(key);
	        return Base64.getEncoder().encodeToString(key);
	    }

	 public static String generateRandomSalt() {
	        SecureRandom secureRandom = new SecureRandom();
	        byte[] salt = new byte[16];
	        secureRandom.nextBytes(salt);
	        return Base64.getEncoder().encodeToString(salt);
	    }

	@PostMapping("GetAESwithCBC")
	public String getCBCEncryption(@RequestBody String data) {
		
			 iv=generateRandomSalt();
			 ivKey=generateRandomKey();
			
			try {
				 byte[] ivs = Base64.getDecoder().decode(iv);
				 IvParameterSpec ivspec = new IvParameterSpec(ivs);
				 SecretKeySpec keySpec = new
				SecretKeySpec(Base64.getDecoder().decode(ivKey), "AES");
				 Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
				 cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivspec);
				 byte[] encrypted = cipher.doFinal(data.getBytes("UTF-8"));
				 return bytesToHex(encrypted);
				 } catch (Exception e) {
				 e.printStackTrace();
				 } 
		return "hello this method is called and it's returning"+data;
		
	}
	
	 private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
	
	public static String bytesToHex(byte[] bytes) {
		 
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
	
	@PostMapping("DecryptCBCData")
	public String getDecryptDataFromCBCEnc(@RequestBody String Data) {
		
		try {
			byte[] msg = hexStringToByteArray(Data);
			 SecretKeySpec keySpec = new SecretKeySpec(Base64.getDecoder().decode(ivKey), "AES");
			 byte[] ivs = Base64.getDecoder().decode(iv);
			 IvParameterSpec ivspec = new IvParameterSpec(ivs);
			 Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			 cipher.init(Cipher.DECRYPT_MODE, keySpec, ivspec);
			 return new String(cipher.doFinal(msg));
			 } catch (Exception e) {
			 e.printStackTrace();
			 }
			 return null; 

		
		
	}
	
	public static byte[] hexStringToByteArray(String s) {
	    int len = s.length();
	    byte[] data = new byte[len / 2];
	    for (int i = 0; i < len; i += 2) {
	        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
	                             + Character.digit(s.charAt(i+1), 16));
	    }
	    return data;

}
}
