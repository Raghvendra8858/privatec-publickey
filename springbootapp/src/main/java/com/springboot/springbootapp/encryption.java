package com.springboot.springbootapp;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;

import org.apache.tomcat.util.codec.binary.Base64;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSAEncrypter;

public class encryption {

    public static String encryptFraudReportJsonRequest(String plainJsonRequest, String publicKeyFileNameWithPath)
            throws Exception {
        // Set the plain text
        Payload payload = new Payload(plainJsonRequest);
        // Create the header
        JWEHeader header = new JWEHeader(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM);
        // Create the JWE object and encrypt it
        JWEObject jweObject = new JWEObject(header, payload);
        jweObject.encrypt(new RSAEncrypter(getFraudReportPublicKey(publicKeyFileNameWithPath)));
        // Serialize to compact JOSE form...
        return jweObject.serialize();
    }

    public static String decryptFraudReportJsonResponse(String encryptedResponse, String privateKeyFileNameWithPath)
            throws Exception {
        // Parse into JWE object...
        JWEObject jweObject = JWEObject.parse(encryptedResponse);
        jweObject.decrypt(new RSADecrypter(getFraudReportPrivateKey(privateKeyFileNameWithPath)));
        // Get the plain text
        Payload payload = jweObject.getPayload();
        return payload.toString();
    }

    private static RSAPublicKey getFraudReportPublicKey(String publicKeyFileNameWithPath) throws Exception {
        InputStream publicKeyStream = null;
        try {
            publicKeyStream = new FileInputStream(publicKeyFileNameWithPath);

            if (publicKeyStream.available() == 0) {
                throw new IOException("Public key file is empty.");
            }

            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            return (RSAPublicKey) certFactory.generateCertificate(publicKeyStream).getPublicKey();
        } catch (IOException e) {
            e.printStackTrace();
            throw new IOException("Error reading public key file: " + e.getMessage());
        } finally {
            if (publicKeyStream != null) {
                publicKeyStream.close();
            }
        }
    }

    private static PrivateKey getFraudReportPrivateKey(String privateKeyFileNameWithPath) throws Exception {
        PrivateKey pk = null;
        try {
            String key = new String(Files.readAllBytes(Paths.get(privateKeyFileNameWithPath)), Charset.defaultCharset());
            String privateKeyPEM = key.replace("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll(System.lineSeparator(), "").replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            Base64 base64 = new Base64();
            byte[] encoded = base64.decode(privateKeyPEM.getBytes());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            pk = keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return pk;
    }
}
