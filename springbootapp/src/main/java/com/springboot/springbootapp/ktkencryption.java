package com.springboot.springbootapp;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
public class ktkencryption {
	@GetMapping("/getname")
//	public static String getName() {
//		
//		return "my name is rps";
//		
//	}
	
	 /*   @PostMapping("/encrypt")
	    public String encrypt(@RequestBody String plainJsonRequest) {
	        try {
	            // Replace with your actual public key file path
	            String publicKeyPath = "E:\\abc\\Key.pem";
	            return encryption.encryptFraudReportJsonRequest(plainJsonRequest, publicKeyPath);
	        } catch (Exception e) {
	            e.printStackTrace();
	            return "Error encrypting the request.";
	        }
	    }

	    @PostMapping("/decrypt")
	    public String decrypt(@RequestBody String encryptedResponse) {
	        try {
	            // Replace with your actual private key file path
	            String privateKeyPath = "/path/to/private_key.pem";
	            return encryption.decryptFraudReportJsonResponse(encryptedResponse, privateKeyPath);
	        } catch (Exception e) {
	            e.printStackTrace();
	            return "Error decrypting the response.";
	        }
	    }*/
	
	
	@PostMapping("/encrypt")
	public ApiResponse encrypt(@RequestBody model user) {
	    try {
	        String publicKeyFilePath = "E:\\abc\\Key.pem";
	        String plainJsonRequest = convertObjectToJson(user);
	        
	        if (plainJsonRequest == null) {
	            return new ApiResponse("error", "Failed to convert object to JSON", null);
	        }

	        String encryptedJson = encryption.encryptFraudReportJsonRequest(plainJsonRequest, publicKeyFilePath);
	        return new ApiResponse("success", "successful", encryptedJson);
	    } catch (Exception e) {
	        e.printStackTrace();
	        return new ApiResponse("error", "Failed to encrypt", null);
	    }
	}

	private String convertObjectToJson(Object object) {
	    ObjectMapper objectMapper = new ObjectMapper();
	    try {
	        return objectMapper.writeValueAsString(object);
	    } catch (JsonProcessingException e) {
	        e.printStackTrace();
	        return null;
	    }
	}

	

}

	