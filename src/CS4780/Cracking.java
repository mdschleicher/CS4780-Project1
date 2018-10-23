package CS4780;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

public class Cracking {

	private static final String testCase1 = "CRYPTOGRAPHY";
	private static final byte[] keyCase1 = {0,1,1,1,0,0,1,1,0,1};
	private static final int TEXT_BIT_LENGTH = 8;
	private static final int KEY_LENGTH = 10;
	private static final int MAX_KEY = 1024;
	
	public static void main(String args[]) {
		question1();
		
		question2();
		
		//question3();
		
	}
	
	private static void question3() {
		String file = "msg1.txt";
		String currentLine = null;
		try {
			BufferedReader reader = new BufferedReader(new FileReader(file));
			currentLine = reader.readLine();
		    reader.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		byte[][] cipherBits = new byte[currentLine.length() / TEXT_BIT_LENGTH][TEXT_BIT_LENGTH];
		
		for(int i = 0; i < currentLine.length(); i++) {
			if(currentLine.charAt(i) == '1') 
				cipherBits[i/TEXT_BIT_LENGTH][i%TEXT_BIT_LENGTH] = 1;
			else if(currentLine.charAt(i) == '0') 
				cipherBits[i/TEXT_BIT_LENGTH][i%TEXT_BIT_LENGTH] = 0;
			else
				throw new RuntimeException("Invalid character in file: " + currentLine.charAt(i));
		}
		
		BufferedWriter writer = null;
		try {
			writer = new BufferedWriter(new FileWriter("plaintext2.txt"));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		for(int testKey1 = 0; testKey1 < MAX_KEY; testKey1++) {
			byte[] byteKey1 = intToKeyArray(testKey1);
			for(int testKey2 = 0; testKey2 < MAX_KEY; testKey2++) {
				byte[] byteKey2 = intToKeyArray(testKey2);
				byte[] plaintextBytes = new byte[currentLine.length()];
				
				//decrypt
				for(int i = 0; i < cipherBits.length; i++) {
					System.arraycopy(TripleDES.Decrypt(byteKey1, byteKey2, cipherBits[i]), 0, plaintextBytes, TEXT_BIT_LENGTH * i, TEXT_BIT_LENGTH);;
				}
				
				//convert
				String plainText = CASCII.toString(plaintextBytes);
				
				
				
				
				    try {
						writer.write(testKey1 + " " + testKey2 + " " + plainText);
						writer.newLine();
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				     
			    
				/*SDES.printByteArray(byteKey1);
				System.out.print(" ");
				SDES.printByteArray(byteKey2);
				System.out.println(" " + plainText);*/
			}
			System.out.println("Done with first key: " + testKey1);
		}
	    try {
			writer.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	private static void question2() {
		String file = "msg1.txt";
		String currentLine = null;
		try {
			BufferedReader reader = new BufferedReader(new FileReader(file));
			currentLine = reader.readLine();
		    reader.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		byte[][] cipherBits = new byte[currentLine.length() / TEXT_BIT_LENGTH][TEXT_BIT_LENGTH];
		
		for(int i = 0; i < currentLine.length(); i++) {
			if(currentLine.charAt(i) == '1') 
				cipherBits[i/TEXT_BIT_LENGTH][i%TEXT_BIT_LENGTH] = 1;
			else if(currentLine.charAt(i) == '0') 
				cipherBits[i/TEXT_BIT_LENGTH][i%TEXT_BIT_LENGTH] = 0;
			else
				throw new RuntimeException("Invalid character in file: " + currentLine.charAt(i));
		}
		
		System.out.println("Cracking msg1.txt: (key) (CASCII Encoding of decrypted bits)");
		for(int testKey = 0; testKey < MAX_KEY; testKey++) {
			byte[] byteKey = intToKeyArray(testKey);
			byte[] plaintextBytes = new byte[currentLine.length()];
			
			//decrypt
			for(int i = 0; i < cipherBits.length; i++) {
				System.arraycopy(SDES.Decrypt(byteKey, cipherBits[i]), 0, plaintextBytes, TEXT_BIT_LENGTH * i, TEXT_BIT_LENGTH);;
			}
			
			//convert
			String plainText = CASCII.toString(plaintextBytes);
			
			SDES.printByteArray(byteKey);
			System.out.println(" " + plainText);
		}

	}
	
	private static byte[] intToKeyArray(int key) {
		byte[] result = new byte[KEY_LENGTH];
		
		if(key > MAX_KEY)
			throw new IllegalArgumentException("Key too big!");
		
		for(int i = 0; i < KEY_LENGTH; i++) {
			int currentBit = 1<<(KEY_LENGTH - (i + 1));
			if(key >= currentBit) { //we have an upper bit we need to remove from key
				result[i] = 1;
				key ^= currentBit;
			} else
				result[i] = 0;
		}
		
		return result;
	}

	public static void printArrayByteArrays(byte[][] printAllofMe ) {
		for(int i = 0; i < printAllofMe.length; i++) {
			SDES.printByteArray(printAllofMe[i]);
			System.out.print(" ");
		}
	}
	
	private static void question1() {
		byte[] test1 = CASCII.Convert(testCase1);
		
		int numberOfChunks = test1.length / TEXT_BIT_LENGTH;
		byte[][] chunks = new byte[numberOfChunks][TEXT_BIT_LENGTH];
		byte[][] results = new byte[numberOfChunks][TEXT_BIT_LENGTH];
		
		for(int i = 0; i < numberOfChunks; i++) {
			System.arraycopy(test1, i*TEXT_BIT_LENGTH, chunks[i], 0, TEXT_BIT_LENGTH);
			byte[] currentResults = SDES.Encrypt(keyCase1, chunks[i]);
			System.arraycopy(currentResults, 0, results[i], 0, TEXT_BIT_LENGTH);
		}
		
		System.out.println("CASCII: " + testCase1);
		System.out.println("CASCII Binary: ");
		SDES.printByteArray(test1);
		System.out.println("");
		System.out.println("PlainText Arrays: ");
		printArrayByteArrays(chunks);
		System.out.println("");
		System.out.println("CipherText Arrays: ");
		printArrayByteArrays(results);
		System.out.println("");
	}
}
