package CS4780;

public class Cracking {

	private static final String testCase1 = "CRYPTOGRAPHY";
	private static final byte[] keyCase1 = {0,1,1,1,0,0,1,1,0,1};
	private static final int TEXT_BIT_LENGTH = 8;
	private static final int KEY_LENGTH = 10;
	private static final int MAX_KEY = 1024;
	
	public static void main(String args[]) {
		question1();
		
		question2();
		
		question3();
	}
	
	private static void question3() {
		//copy+pasted in to remove any errors from reading the file
		String msg2txt = "00011111100111111110011111101100111000000011001011110010101010110001011101001101000000110011010111111110000000001010111111000001010010111001111001010101100000110111100011111101011100100100010101000011001100101000000101111011000010011010111100010001001000100001111100100000001000000001101101000000001010111010000001000010011100101111001101111011001001010001100010100000";
		
		//build as many 8 byte arrays we need to hold the whole message, so we can decrypt them one at a time
		byte[][] cipherBits = new byte[msg2txt.length() / TEXT_BIT_LENGTH][TEXT_BIT_LENGTH];
		
		for(int i = 0; i < msg2txt.length(); i++) {
			if(msg2txt.charAt(i) == '1') 
				cipherBits[i/TEXT_BIT_LENGTH][i%TEXT_BIT_LENGTH] = 1;
			else if(msg2txt.charAt(i) == '0') 
				cipherBits[i/TEXT_BIT_LENGTH][i%TEXT_BIT_LENGTH] = 0;
			else
				throw new RuntimeException("Invalid character in file: " + msg2txt.charAt(i));
		}

		System.out.println("");
		System.out.println("Cracking msg2.txt: (key1) (key2) (CASCII Encoding of decrypted bits)");

		//start decrypting
		for(int testKey1 = 0; testKey1 < MAX_KEY; testKey1++) {
			//convert an int to byte array we can use to decrypt
			byte[] byteKey1 = intToKeyArray(testKey1);
			for(int testKey2 = 0; testKey2 < MAX_KEY; testKey2++) {
				//convert an int to byte array we can use to decrypt
				byte[] byteKey2 = intToKeyArray(testKey2);
				byte[] plaintextBytes = new byte[msg2txt.length()];
				
				//decrypt
				for(int i = 0; i < cipherBits.length; i++) {
					System.arraycopy(TripleDES.Decrypt(byteKey1, byteKey2, cipherBits[i]), 0, plaintextBytes, TEXT_BIT_LENGTH * i, TEXT_BIT_LENGTH);;
				}
				
				//convert
				String plainText = CASCII.toString(plaintextBytes);
				
				//check if the average word length is close to 4.79 letters per word     
				if(isMaybeSentence(plainText, 1.1)) {
					SDES.printByteArray(byteKey1);
					System.out.print(" ");
					SDES.printByteArray(byteKey2);
					System.out.println(" " + plainText);
				}
			}
		}
	}

	private static void question2() {
		//copy+pasted in to remove any errors from reading the file
		String msg1txt = "1011011001111001001011101111110000111110100000000001110111010001111011111101101100010011000000101101011010101000101111100011101011010111100011101001010111101100101110000010010101110001110111011111010101010100001100011000011010101111011111010011110111001001011100101101001000011011111011000010010001011101100011011110000000110010111111010000011100011111111000010111010100001100001010011001010101010000110101101111111010010110001001000001111000000011110000011110110010010101010100001000011010000100011010101100000010111000000010101110100001000111010010010101110111010010111100011111010101111011101111000101001010001101100101100111001110111001100101100011111001100000110100001001100010000100011100000000001001010011101011100101000111011100010001111101011111100000010111110101010000000100110110111111000000111110111010100110000010110000111010001111000101011111101011101101010010100010111100011100000001010101110111111101101100101010011100111011110101011011";
		
		//build as many 8 byte arrays we need to hold the whole message, so we can decrypt them one at a time
		byte[][] cipherBits = new byte[msg1txt.length() / TEXT_BIT_LENGTH][TEXT_BIT_LENGTH];
		
		for(int i = 0; i < msg1txt.length(); i++) {
			if(msg1txt.charAt(i) == '1') 
				cipherBits[i/TEXT_BIT_LENGTH][i%TEXT_BIT_LENGTH] = 1;
			else if(msg1txt.charAt(i) == '0') 
				cipherBits[i/TEXT_BIT_LENGTH][i%TEXT_BIT_LENGTH] = 0;
			else
				throw new RuntimeException("Invalid character in file: " + msg1txt.charAt(i));
		}
		
		System.out.println("");
		System.out.println("Cracking msg1.txt: (key) (CASCII Encoding of decrypted bits)");
		
		//start decrypting
		for(int testKey = 0; testKey < MAX_KEY; testKey++) {
			//convert an int into a byte array we can use to decrypt
			byte[] byteKey = intToKeyArray(testKey);
			byte[] plaintextBytes = new byte[msg1txt.length()];
			
			//decrypt
			for(int i = 0; i < cipherBits.length; i++) {
				System.arraycopy(SDES.Decrypt(byteKey, cipherBits[i]), 0, plaintextBytes, TEXT_BIT_LENGTH * i, TEXT_BIT_LENGTH);;
			}
			
			//convert
			String plainText = CASCII.toString(plaintextBytes);
			if(isMaybeSentence(plainText, 1.5)) {
				SDES.printByteArray(byteKey);
				System.out.println(" " + plainText);
			}
		}

	}
	
	//converts an int into an new byte array we can use for decryption
	private static byte[] intToKeyArray(int key) {
		byte[] result = new byte[KEY_LENGTH];
		
		if(key > MAX_KEY)
			throw new IllegalArgumentException("Key too big!");
		
		for(int i = 0; i < KEY_LENGTH; i++) {
			//start at the highest bit and work down to match how we are storing bits into byte arrays
			int currentBit = 1<<(KEY_LENGTH - (i + 1));
			if(key >= currentBit) { //we have an upper bit we need to remove from key
				result[i] = 1;
				key ^= currentBit;
			} else
				result[i] = 0;
		}
		
		return result;
	}

	//print out all of the arrays
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
	
	//returns true if the average number of letters per word is less than or equal to 4.79 * tolerance
	//4.79 is the average found via google "average letters per word"
	private static boolean isMaybeSentence(String text, double tolerance) {
		
		double averageLettersPerWord = 4.79;
		
		String[] words = text.split("\\s+");
		
		return ((((double) text.length() - words.length) / words.length) <= averageLettersPerWord * tolerance);

	}
}
