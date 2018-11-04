package CS4780;

import java.util.Arrays;

//Randy Yin: This will print out raw key 1, raw key 2, plaintext, and cipher text for each row. 
//output for each missing section is correct. 

public class TripleSDES {

	public static void main(String args[])
	{
		//Row 1 Correct 
		byte[] key1 = SDES.stringToByteArray("0000000000");
		byte[] key2 = SDES.stringToByteArray("0000000000");
		byte[] plaintext1 =  SDES.stringToByteArray("0000000000");

		byte[] ciphertext1 = Encrypt(key1, key2, plaintext1);

		System.out.println("Raw Key 1: " + Arrays.toString(key1));
		System.out.println("Raw Key 2: " + Arrays.toString(key2));

		System.out.println("Plaintext: " + Arrays.toString(plaintext1));
		System.out.println("Ciphertext: " + Arrays.toString(ciphertext1));

		
		//Row 2 Correct 
		byte[] key3 = SDES.stringToByteArray("1000101110");
		byte[] key4 = SDES.stringToByteArray("0110101110");
		byte[] plaintext2 =  SDES.stringToByteArray("11010111");

		byte[] ciphertext2 = Encrypt(key3, key4, plaintext2);

		System.out.println("\nRaw Key 1: " + Arrays.toString(key3));
		System.out.println("Raw Key 2: " + Arrays.toString(key4));

		System.out.println("Plaintext: " + Arrays.toString(plaintext2));
		System.out.println("Ciphertext: " + Arrays.toString(ciphertext2));

		
		//Row 3 Correct 
		byte[] key5 = SDES.stringToByteArray("1000101110");
		byte[] key6 = SDES.stringToByteArray("0110101110");
		byte[] plaintext3 =  SDES.stringToByteArray("10101010");

		byte[] ciphertext3 = Encrypt(key5, key6, plaintext3);

		System.out.println("\nRaw Key 1: " + Arrays.toString(key5));
		System.out.println("Raw Key 2: " + Arrays.toString(key6));

		System.out.println("Plaintext: " + Arrays.toString(plaintext3));
		System.out.println("Ciphertext: " + Arrays.toString(ciphertext3));

		
		//Row 4 Correct
		byte[] key7 = SDES.stringToByteArray("1111111111");
		byte[] key8 = SDES.stringToByteArray("1111111111");
		byte[] plaintext4 =  SDES.stringToByteArray("10101010");

		byte[] ciphertext4 = Encrypt(key7, key8, plaintext4);

		System.out.println("\nRaw Key 1: " + Arrays.toString(key7));
		System.out.println("Raw Key 2: " + Arrays.toString(key8));

		System.out.println("Plaintext: " + Arrays.toString(plaintext4));
		System.out.println("Ciphertext: " + Arrays.toString(ciphertext4));

		
		//Row 5 correct 
		byte[] key9 = SDES.stringToByteArray("1000101110");
		byte[] key10 = SDES.stringToByteArray("0110101110");
		byte[] ciphertext5 =  SDES.stringToByteArray("11100110");

		byte[] plaintext5 = Decrypt(key9, key10, ciphertext5);

		System.out.println("\nRaw Key 1: " + Arrays.toString(key9));
		System.out.println("Raw Key 2: " + Arrays.toString(key10));

		System.out.println("Plaintext: " + Arrays.toString(plaintext5));
		System.out.println("Ciphertext: " + Arrays.toString(ciphertext5));

		
		//Row 6 correct
		byte[] key11 = SDES.stringToByteArray("1011101111");
		byte[] key12 = SDES.stringToByteArray("0110101110");
		byte[] ciphertext6 =  SDES.stringToByteArray("01010000");

		byte[] plaintext6 = Decrypt(key11, key12, ciphertext6);

		System.out.println("\nRaw Key 1: " + Arrays.toString(key11));
		System.out.println("Raw Key 2: " + Arrays.toString(key12));

		System.out.println("Plaintext: " + Arrays.toString(plaintext6));
		System.out.println("Ciphertext: " + Arrays.toString(ciphertext6));

		
		//Row 7 Correct 
		byte[] key13 = SDES.stringToByteArray("0000000000");
		byte[] key14 = SDES.stringToByteArray("0000000000");
		byte[] ciphertext7 =  SDES.stringToByteArray("10000000");

		byte[] plaintext7 = Decrypt(key13, key14, ciphertext7);

		System.out.println("\nRaw Key 1: " + Arrays.toString(key13));
		System.out.println("Raw Key 2: " + Arrays.toString(key14));

		System.out.println("Plaintext: " + Arrays.toString(plaintext7));
		System.out.println("Ciphertext: " + Arrays.toString(ciphertext7));
		
		
		//Row 8 correct
		byte[] key15 = SDES.stringToByteArray("1111111111");
		byte[] key16 = SDES.stringToByteArray("1111111111");
		byte[] ciphertext8 =  SDES.stringToByteArray("10010010");

		byte[] plaintext8 = Decrypt(key15, key16, ciphertext8);

		System.out.println("\nRaw Key 1: " + Arrays.toString(key15));
		System.out.println("Raw Key 2: " + Arrays.toString(key16));

		System.out.println("Plaintext: " + Arrays.toString(plaintext8));
		System.out.println("Ciphertext: " + Arrays.toString(ciphertext8));
	}

	public static byte[] Encrypt(byte[] rawkey1, byte[] rawkey2, byte[] plaintext) 
	{
		byte[] encrypted;
		byte[] roundOne = SDES.Encrypt(rawkey1, plaintext);
		byte[] roundTwo = SDES.Decrypt(rawkey2, roundOne);
		encrypted = SDES.Encrypt(rawkey1, roundTwo);

		return encrypted;
	}

	public static byte[] Decrypt(byte[] rawkey1, byte[] rawkey2, byte[] ciphertext)
	{
		byte[] decrypted;
		byte[] roundOne = SDES.Decrypt(rawkey1, ciphertext);
		byte[] roundTwo = SDES.Encrypt(rawkey2, roundOne);
		decrypted = SDES.Decrypt(rawkey1, roundTwo);

		return decrypted;
	}
 
}

