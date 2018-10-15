package CS4780;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

import CS4780.SDES.KeyGenerator;

class SDESTest {

	byte[] rawkey1 = {0,0,0,0,0,0,0,0,0,0};
	byte[] plaintext1 = {1,0,1,0,1,0,1,0};
	byte[] ciphertext1 = {0,0,0,1,0,0,0,1};
	
	byte[] rawkey2 = {1,1,1,0,0,0,1,1,1,0};
	byte[] plaintext2 = {1,0,1,0,1,0,1,0};
	byte[] ciphertext2 = {1,1,0,0,1,0,1,0};
	
	byte[] rawkey3 = {1,1,1,0,0,0,1,1,1,0};
	byte[] plaintext3 = {0,1,0,1,0,1,0,1};
	byte[] ciphertext3 = {0,1,1,1,0,0,0,0};
	
	byte[] rawkey4 = {1,1,1,1,1,1,1,1,1,1};
	byte[] plaintext4 = {1,0,1,0,1,0,1,0};
	byte[] ciphertext4 = {0,0,0,0,0,1,0,0};
	
	@Test
	void testEncrypt() {

		assertArrayEquals(SDES.Encrypt(rawkey1, plaintext1) , ciphertext1 );
		assertArrayEquals(SDES.Encrypt(rawkey2, plaintext2) , ciphertext2 );
		assertArrayEquals(SDES.Encrypt(rawkey3, plaintext3) , ciphertext3 );
		assertArrayEquals(SDES.Encrypt(rawkey4, plaintext4) , ciphertext4 );
	}

	@Test
	void testDecrypt() {
		assertArrayEquals(SDES.Decrypt(rawkey1, ciphertext1), plaintext1);
		assertArrayEquals(SDES.Decrypt(rawkey2, ciphertext2), plaintext2);
		assertArrayEquals(SDES.Decrypt(rawkey3, ciphertext3), plaintext3);
		assertArrayEquals(SDES.Decrypt(rawkey4, ciphertext4), plaintext4);
	}
	
	@Test
	void testPBox() {
		byte[] pbox1 = {3,5,2,7,4,10,1,9,8,6};
		byte[] input1 = {1,0,1,0,0,0,0,0,1,0};
		byte[] output1 = {1,0,0,0,0,0,1,1,0,0};
		assertArrayEquals(SDES.executePbox(pbox1, input1), output1);
		
		byte[] pbox2 = {6,3,7,4,8,5,10,9};
		byte[] input2 = {0,0,0,0,1,1,1,0,0,0};
		byte[] output2 = {1,0,1,0,0,1,0,0};
		assertArrayEquals(SDES.executePbox(pbox2, input2), output2);
		
		byte[] input3 = {0,0,1,0,0,0,0,0,1,1};
		byte[] output3 = {0,1,0,0,0,0,1,1};
		assertArrayEquals(SDES.executePbox(pbox2, input3), output3);
	}
	
	@Test
	void testLeftShift() {
		byte[] input1 =  {1,0,0,0,0,0,1,1,0,0};
		byte[] output1 = {0,0,0,0,1,1,1,0,0,0};
		
		SDES.leftShift(input1);
		assertArrayEquals(input1, output1);
	}
	
	@Test
	void testSwap() {
		byte[] input1 =  {1,0,0,0,0, 0,1,1,0,0};
		byte[] output1 = {0,1,1,0,0, 1,0,0,0,0};
		
		SDES.swap(input1);
		assertArrayEquals(input1, output1);
	}
	
	@Test
	void testSplit() {
		byte[] input1 =  {1,0,0,0,0, 0,1,1,0,0};
		byte[][] output = {{1,0,0,0,0},{0,1,1,0,0}};
		
		byte[][] results = SDES.split(input1);
		
		assertArrayEquals(results[0], output[0]);
		assertArrayEquals(results[1], output[1]);
	}
	
	@Test
	void testCombine() {
		byte[] output =  {1,0,0,0,0, 0,1,1,0,0};
		byte[][] input = {{1,0,0,0,0},{0,1,1,0,0}};
		
		assertArrayEquals(SDES.combine(input), output);
	}
	
	@Test
	void testKeyGenerator() {
		byte[] rawkey = {1,0,1,0,0,0,0,0,1,0};
		byte[] subkey1 = {1,0,1,0,0,1,0,0};
		byte[] subkey2 = {0,1,0,0,0,0,1,1};
		
		
		KeyGenerator test2 = new KeyGenerator(rawkey);
		assertArrayEquals(test2.next(), subkey1);
		assertArrayEquals(test2.next(), subkey2);
		
	}

}
