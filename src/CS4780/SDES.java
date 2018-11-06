package CS4780;

import java.util.Stack;

public class SDES {

	private static final int HUMAN_READABLE_OFFSET = 1;
	private static final byte[] P10 = {3,5,2,7,4,10,1,9,8,6};
	private static final byte[] P8 = {6,3,7,4,8,5,10,9};
	private static final byte[] IP = {2,6,3,1,4,8,5,7};
	private static final byte[] FP = {4,1,3,5,7,2,8,6};
	private static final byte[] EP = {4,1,2,3,2,3,4,1};
	private static final byte[] P4 = {2,4,3,1};
	private static final int LEFT = 0;
	private static final int RIGHT = 1;
	
	//S0[byte 0][byte 1][byte 2][byte 3] returns an array corresponding to the S0 table with "0123" as input
	//this allows instant lookup of the result of the S-box
	protected static final byte[][][][][] S0 = {
												{
													{
														{
															//0000 0001
															{0,1}, {1,1}
														},
														
														{
															//0010 0011
															{0,0}, {1,0}
														}
													},
													
													{
														{
															//0100 0101
															{1,1}, {0,1}
														},
														
														{
															//0110 0111
															{1,0}, {0,0}
														}
													}
												},
												
												{
													{
														{
															//1000 1001
															{0,0}, {1,1}
														},
														
														{
															//1010 1011
															{1,0}, {0,1}
														}
													},
													
													{
														{
															//1100 1101
															{0,1}, {1,1}
														},
														
														{
															//1110 1111
															{1,1}, {1,0}
														}
													}
												}
											};
	
	//S1[byte 0][byte 1][byte 2][byte 3] returns an array corresponding to the S1 table with "0123" as input
	//this allows instant lookup of the result of the S-box
	protected static final byte[][][][][] S1 = {
												{
													{
														{
															//0000 0001
															{0,0}, {1,0}
														},
														
														{
															//0010 0011
															{0,1}, {0,0}
														}
													},
													
													{
														{
															//0100 0101
															{1,0}, {0,1}
														},
														
														{
															//0110 0111
															{1,1}, {1,1}
														}
													}
												},
												
												{
													{
														{
															//1000 1001
															{1,1}, {1,0}
														},
														
														{
															//1010 1011
															{0,0}, {0,1}
														}
													},
													
													{
														{
															//1100 1101
															{0,1}, {0,0}
														},
														
														{
															//1110 1111
															{0,0}, {1,1}
														}
													}
												}
											};

	
	public static void main(String[] args) {
		byte[] rawkey1 = {0,0,0,0,0,0,0,0,0,0};
		byte[] plaintext1 = {0,0,0,0,0,0,0,0};
		
		byte[] rawkey2 = {1,1,1,1,1,1,1,1,1,1};
		byte[] plaintext2 = {1,1,1,1,1,1,1,1};
		
		byte[] rawkey3 = {0,0,0,0,0,1,1,1,1,1};
		
		byte[] rawkey5 = {1,0,0,0,1,0,1,1,1,0};
		byte[] cipertext5 = {0,0,0,1,1,1,0,0};
		byte[] cipertext6 = {1,1,0,0,0,0,1,0};
		
		byte[] rawkey7 = {0,0,1,0,0,1,1,1,1,1};
		byte[] cipertext7 = {1,0,0,1,1,1,0,1};
		byte[] cipertext8 = {1,0,0,1,0,0,0,0};
		
		
		System.out.println("Unknown Ciphertext:");
		System.out.print("Raw Key: ");
		printByteArray(rawkey1);
		System.out.print(" Plaintext: ");
		printByteArray(plaintext1);
		System.out.print(" Ciphertext: ");
		printByteArray(Encrypt(rawkey1,plaintext1));
		System.out.println("");
		
		System.out.print("Raw Key: ");
		printByteArray(rawkey2);
		System.out.print(" Plaintext: ");
		printByteArray(plaintext2);
		System.out.print(" Ciphertext: ");
		printByteArray(Encrypt(rawkey2,plaintext2));
		System.out.println("");
		
		System.out.print("Raw Key: ");
		printByteArray(rawkey3);
		System.out.print(" Plaintext: ");
		printByteArray(plaintext1);
		System.out.print(" Ciphertext: ");
		printByteArray(Encrypt(rawkey3,plaintext1));
		System.out.println("");
		
		System.out.print("Raw Key: ");
		printByteArray(rawkey3);
		System.out.print(" Plaintext: ");
		printByteArray(plaintext2);
		System.out.print(" Ciphertext: ");
		printByteArray(Encrypt(rawkey3,plaintext2));
		System.out.println("");
		
		System.out.println("Unknown Plaintext:");
		System.out.print("Raw Key: ");
		printByteArray(rawkey5);
		System.out.print(" Plaintext: ");
		printByteArray(Decrypt(rawkey5,cipertext5));
		System.out.print(" Ciphertext: ");
		printByteArray(cipertext5);
		System.out.println("");
		
		System.out.print("Raw Key: ");
		printByteArray(rawkey5);
		System.out.print(" Plaintext: ");
		printByteArray(Decrypt(rawkey5,cipertext6));
		System.out.print(" Ciphertext: ");
		printByteArray(cipertext6);
		System.out.println("");
		
		System.out.print("Raw Key: ");
		printByteArray(rawkey7);
		System.out.print(" Plaintext: ");
		printByteArray(Decrypt(rawkey7,cipertext7));
		System.out.print(" Ciphertext: ");
		printByteArray(cipertext7);
		System.out.println("");
		
		System.out.print("Raw Key: ");
		printByteArray(rawkey7);
		System.out.print(" Plaintext: ");
		printByteArray(Decrypt(rawkey7,cipertext8));
		System.out.print(" Ciphertext: ");
		printByteArray(cipertext8);
		System.out.println("");
	}
	
	public static void printByteArray(byte[] printMe) {
		if(printMe[0] == (byte)0) 
			System.out.print("{0");
		else
			System.out.print("{1");
		
		for(int i = 1; i < printMe.length; i++) {
			if(printMe[i] == (byte)0)
				System.out.print(",0");
			else
				System.out.print(",1");
			
		}
		
		System.out.print("}");
	}
			
	
	public static byte[] Encrypt(byte[] rawkey, byte[] plaintext) {
		KeyGenerator myKeyGenerator = new KeyGenerator(rawkey);
		
		//initial permutation
		byte[] workingText = executePbox(IP, plaintext);
		
		//round 1
		workingText = fk(workingText, myKeyGenerator.next());
		
		swap(workingText);
		
		//round 2
		workingText = fk(workingText, myKeyGenerator.next());
		
		//final permutation
		return executePbox(FP, workingText);
	}
	
	public static byte[] Decrypt(byte[] rawkey, byte[] ciphertext) {
		KeyGenerator myKeyGenerator = new KeyGenerator(rawkey);
		
		Stack<byte[]> keys = new Stack<>();
		keys.push(myKeyGenerator.next());
		keys.push(myKeyGenerator.next());
		
		//initial permutation
		byte[] workingText = executePbox(IP, ciphertext);
		
		//round 1
		workingText = fk(workingText, keys.pop());
		
		swap(workingText);
		
		//round 2
		workingText = fk(workingText,keys.pop());
		
		//final permutation
		return executePbox(FP, workingText);
	}
	
	//Generic pbox executor, send in the pBox and the input and it will generate the output based on the pBox
	public static byte[] executePbox(byte[] pBox, byte[] input) throws IllegalArgumentException {
		//output is based on length of the pBox (to shrink or expand the input)
		byte[] output = new byte[pBox.length];
		//pBox written are assuming the first index is 1 not 0
		int modifiedLength = input.length + HUMAN_READABLE_OFFSET;

		for(int i = 0; i < pBox.length; i++) {
			if(pBox[i] < modifiedLength) {
				output[i] = input[pBox[i] - HUMAN_READABLE_OFFSET];
			} else {
				//pBox is asking for an index not in the input
				throw new IllegalArgumentException("Invalid p-Box.");
			}
		}
		
		return output;
		
	}
	
	//Left "shift" (rotate) the byte array
	//Does this "inplace" aka to the input directly by following the pointer
	public static void leftShift(byte[] input) {
		byte LeftLeftBit = input[0];
		byte RightLeftBit = input[input.length / 2];
		
		int i = 0;
		for(; i < input.length / 2 - 1; i++) {
			input[i] = input[i+1];
		}
		input[i] = LeftLeftBit;
		for(i++; i < input.length - 1; i++) {
			input[i] = input[i+1];
		}
		input[i] = RightLeftBit;

	}
	
	//Swaps the first half of the byte array with the second half
	//Does this "inplace" aka to the input directly by following the pointer
	public static void swap(byte[] input) {
		byte[] temp = new byte[input.length/2];
		System.arraycopy(input, 0, temp, 0, temp.length);
		System.arraycopy(input, temp.length, input, 0, temp.length);
		System.arraycopy(temp, 0, input, temp.length, temp.length);
	}
	
	//returns a new byte array of left xor right
	public static byte[] xor(byte[] left, byte[] right) {
		if(left.length != right.length) 
			throw new IllegalArgumentException("Left and Right do not have the same length!");
		
		byte[] results = new byte[left.length];
		
		for(int i = 0; i < results.length; i++) {
			results[i] = (byte) (left[i] ^ right[i]);
		}
		
		return results;
		
	}
	
	//returns a new byte array of the result of fk on input with the given roundkey
	public static byte[] fk(byte[] input, byte[] roundKey) {
		byte[][] results = new byte[2][input.length/2];
		
		byte[][] splitInput = split(input);
		
		System.arraycopy(splitInput[RIGHT], 0, results[RIGHT], 0, splitInput[RIGHT].length);
		
		byte[] afterKeyXor = xor(executePbox(EP, splitInput[RIGHT]), roundKey);
		
		byte[][] afterSplit = split(afterKeyXor);
		
		byte[] afterXor = xor(executePbox(P4,combine(S0[afterSplit[LEFT][0]][afterSplit[LEFT][1]][afterSplit[LEFT][2]][afterSplit[LEFT][3]],
				S1[afterSplit[RIGHT][0]][afterSplit[RIGHT][1]][afterSplit[RIGHT][2]][afterSplit[RIGHT][3]])), splitInput[LEFT]);
		
		System.arraycopy(afterXor, 0, results[LEFT], 0, afterXor.length);
		
		return combine(results);
	}
	
	//split the input array into two sub arrays (right down the middle)
	//results[0] = left array; results[1] = right array
	public static byte[][] split(byte[] input) {
		byte[][] results = new byte[2][input.length/2];
		System.arraycopy(input, 0, results[LEFT], 0, results[LEFT].length);
		System.arraycopy(input, input.length/2, results[RIGHT], 0, results[RIGHT].length);
		return results;
	}
	
	//combine two subarrays created with split back together
	//input[0] = left, input[1] = right
	//assumes left and right are the same length
	public static byte[] combine(byte[][] input) {
		byte[] results = new byte[2*input[LEFT].length];
		System.arraycopy(input[LEFT], 0, results, 0, input[LEFT].length);
		System.arraycopy(input[RIGHT], 0, results, input[RIGHT].length, input[RIGHT].length);
		return results;
	}
	
	//similar to above but without the restriction that left and right are in an array next to each other
	public static byte[] combine(byte[] left, byte[] right) {
		byte[] results = new byte[left.length + right.length];
		System.arraycopy(left, 0, results, 0, left.length);
		System.arraycopy(right, 0, results, left.length, right.length);
		return results;
	}
	
	//static class because doesn't need to modify outer class
	public static class KeyGenerator {
		byte[] myCurrentKeyValue;
		int subKeyCount;
		private final int[] shiftLookupTable = {1,2};
		
		public KeyGenerator(byte[] rawkey) {
			myCurrentKeyValue = executePbox(P10, rawkey);
			subKeyCount = 0;
		}
		
		public byte[] next() {
			for(int i = 0; i < shiftLookupTable[subKeyCount]; i++)
				leftShift(myCurrentKeyValue);
			
			subKeyCount++;
			return executePbox(P8,myCurrentKeyValue);
		}
	}
}
