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
	
	public static byte[] executePbox(byte[] pBox, byte[] input) throws IllegalArgumentException {
		byte[] output = new byte[pBox.length];
		
		for(int i = 0; i < pBox.length; i++) {
			int modifiedLength = input.length + HUMAN_READABLE_OFFSET;
			if(pBox[i] < modifiedLength) {
				output[i] = input[pBox[i] - HUMAN_READABLE_OFFSET];
			} else {
				throw new IllegalArgumentException("Invalid p-Box.");
			}
		}
		
		return output;
		
	}
	
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
	
	public static void swap(byte[] input) {
		byte[] temp = new byte[input.length/2];
		System.arraycopy(input, 0, temp, 0, temp.length);
		System.arraycopy(input, temp.length, input, 0, temp.length);
		System.arraycopy(temp, 0, input, temp.length, temp.length);
	}
	
	public static byte[] xor(byte[] left, byte[] right) {
		if(left.length != right.length) 
			throw new IllegalArgumentException("Left and Right do not have the same length!");
		
		byte[] results = new byte[left.length];
		
		for(int i = 0; i < results.length; i++) {
			results[i] = (byte) (left[i] ^ right[i]);
		}
		
		return results;
		
	}
	
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
	
	public static byte[][] split(byte[] input) {
		byte[][] results = new byte[2][input.length/2];
		System.arraycopy(input, 0, results[LEFT], 0, results[LEFT].length);
		System.arraycopy(input, input.length/2, results[RIGHT], 0, results[RIGHT].length);
		return results;
	}
	
	public static byte[] combine(byte[][] input) {
		byte[] results = new byte[2*input[LEFT].length];
		System.arraycopy(input[LEFT], 0, results, 0, input[LEFT].length);
		System.arraycopy(input[RIGHT], 0, results, input[RIGHT].length, input[RIGHT].length);
		return results;
	}
	
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
