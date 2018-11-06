package CS4780;

public class TripleDES {
	
	//E3DES(p) = EDES(k1,DDES(k2,EDES(k1, p)))
	public static byte[] Encrypt( byte[] rawkey1, byte[] rawkey2, byte[] plaintext ) {
		return SDES.Encrypt(rawkey1, SDES.Decrypt(rawkey2, SDES.Encrypt(rawkey1, plaintext)));
	}
	
	//D3DES(c) = DDES(k1,EDES(k2,DDES(k1, c)))
	public static byte[] Decrypt( byte[] rawkey1, byte[] rawkey2, byte[] ciphertext ) {
		return SDES.Decrypt(rawkey1, SDES.Encrypt(rawkey2, SDES.Decrypt(rawkey1, ciphertext)));
	}
	
	
	public static void main(String[] args) {
		byte[] rawkey1 = {0,0,0,0,0,0,0,0,0,0};
		byte[] rawkey2 = {1,1,1,1,1,1,1,1,1,1};
		byte[] plaintext1 = {0,0,0,0,0,0,0,0};
		
		byte[] rawkey3 = {1,0,0,0,1,0,1,1,1,0};
		byte[] rawkey4 = {0,1,1,0,1,0,1,1,1,0};
		byte[] plaintext2 = {1,1,0,1,0,1,1,1};
		byte[] plaintext3 = {1,0,1,0,1,0,1,0};
		
		byte[] ciphertext1 = {1,1,1,0,0,1,1,0};
		byte[] rawkey6 = {1,0,1,1,1,0,1,1,1,1};
		byte[] ciphertext2 = {0,1,0,1,0,0,0,0};
		byte[] ciphertext3 = {1,0,0,0,0,0,0,0};
		byte[] ciphertext4 = {1,0,0,1,0,0,1,0};
		
		System.out.println("Unknown Ciphertext:");
		System.out.print("Raw Key1: ");
		SDES.printByteArray(rawkey1);
		System.out.print(" Raw Key2: ");
		SDES.printByteArray(rawkey1);
		System.out.print(" Plaintext: ");
		SDES.printByteArray(plaintext1);
		System.out.print(" Ciphertext: ");
		SDES.printByteArray(Encrypt(rawkey1,rawkey1,plaintext1));
		System.out.println("");
		
		System.out.print("Raw Key1: ");
		SDES.printByteArray(rawkey3);
		System.out.print(" Raw Key2: ");
		SDES.printByteArray(rawkey4);
		System.out.print(" Plaintext: ");
		SDES.printByteArray(plaintext2);
		System.out.print(" Ciphertext: ");
		SDES.printByteArray(Encrypt(rawkey3,rawkey4,plaintext2));
		System.out.println("");
		
		System.out.print("Raw Key1: ");
		SDES.printByteArray(rawkey3);
		System.out.print(" Raw Key2: ");
		SDES.printByteArray(rawkey4);
		System.out.print(" Plaintext: ");
		SDES.printByteArray(plaintext3);
		System.out.print(" Ciphertext: ");
		SDES.printByteArray(Encrypt(rawkey3,rawkey4,plaintext3));
		System.out.println("");
		
		System.out.print("Raw Key1: ");
		SDES.printByteArray(rawkey2);
		System.out.print(" Raw Key2: ");
		SDES.printByteArray(rawkey2);
		System.out.print(" Plaintext: ");
		SDES.printByteArray(plaintext3);
		System.out.print(" Ciphertext: ");
		SDES.printByteArray(Encrypt(rawkey2,rawkey2,plaintext3));
		System.out.println("");
		
		
		
		
		System.out.println("Unknown Plaintext:");
		System.out.print("Raw Key1: ");
		SDES.printByteArray(rawkey3);
		System.out.print(" Raw Key2: ");
		SDES.printByteArray(rawkey4);
		System.out.print(" Plaintext: ");
		SDES.printByteArray(Decrypt(rawkey3,rawkey4,ciphertext1));
		System.out.print(" Ciphertext: ");
		SDES.printByteArray(ciphertext1);
		System.out.println("");
		
		System.out.print("Raw Key1: ");
		SDES.printByteArray(rawkey6);
		System.out.print(" Raw Key2: ");
		SDES.printByteArray(rawkey4);
		System.out.print(" Plaintext: ");
		SDES.printByteArray(Decrypt(rawkey6,rawkey4,ciphertext2));
		System.out.print(" Ciphertext: ");
		SDES.printByteArray(ciphertext2);
		System.out.println("");
		
		System.out.print("Raw Key1: ");
		SDES.printByteArray(rawkey1);
		System.out.print(" Raw Key2: ");
		SDES.printByteArray(rawkey1);
		System.out.print(" Plaintext: ");
		SDES.printByteArray(Decrypt(rawkey1,rawkey1,ciphertext3));
		System.out.print(" Ciphertext: ");
		SDES.printByteArray(ciphertext3);
		System.out.println("");
		
		System.out.print("Raw Key1: ");
		SDES.printByteArray(rawkey2);
		System.out.print(" Raw Key2: ");
		SDES.printByteArray(rawkey2);
		System.out.print(" Plaintext: ");
		SDES.printByteArray(Decrypt(rawkey2,rawkey2,ciphertext4));
		System.out.print(" Ciphertext: ");
		SDES.printByteArray(ciphertext4);
		System.out.println("");
		
	}
	
}
