import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;

public class RSA {

	public static void main(String[] args) throws IOException {
	
		if (args[0].equals("key"))
		{
			long a, b;		
			a = getNum(args[1]);
			b = getNum(args[2]);
			createKey(a,b);
		}
		
		else if (args[0].equals("encrypt"))
				encryptDecrypt(args[1], args[2], args[3], 1);
		
		else if(args[0].equals("decrypt"))
				encryptDecrypt(args[1], args[2], args[3], 0);
				
//		createKey(5077,5107); // For manual testing
//		createKey(47,59);  // For manual testing
//		encryptDecrypt("inFile", "keyFile", "outFile.txt", 1); // For manual testing
//		encryptDecrypt("outFile.txt", "keyFile", "outFile2.txt", 0); // For manual testing
	}

	/*
	 * Convert the input string from the command line or from the keyFile into a number.
	 */
	private static long getNum(String num1) {

		int i = 1;
		
		long num = 0;

		for (int j = num1.length()-1; j >= 0; j--)
		{
			num += (int)(num1.charAt(j) - '0') * i;
			i *= 10;
		}
		return num;
	}

	/*
	 * This method is used in both encrypt and decrypt processes, based on choice. 
	 * 		- If choice = 1, then the process is to encrypt with key e,
	 * 		  if choice = 0, the process is to decrypt with key d.
	 */
	private static void encryptDecrypt(String inFile, String keyFile, String outFile, int choice) throws IOException {
		//For decryption, arguments are (String outFile, String keyFile, String inFile, int choice)
		
		long n = 0, e = 0, d = 0;
		
		DataInputStream inF = new DataInputStream(new FileInputStream(inFile));
		
		BufferedReader reader = new BufferedReader(new FileReader(keyFile));
		
		DataOutputStream outF = new DataOutputStream(new FileOutputStream(outFile));
		
		byte[] numEn = new byte[3]; // Block of 3, used to hold bytes from input file in order to encrypt it.
		
		byte[] numDe = new byte[4]; // Block of 4, used to hold bytes from encrypted file in order to decrypt it.
		
		String line = reader.readLine();
		
		int i = 0, k = 0;
		
		//get n, e, d from keyFile
		while (i < line.length())
		{
			if (line.charAt(i) == ' ')
			{
				if (k == 0) // first number: n
					n = getNum(line.substring(k, i));
				else // second number: e
					e = getNum(line.substring(k, i));
				k = i+1;
			}
			i++;		
		}

		d = getNum(line.substring(k, i)); // only the third number remains: d
		
		if (choice == 1)
			EDCrypt(numEn, e, n, inF, outF, choice);
		else
			EDCrypt(numDe, d, n, inF, outF, choice);
	}
	
	/*
	 * Just a breaking-up helper method for the encryptDecrypt method to avoid redundancy.
	 * The cryptNumber is calculated by the RSA algorithm based on e_d.
	 * 		- if e_d is e, it is the encrypted number and will be written into encrypted file.
	 * 		- if e_d is d, it is the decrypted number and will be written into decrypted file.
	 */
	private static void EDCrypt(byte[] num, long e_d, long n, DataInputStream inF, 
																DataOutputStream outF, int choice) throws IOException {	
		int end = inF.read(num);
		
		while (end != -1)
		{
			// Now encrypt or decrypt
			long cryptNumber;		
			
			long concatNum = getConcatNum(num);
			
			long mask = getMask(e_d);
			
			cryptNumber = encryptDecrypt(e_d, mask, concatNum, n);
			
			if (choice == 1) // encrypt
				outF.writeInt((int)cryptNumber);
			else // decrypt
				writeFile(outF, cryptNumber);
			
			//reset num[] to hold new set of data.
			for(int m = 0; m < num.length; m++)
				num[m] = 0;
			end = inF.read(num);
		}	
	}
	
	/*
	 * Form the concatenated number from 3 bytes, read from inFile
	 * 	The number is formed by 
	 * 		- shiftting-left the first byte, 8 bits.
	 * 		- add to the second number
	 * 		- shiftting-left the result, 8 bits
	 * 		- add to the third number.
	 */
	private static long getConcatNum(byte[] num) {
		
		long concatNum = num[0];
		
		for(int j = 1; j < num.length; j++)
		{	
			concatNum = concatNum << 8;
			if(num[j] < 0)
				concatNum += 256 + num[j];
			else
				concatNum += num[j];
		}
		return concatNum;
	}
	
	/*
	 * Calculate the mask to be used in encryptDecrypt method.
	 * The mask, with the left most bit is 1 and all other bits are 0,
	 * must have the same bit-length as e or d.
	 */
	private static long getMask(long e2) {
		
		long temp = e2/2;
		
		long mask = 1;
		
		while(temp != 0)
		{
			mask = mask << 1;
			temp = temp/2;
		}
		return mask;
	}
	
	/*
	 * This method writes the decrypted number back into the file.
	 */
	private static void writeFile(DataOutputStream outF, long num) throws IOException {
		
		byte[] arr = new byte[3]; //arr - the array of bytes that will be written into final file
		
		long mask = 255; // use mask to extract the rightmost byte in decrypted number.
		
		
		//with leftmost byte is in position 0
		for(int i = arr.length-1; i >= 0; i--)
		{
			arr[i] = (byte)(num & mask);
			num = num >> 8;
		}
		
		//scan the 'arr' array to write into file,
		//only write bytes that are not zero.
		for(int i = 0; i < arr.length; i++) {
			if (arr[i] != 0) {
				outF.writeByte(arr[i]);
			}
		}

	}

	/*
	 * Create the public key e and private key d from 2 primes p and q.
	 * 		- First, calculate phi_n and n.
	 * 		- Any first value of e which is the primitive prime of phi_n is selected.
	 * 		- d is calculated by the Extended Euclid algorithm.
	 */
	private static void createKey(long p, long q) {

		long n, e, d = 0;
		
		long phiN;
		
		n = p*q;
		
		phiN = (p-1) * (q-1);
		
		e = 2;
		
		while ((gcd(e,phiN) != 1) && (e < n))
		{
			e++;
			if (gcd(e,phiN) == 1) // e is relative prime of phi_n
				d = extEucl(e,phiN);
		}
		System.out.println(n + " " + e + " " + d);
	}
	
	/*
	 * Implement the extended Eucllid algorithm.
	 * This method is used to calculate d from e and phi_n.
	 */
	private static long extEucl(long e, long phiN) {

			long new_u, new_v, new_s, new_t, new_c, new_d, q;
			
			long old_s, old_t, old_c, old_d;
			
			long adjustNum = phiN;
			
			if (e >= phiN)
			{
				old_s = 0; old_t = 1;
				
				old_c = 1; old_d = 0;
			}
			else
			{
				old_s = 1; old_t = 0;
				
				old_c = 0; old_d = 1;
			}
			while (phiN != 0)
			{
				q = e/phiN;
				
				new_u = phiN; new_v = e - q * new_u;
				
				new_s = old_c; new_t = old_d;
				
				new_c = old_s - q * old_c; 
				
				new_d = old_t - q * old_d;
				
				//update s,t,c,d, e, phi_n for a new iteration.
				old_s = new_s; old_t = new_t;
				
				old_c = new_c; old_d = new_d;
				
				e = new_u; phiN = new_v;
			}

			//if d is negative, add it to phi_n until d is positive.
			if (old_s < 0)
				while (old_s < 0) {
					old_s = old_s + adjustNum;
				}
			return old_s;		
	}
	
	/*
	 * Implement the Modular Simplification Rule
	 * 		- Each bit of e (or d) is checked by using a mask of the same bit-length with 
	 * 		  leftmost bit is 1 and all other bits are 0.
	 * 		- Each bit of e (or d) is checked by and-ing with the mask
	 * 		  If the result is 0, then the bit in e (d) is 0, otherwise, the bit is 1.
	 * 		- Then mask is shifted right 1 bit to be ready for checking the next right bit in 
	 * 	      e (or d).
	 */
	private static long encryptDecrypt(long e2, long mask, long ENum, long n) {
		
		long C = 1;
		
		while (mask != 0)
		{
			long ek = mask & e2;
			if (ek == 0)
				C = (C * C) % n;
			else
				C = (((C * C) % n) * ENum) % n;
			mask = mask >> 1;
		}
		return C;
	}
	
	/*
	 *  calculate the gcd between 2 numbers. 
	 *  This method is used to check the relative prime of 2 numbers (gcd = 1).
	 */
	private static long gcd(long a, long b){
		if (b == 0)
			return a;
		else
			return gcd(b, a % b);
	}

}
