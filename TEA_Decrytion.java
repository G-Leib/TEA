import java.util.Scanner;

/* Single pair of rounds TEA decryption */

class DecryptTEA {
    public static void main(String [] args) {
        Scanner scan = new Scanner(System.in);
        
        long delta1 = 0x11111111;
        long delta2 = 0x22222222;

        // 128 bit key with default test keys
        long[] key = new long[]{0x90001C55, 0x1234ABCD, 0xFEDCBA98, 0xE2468AC0};

        // Left and Right half of plain text initialized to 0
        long[] L = new long[]{0x0, 0x0, 0x0};
        long[] R = new long[]{0x0, 0x0, 0x0};

        // Get keys from user
        System.out.println("Enter four 32-bit encryption keys in hex format");
        for (int i = 0; i < 4; i++) {
            System.out.print("Key " + i + ": ");
            String k = scan.nextLine();
            // If k is empty then default keys will be used
            if (!k.isEmpty()) {
                if (k.contains("0x")) {
                    k = k.replace("0x", "");
                }
                key[i] = Long.parseLong(k, 16);
            }
        }

        // Get plaintext from user
        System.out.println("Enter 64 bit ciphertext in hex format");
        String C = scan.nextLine();
        if (C.contains("0x")) {
            C = C.replace("0x", "");
        } else if (C.isEmpty()) {
            // Default test string if no input given
            C = "B72599B2CF8E5A4C";
        }
        L[2] = Long.parseLong(C.substring(0,8), 16);
        R[2] = Long.parseLong(C.substring(8,16), 16);

        R[1] = L[2];
        L[1] = DeTEA(R[2], L[2], key[2], key[3], delta2);

        R[0] = L[1];
        L[0] = DeTEA(R[1], L[1], key[0], key[1], delta1);
        
        String P = String.format("%08X", L[0]) + String.format("%08X", R[0]);
        
        System.out.println("\nCiphertext: " + C + '\n');
        System.out.println("L[2]: " + String.format("%08X", L[2]) + "\tR[2]: " + String.format("%08X", R[2]));
        System.out.println("L[1]: " + String.format("%08X", L[1]) + "\tR[1]: " + String.format("%08X", R[1]));
        System.out.println("L[0]: " + String.format("%08X", L[0]) + "\tR[0]: " + String.format("%08X", R[0]));
        System.out.println("\nPaintext: " + P + '\n');



        scan.close();
    }

    public static long DeTEA (long x, long l, long km, long kn, long delta) {

        long[] mod = {((l << 4) + km), ((l >> 5) + kn), (l + delta)};
        
        for (int i = 0; i < 3; i++){
            mod[i] = removeCarry(mod[i]);
        }
        
        long r =  x - (mod[0] ^ mod[1] ^ mod[2]);

        r = addBorrow(r);

        return r;
    }

    public static long addBorrow (long num) {

        if (num < 0) {
            num+=0xffffffff;
            num+=1;
        }

        return num;
    }

    public static long removeCarry (long num) {
        // Use only last 32 bits (eliminating the carry)
        String str = String.format("%08X", num);
        if (str.length() > 8) {
            str = str.substring(str.length() - 8);
            num = Long.parseLong(str, 16);
        }

        return num;
    }

}