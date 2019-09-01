import static java.lang.Integer.parseInt;

import java.util.Scanner;

/* Single pair of rounds TEA encryption */

class EncryptTEA {
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
        System.out.println("Enter 64 bit plaintext in hex format");
        String p = scan.nextLine();
        if (p.contains("0x")) {
            p = p.replace("0x", "");
        } else if (p.isEmpty()) {
            // Default test string if no input given
            p = "A00000098000006B";
        }
        L[0] = Long.parseLong(p.substring(0,8), 16);
        R[0] = Long.parseLong(p.substring(8,16), 16);

        L[1] = R[0];
        R[1] = EncTEA(L[0], R[0], key[0], key[1], delta1);

        L[2] = R[1];
        R[2] = EncTEA(L[1], R[1], key[2], key[3], delta2);

        
        String C = String.format("%08X", L[2]) + String.format("%08X", R[2]);
       
        System.out.println("\nPlaintext: " + p + '\n');
        System.out.println("L[0]: " + String.format("%08X", L[0]) + "\tR[0]: " + String.format("%08X", R[0]));
        System.out.println("L[1]: " + String.format("%08X", L[1]) + "\tR[1]: " + String.format("%08X", R[1]));
        System.out.println("L[2]: " + String.format("%08X", L[2]) + "\tR[2]: " + String.format("%08X", R[2]));
        System.out.println("\nCiphertext: " + C + '\n');



        scan.close();
    }

    public static long EncTEA (long l, long x, long km, long kn, long delta) {
        
        long[] mod = {((x << 4) + km), ((x >> 5) + kn), (x + delta)};

        for (int i = 0; i < 3; i++){
            mod[i] = removeCarry(mod[i]);
        }

        long r = l + (mod[0] ^ mod[1] ^ mod[2]);
        r = removeCarry(r);

        return r;
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