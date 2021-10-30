import java.math.BigInteger;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.List;
import java.util.Scanner;

class TheRing {

    public static void main(String[] args) {

        Boolean shouldExitProgram = false;
        
        while (!shouldExitProgram) {
            
            int selectedOption = showMenu();
            
            Scanner s = new Scanner(System.in);
            
            switch (selectedOption) {
                
                // Signature module
                case 0:
                    
                    runSignature();
                    break;
                
                // Verification module
                case 1:
                    
                    runVerification();
                    break;
                
                // Exit program
                case 2:
                    shouldExitProgram = true;
                    break;
            }
            
            if (selectedOption != 2) {
                System.out.println();
                System.out.print("Press any key to return to the main menu.");
                s.nextLine();
            } else {
                System.out.println();
            }
            
        }
        
        
    }
    
    private static int showMenu() {
        
        Boolean shouldExitMenu = false;
        
        while (!shouldExitMenu) {
            Scanner s = new Scanner(System.in);
            clearScreen();
            printHeader();
            System.out.println("Choose an option to continue: ");
            System.out.println();
            System.out.println("  s: Sign a message");
            System.out.println("  v: Verify a signature");
            System.out.println("  x: Exit");
            System.out.println();
            System.out.print("Your option: ");
            String o = s.nextLine();
            if (o.toLowerCase().startsWith("s")) {
                shouldExitMenu = true;
                return 0;
            } else if (o.toLowerCase().startsWith("v")) {
                shouldExitMenu = true;
                return 1;
            } else if (o.toLowerCase().startsWith("x")) {
                shouldExitMenu = true;
                return 2;
            } else {
                shouldExitMenu = false;
            }
        }
        
        return 2;
        
    }

    private static void printHeader() {
        System.out.println();
        System.out.println("--------- The Ring Signature ---------");
        System.out.println();
    }
    
    private static void clearScreen() {
        System.out.print("\033[H\033[2J");
        System.out.flush();
    }

    private static void runSignature() {
        
        Scanner s = new Scanner(System.in);
        String[] pkeyLines = open("publickey.txt").split(System.lineSeparator());
        String[] messageLines = open("message.txt").split(System.lineSeparator());
        BigInteger e1 = BigInteger.ZERO;
        BigInteger n1 = BigInteger.ZERO;
        BigInteger e2 = BigInteger.ZERO;
        BigInteger n2 = BigInteger.ZERO;
        String message = "";

        // Get public key lines
        e1 = new BigInteger(pkeyLines[0], 10);
        n1 = new BigInteger(pkeyLines[1], 10);
        e2 = new BigInteger(pkeyLines[2], 10);
        n2 = new BigInteger(pkeyLines[3], 10);

        // Get message
        message = messageLines[0];

        // Ask for the user number
        System.out.print("Select a user to sign the message (1/2): ");
        String userNumberString = s.nextLine();
        int userNumber = 0;
        if (userNumberString.startsWith("1")) {
            userNumber = 1;
        } else if (userNumberString.startsWith("2")) {
            userNumber = 2;
        } else {
            System.err.println("!! Invalid user selected.");
            System.exit(1);
        }
        System.out.println();

        // Perform ring signature
        BigInteger k = sha1(message);
        BigInteger v = rand(160);
        BigInteger xA = rand(160);
        BigInteger yA = BigInteger.ZERO;

        // Calculate yA = xA^eA mod nA
        switch (userNumber) {
            case 1: 
                yA = xA.modPow(e2, n2);
                break;
            case 2:
                yA = xA.modPow(e1, n1);
                break;
            default: 
                System.exit(1);
                break;
        }

        // Solve for yB
        BigInteger yB = decrypt(v, k).xor(encrypt(yA.xor(v), k));

        // Get the RSA secrets

        System.out.print("Enter the private exponent d in radix-16 for user ");
        System.out.print(userNumber);
        System.out.print(": ");
        BigInteger dX = new BigInteger(s.nextLine(), 16);

        System.out.println();
        switch (userNumber) {
            case 1: 
                System.out.println("Public exponent for user " + userNumber + ": " + e1.toString(16));
                break;
            case 2:
                System.out.println("Public exponent for user " + userNumber + ": " + e2.toString(16));
                break;
            default: break;
        }
        System.out.println("Private exponent for user " + userNumber + ": " + dX.toString(16));
        System.out.println();

        // Find xB
        BigInteger xB = BigInteger.ZERO;
        switch (userNumber) {
            case 1: 
                xB = yB.modPow(dX, n1);
                break;
            case 2:
                xB = yB.modPow(dX, n2);
                break;
            default: break;
        }

        // Signature is (e1, n1), (e2, n2), v, xA, xB
        System.out.println("Signed message: ");
        System.out.print("(");
        System.out.print(e1.toString(16));
        System.out.print(", ");
        System.out.print(n1.toString(16));
        System.out.print("), (");
        System.out.print(e2.toString(16));
        System.out.print(", ");
        System.out.print(n2.toString(16));
        System.out.print("), ");
        System.out.print(v.toString(16));
        System.out.print(", ");
        System.out.print(xA.toString(16));
        System.out.print(", ");
        System.out.print(xB.toString(16));
        System.out.println();
        

        save("signed.txt", e1.toString(10) + System.lineSeparator() + 
                            n1.toString(10) + System.lineSeparator() + 
                            e2.toString(10) + System.lineSeparator() +
                            n2.toString(10) + System.lineSeparator() + 
                            v.toString(10) + System.lineSeparator() + 
                            xA.toString(10) + System.lineSeparator() + 
                            xB.toString(10));

        System.out.println("The signed message has been saved as 'signed.txt'.");
        System.out.println("! Note that the signed message is saved in radix-10 (base-10).");

    }

    private static void runVerification() {

        Scanner s = new Scanner(System.in);
        String[] signedLines = open("signed.txt").split(System.lineSeparator());
        String[] messageLines = open("message.txt").split(System.lineSeparator());
        BigInteger e1 = BigInteger.ZERO;
        BigInteger n1 = BigInteger.ZERO;
        BigInteger e2 = BigInteger.ZERO;
        BigInteger n2 = BigInteger.ZERO;
        BigInteger v = BigInteger.ZERO;
        BigInteger xA = BigInteger.ZERO;
        BigInteger xB = BigInteger.ZERO;
        String message = "";

        try {
            
            // Get public key lines
            e1 = new BigInteger(signedLines[0], 10);
            n1 = new BigInteger(signedLines[1], 10);
            e2 = new BigInteger(signedLines[2], 10);
            n2 = new BigInteger(signedLines[3], 10);

            // Get other components of signature
            v = new BigInteger(signedLines[4], 10);
            xA = new BigInteger(signedLines[5], 10);
            xB = new BigInteger(signedLines[6], 10);

            // Get message
            message = messageLines[0];
            
        } catch (Exception e) {
            System.err.println("!! Could not read one or more required files.");
            System.exit(1);
        }

        // Ask for the user number
        System.out.print("Select the user who signed the message (1/2): ");
        String userNumberString = s.nextLine();
        int userNumber = 0;
        if (userNumberString.startsWith("1")) {
            userNumber = 1;
        } else if (userNumberString.startsWith("2")) {
            userNumber = 2;
        } else {
            System.err.println("!! Invalid user selected.");
            System.exit(1);
        }
        System.out.println();

        // Verify signature
        BigInteger yA = BigInteger.ZERO;
        BigInteger yB = BigInteger.ZERO;
        switch (userNumber) {
            case 1: 
                yA = xA.modPow(e2, n2);
                yB = xB.modPow(e1, n1);
                break;
            case 2:
                yA = xA.modPow(e1, n1);
                yB = xB.modPow(e2, n2);
                break;
            default: break;
        }

        BigInteger k = sha1(message);

        BigInteger validation = encrypt(yB.xor(encrypt(yA.xor(v), k)), k);

        System.out.println("Calculated value: " + validation.toString(16));
        System.out.println("Signed value v: " + v.toString(16));

        System.out.println();
        if (validation.equals(v)) {
            System.out.println("The signature appears valid.");
        } else {
            System.out.println("The signature does not appear to be valid.");
        }
        
    }

    // Helper functions
    
    private static BigInteger rand(int bits) {
        try {

            BigInteger randomNumber;
            SecureRandom rng = SecureRandom.getInstance("SHA1PRNG");
            randomNumber = new BigInteger(bits, 1, rng);
            return randomNumber;

        } catch (Exception e) {
            return BigInteger.ZERO;
        }
    }

    private static BigInteger sha1(String message) {
        try {
            
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            digest.reset();
            digest.update(message.getBytes("UTF-8"));
            
            return new BigInteger(String.format("%040x", new BigInteger(1, digest.digest())), 16);
            
        } catch (Exception e) {
            return BigInteger.ZERO;
        }
    }

    // Super secret encryption algorithm using XOR
    private static BigInteger encrypt(BigInteger message, BigInteger key) {
        return message.xor(key);
    }

    // Super secret decryption algorithm using XOR
    private static BigInteger decrypt(BigInteger ciphertext, BigInteger key) {
        return ciphertext.xor(key);
    }

    private static void save(String p, String c) {
        try {
            File f = new File(p);
            FileWriter w = new FileWriter(f);
            w.write(c);
            w.close();
        } catch (Exception e) {
            System.err.println("!! Failed to save a file.");
            System.exit(1);
        }
    }
    
    private static String open(String p) {
        try {
            File f = new File(p);
            FileReader r = new FileReader(f);
            int d;
            String s = "";
            while ((d = r.read()) != -1) {
                s = s + (char)d;
            }
            return s;
        } catch (Exception e) {
            return "";
        }
    }

}