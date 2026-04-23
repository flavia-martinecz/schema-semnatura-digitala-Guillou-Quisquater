import java.math.BigInteger;
import java.security.*;
import javax.crypto.Cipher;

/**
 * Benchmark comparativ: GQ vs RSA
 * Masoara: setup, semnare, verificare, dimensiuni
 */
public class GQBenchmark {
    
    private static final int ITERATII = 1000;
    private static final String MESAJ_TEST = "Acesta este un mesaj de test pentru semnatura digitala";
    private static final String IDENTITATE_TEST = "user@example.com";
    
    public static void main(String[] args) {
        afiseazaSeparator();
        System.out.println("BENCHMARK GUILLOU-QUISQUATER vs RSA");
        afiseazaSeparator();
        
        try {
            // Testeaza diferite dimensiuni de chei
            int[] dimensiuni = {1024, 2048};
            
            for (int dim : dimensiuni) {
                System.out.println("\n--- Dimensiune cheie: " + dim + " biti ---\n");
                
                benchmarkGQ(dim);
                System.out.println();
                
                benchmarkRSASignature(dim);
                System.out.println();
                
                benchmarkRSAEncryption(dim);
                System.out.println();
                
                afiseazaSeparator();
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    /**
     * Benchmark pentru schema GQ
     */
    private static void benchmarkGQ(int dimensiuneCheie) throws Exception {
        System.out.println("GUILLOU-QUISQUATER:");
        
        // 1. SETUP sistem
        long timpStart = System.nanoTime();
        GQSignature autoritate = new GQSignature(dimensiuneCheie, 256);  // k=256
        double timpSetup = (System.nanoTime() - timpStart) / 1_000_000.0;

        // 2. GENERARE certificat
        timpStart = System.nanoTime();
        BigInteger certificat = autoritate.generareCertificat(IDENTITATE_TEST);
        double timpCertificat = (System.nanoTime() - timpStart) / 1_000_000.0;
        
        // 3. Creeare instanta utilizator
        GQSignature utilizator = new GQSignature(
            autoritate.getN(), 
            autoritate.getV(), 
            autoritate.getK()
        );
        
        // 4. WARMUP (incalzire JVM)
        for (int i = 0; i < 10; i++) {
            GQSignature.Semnatura sem = utilizator.semnare(MESAJ_TEST, IDENTITATE_TEST, certificat);
            utilizator.verificare(MESAJ_TEST, sem);
        }
        
        // 5. BENCHMARK semnare
        timpStart = System.nanoTime();
        GQSignature.Semnatura semnatura = null;
        for (int i = 0; i < ITERATII; i++) {
            semnatura = utilizator.semnare(MESAJ_TEST, IDENTITATE_TEST, certificat);
        }
        double timpSemnare = (System.nanoTime() - timpStart) / (double) ITERATII / 1_000_000.0;

        // 6. BENCHMARK verificare
        timpStart = System.nanoTime();
        boolean valid = false;
        for (int i = 0; i < ITERATII; i++) {
            valid = utilizator.verificare(MESAJ_TEST, semnatura);
        }
        double timpVerificare = (System.nanoTime() - timpStart) / (double) ITERATII / 1_000_000.0;

        // 7. AFISARE rezultate
        System.out.printf("  Setup sistem:           %9.3f ms\n", timpSetup);
        System.out.printf("  Generare certificat:    %9.3f ms\n", timpCertificat);
        System.out.printf("  Semnare (medie):        %9.3f ms\n", timpSemnare);
        System.out.printf("  Verificare (medie):     %9.3f ms\n", timpVerificare);
        System.out.printf("  Verificare valida:      %s\n", valid ? "DA" : "NU");
        
        int dimSemnatura = (semnatura.d.bitLength() + semnatura.y.bitLength()) / 8;
        System.out.printf("  Dimensiune semnatura:   %d bytes\n", dimSemnatura);
    }
    
    /**
     * Benchmark pentru RSA Signature
     */
    private static void benchmarkRSASignature(int dimensiuneCheie) throws Exception {
        System.out.println("RSA SIGNATURE (SHA256withRSA):");
        
        // 1. SETUP (generare chei)
        long timpStart = System.nanoTime();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(dimensiuneCheie, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();
        double timpSetup = (System.nanoTime() - timpStart) / 1_000_000.0;

        Signature rsaSign = Signature.getInstance("SHA256withRSA");
        byte[] mesajBytes = MESAJ_TEST.getBytes();
        
        // 2. WARMUP
        for (int i = 0; i < 10; i++) {
            rsaSign.initSign(keyPair.getPrivate());
            rsaSign.update(mesajBytes);
            byte[] sem = rsaSign.sign();
            
            rsaSign.initVerify(keyPair.getPublic());
            rsaSign.update(mesajBytes);
            rsaSign.verify(sem);
        }
        
        // 3. BENCHMARK semnare
        timpStart = System.nanoTime();
        byte[] semnatura = null;
        for (int i = 0; i < ITERATII; i++) {
            rsaSign.initSign(keyPair.getPrivate());
            rsaSign.update(mesajBytes);
            semnatura = rsaSign.sign();
        }
        double timpSemnare = (System.nanoTime() - timpStart) / (double) ITERATII / 1_000_000.0;

        // 4. BENCHMARK verificare
        timpStart = System.nanoTime();
        boolean valid = false;
        for (int i = 0; i < ITERATII; i++) {
            rsaSign.initVerify(keyPair.getPublic());
            rsaSign.update(mesajBytes);
            valid = rsaSign.verify(semnatura);
        }
        double timpVerificare = (System.nanoTime() - timpStart) / (double) ITERATII / 1_000_000.0;

        // 5. AFISARE rezultate
        System.out.printf("  Generare chei:          %9.3f ms\n", timpSetup);
        System.out.printf("  Semnare (medie):        %9.3f ms\n", timpSemnare);
        System.out.printf("  Verificare (medie):     %9.3f ms\n", timpVerificare);
        System.out.printf("  Verificare valida:      %s\n", valid ? "DA" : "NU");
        System.out.printf("  Dimensiune semnatura:   %d bytes\n", semnatura.length);
    }
    
    /**
     * Benchmark pentru RSA Encryption/Decryption
     */
    private static void benchmarkRSAEncryption(int dimensiuneCheie) throws Exception {
        System.out.println("RSA ENCRYPTION/DECRYPTION (PKCS1Padding):");
        
        // 1. SETUP (generare chei)
        long timpStart = System.nanoTime();
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(dimensiuneCheie, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();
        double timpSetup = (System.nanoTime() - timpStart) / 1_000_000.0;

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        
        // Mesaj scurt pentru criptare (limitare RSA)
        byte[] mesajScurt = "Test".getBytes();
        
        // 2. WARMUP
        for (int i = 0; i < 10; i++) {
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            byte[] criptat = cipher.doFinal(mesajScurt);
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            cipher.doFinal(criptat);
        }
        
        // 3. BENCHMARK criptare
        timpStart = System.nanoTime();
        byte[] criptat = null;
        for (int i = 0; i < ITERATII; i++) {
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            criptat = cipher.doFinal(mesajScurt);
        }
        double timpCriptare = (System.nanoTime() - timpStart) / (double) ITERATII / 1_000_000.0;

        // 4. BENCHMARK decriptare
        timpStart = System.nanoTime();
        for (int i = 0; i < ITERATII; i++) {
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            cipher.doFinal(criptat);
        }
        double timpDecriptare = (System.nanoTime() - timpStart) / (double) ITERATII / 1_000_000.0;

        // 5. AFISARE rezultate
        System.out.printf("  Generare chei:          %9.3f ms\n", timpSetup);
        System.out.printf("  Criptare (medie):       %9.3f ms\n", timpCriptare);
        System.out.printf("  Decriptare (medie):     %9.3f ms\n", timpDecriptare);
        System.out.printf("  Dimensiune criptat:     %d bytes\n", criptat.length);
    }
    
    private static void afiseazaSeparator() {
        System.out.println("=".repeat(70));
    }
}