import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.SecureRandom;

/**
 * Tema proiect:
 * Schema de semnatura digitala bazata pe identitate Guillou-Quisquater (in Zn)
 * 
 * @author Flavia Martinecz
 * @university Universitatea Politehnica Timisoara
 * @course Master SISC - Tehnici criptografice moderne - an I sem. I
 */
public class GQSignature {
    
    // Parametri PUBLICI - toti ii stiu
    private BigInteger n;  // Modul RSA: n = p × q
    private BigInteger v;  // Exponent public (65537)
    private int k;         // Dimensiune challenge (256 biti)
    
    // Parametri SECRETI - doar CA
    private BigInteger p, q;  // Factori primi
    private BigInteger s;     // Exponent privat: s = v^-1 mod φ(n)
    
    // Utilitare
    private SecureRandom random;
    private MessageDigest hash;
    
    /**
     * Constructor pentru Autoritatea de Certificare (CA)
     * Genereaza toti parametrii sistemului
     */
    public GQSignature(int bitLength, int k) throws Exception {
        this.k = k;
        this.random = new SecureRandom();
        this.hash = MessageDigest.getInstance("SHA-256");
        generareParametri(bitLength);
    }
    
    /**
     * Constructor pentru Utilizatori
     * Foloseste parametri publici existenti
     */
    public GQSignature(BigInteger n, BigInteger v, int k) throws Exception {
        this.n = n;
        this.v = v;
        this.k = k;
        this.random = new SecureRandom();
        this.hash = MessageDigest.getInstance("SHA-256");
    }
    
    /**
     * PASUL 1: Generare parametri sistem (doar CA)
     * Genereaza: p, q, n, v, s
     */
    private void generareParametri(int bitLength) {
        // Genereaza doi factori primi mari
        p = BigInteger.probablePrime(bitLength / 2, random);
        q = BigInteger.probablePrime(bitLength / 2, random);
        
        // Calculeaza n = p × q
        n = p.multiply(q);
        
        // Calculeaza φ(n) = (p-1)(q-1)
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        
        // Alege v = 65537 (standard RSA)
        v = BigInteger.valueOf(65537);
        
        // Calculeaza s = v^-1 mod φ(n)
        s = v.modInverse(phi);
    }
    
    /**
     * PASUL 2: Generare certificat pentru utilizator (doar CA)
     * Input: identitate (ex: "alice@company.com")
     * Output: J = certificat secret
     */
    public BigInteger generareCertificat(String identitate) {
        // I = H(identitate) mod n
        BigInteger I = hashCatreBigInteger(identitate).mod(n);
        
        // J = I^s mod n (certificatul secret)
        BigInteger J = I.modPow(s, n);
        
        return J;
    }
    
    /**
     * PASUL 3: Semnare mesaj
     * Input: mesaj, identitate, certificat
     * Output: semnatura (d, y, identitate)
     */
    public Semnatura semnare(String mesaj, String identitate, BigInteger certificat) {
        // 1. Alege r aleatoriu din Zn*
        BigInteger r = generareRandom();
        
        // 2. Calculeaza commitment: T = r^v mod n
        BigInteger T = r.modPow(v, n);
        
        // 3. Calculeaza challenge: d = H(mesaj || T) mod 2^k
        BigInteger d = calculeazaChallenge(mesaj, T);
        
        // 4. Calculeaza raspuns: y = r × J^d mod n
        BigInteger Jd = certificat.modPow(d, n);
        BigInteger y = r.multiply(Jd).mod(n);
        
        return new Semnatura(d, y, identitate);
    }
    
    /**
     * PASUL 4: Verificare semnatura
     * Input: mesaj, semnatura
     * Output: true daca valida, false altfel
     */
    public boolean verificare(String mesaj, Semnatura sem) {
        try {
            // 1. Recalculeaza I = H(identitate) mod n
            BigInteger I = hashCatreBigInteger(sem.identitate).mod(n);
            
            // 2. Calculeaza T' = y^v × I^(-d) mod n
            BigInteger yv = sem.y.modPow(v, n);
            BigInteger Id = I.modPow(sem.d, n);
            BigInteger IdInv = Id.modInverse(n);
            BigInteger TPrim = yv.multiply(IdInv).mod(n);
            
            // 3. Recalculeaza challenge: d' = H(mesaj || T')
            BigInteger dPrim = calculeazaChallenge(mesaj, TPrim);
            
            // 4. Verifica: d' == d
            return dPrim.equals(sem.d);
            
        } catch (Exception e) {
            return false;
        }
    }
    
    // ========== FUNCTII AUXILIARE ==========
    
    /**
     * Genereaza numar aleatoriu r din Zn*
     * Conditii: r < n si gcd(r, n) = 1
     */
    private BigInteger generareRandom() {
        BigInteger r;
        do {
            r = new BigInteger(n.bitLength(), random);
        } while (r.compareTo(n) >= 0 || !r.gcd(n).equals(BigInteger.ONE));
        return r;
    }
    
    /**
     * Hash string catre BigInteger
     */
    private BigInteger hashCatreBigInteger(String text) {
        hash.reset();
        byte[] hashBytes = hash.digest(text.getBytes());
        return new BigInteger(1, hashBytes);
    }
    
    /**
     * Calculeaza challenge: d = H(mesaj || T) mod 2^k
     */
    private BigInteger calculeazaChallenge(String mesaj, BigInteger T) {
        hash.reset();
        String combinat = mesaj + T.toString();
        byte[] hashBytes = hash.digest(combinat.getBytes());
        BigInteger hashInt = new BigInteger(1, hashBytes);
        
        // Reduce la k biti: hash mod 2^k
        BigInteger modulus = BigInteger.ONE.shiftLeft(k);
        return hashInt.mod(modulus);
    }
    
    // Getteri pentru parametri publici
    public BigInteger getN() { return n; }
    public BigInteger getV() { return v; }
    public int getK() { return k; }
    
    /**
     * Clasa pentru stocare semnatura
     */
    public static class Semnatura {
        public final BigInteger d;  // Challenge
        public final BigInteger y;  // Raspuns
        public final String identitate;
        
        public Semnatura(BigInteger d, BigInteger y, String identitate) {
            this.d = d;
            this.y = y;
            this.identitate = identitate;
        }
        
        @Override
        public String toString() {
            return String.format("Semnatura GQ [d=%d biti, y=%d biti, ID=%s]", 
                d.bitLength(), y.bitLength(), identitate);
        }
    }
}