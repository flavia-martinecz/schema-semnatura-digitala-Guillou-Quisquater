import java.math.BigInteger;

/**
 * Demonstratie functionare schema Guillou-Quisquater
 * Exemplu complet cu 2 utilizatori (Alice si Bob)
 */
public class GQDemo {
    
    public static void main(String[] args) {
        try {
            afiseazaSeparator();
            System.out.println("DEMONSTRATIE SCHEMA GUILLOU-QUISQUATER");
            afiseazaSeparator();
            
            // ==================== PASUL 1: SETUP SISTEM ====================
            System.out.println("\n[PASUL 1] SETUP SISTEM - Autoritatea de Certificare (CA)");
            System.out.println("-".repeat(70));
            
            int dimensiuneCheie = 1024;  // biti
            int parametruSecuritate = 256;  // k = 256 biti (SHA-256)
            
            System.out.println("CA genereaza parametri sistem...");
            GQSignature autoritate = new GQSignature(dimensiuneCheie, parametruSecuritate);
            
            System.out.println("Parametri PUBLICI generati:");
            System.out.println("  n (modul):              " + autoritate.getN().bitLength() + " biti");
            System.out.println("     Valoare (primii 40 hex): " + autoritate.getN().toString(16).substring(0, 40) + "...");
            System.out.println("  v (exponent public):    " + autoritate.getV());
            System.out.println("  k (parametru securitate): " + autoritate.getK() + " biti");
            
            // ==================== PASUL 2: INREGISTRARE UTILIZATORI ====================
            System.out.println("\n[PASUL 2] INREGISTRARE UTILIZATORI");
            System.out.println("-".repeat(70));
            
            String idAlice = "alice@company.com";
            String idBob = "bob@company.com";
            
            System.out.println("Generare certificate pentru utilizatori...");
            
            BigInteger certAlice = autoritate.generareCertificat(idAlice);
            System.out.println("  Alice (" + idAlice + ")");
            System.out.println("    Certificat: " + certAlice.bitLength() + " biti");
            System.out.println("    Valoare (primii 40 hex): " + certAlice.toString(16).substring(0, 40) + "...");
            
            BigInteger certBob = autoritate.generareCertificat(idBob);
            System.out.println("  Bob (" + idBob + ")");
            System.out.println("    Certificat: " + certBob.bitLength() + " biti");
            System.out.println("    Valoare (primii 40 hex): " + certBob.toString(16).substring(0, 40) + "...");
            
            // ==================== PASUL 3: UTILIZATORII PRIMESC PARAMETRI ====================
            System.out.println("\n[PASUL 3] DISTRIBUIRE PARAMETRI PUBLICI");
            System.out.println("-".repeat(70));
            
            GQSignature alice = new GQSignature(autoritate.getN(), autoritate.getV(), autoritate.getK());
            GQSignature bob = new GQSignature(autoritate.getN(), autoritate.getV(), autoritate.getK());
            
            System.out.println("Alice si Bob au primit parametrii publici (n, v, k)");
            System.out.println("Acum pot semna mesaje si verifica semnaturi!");
            
            // ==================== PASUL 4: ALICE SEMNEAZA ====================
            System.out.println("\n[PASUL 4] ALICE SEMNEAZA UN MESAJ");
            System.out.println("-".repeat(70));
            
            String mesaj1 = "Contract: Transfer 1000 EUR catre Bob";
            System.out.println("Mesaj: \"" + mesaj1 + "\"");
            System.out.println("\nAlice semneaza...");
            
            GQSignature.Semnatura semAlice = alice.semnare(mesaj1, idAlice, certAlice);
            
            System.out.println("Semnatura generata:");
            System.out.println("  Challenge (d): " + semAlice.d.bitLength() + " biti");
            System.out.println("    Valoare (hex): " + semAlice.d.toString(16));
            System.out.println("  Raspuns (y):   " + semAlice.y.bitLength() + " biti");
            System.out.println("    Valoare (primii 40 hex): " + semAlice.y.toString(16).substring(0, 40) + "...");
            System.out.println("  Identitate:    " + semAlice.identitate);
            
            // ==================== PASUL 5: BOB VERIFICA ====================
            System.out.println("\n[PASUL 5] BOB VERIFICA SEMNATURA LUI ALICE");
            System.out.println("-".repeat(70));
            
            boolean valid1 = bob.verificare(mesaj1, semAlice);
            System.out.println("Rezultat verificare: " + (valid1 ? "VALIDA" : "INVALIDA"));
            
            if (!valid1) {
                System.out.println("EROARE: Semnatura ar trebui sa fie valida!");
                return;
            }
            
            // ==================== PASUL 6: TEST INTEGRITATE ====================
            System.out.println("\n[PASUL 6] TEST INTEGRITATE - Mesaj Modificat");
            System.out.println("-".repeat(70));
            
            String mesajModificat = "Contract: Transfer 9000 EUR catre Bob";  // MODIFICAT!
            System.out.println("Mesaj modificat: \"" + mesajModificat + "\"");
            
            boolean valid2 = bob.verificare(mesajModificat, semAlice);
            System.out.println("Rezultat verificare: " + (valid2 ? "VALIDA" : "INVALIDA"));
            
            if (valid2) {
                System.out.println("EROARE: Mesajul modificat ar trebui sa fie invalid!");
                return;
            }
            System.out.println("Corect! Mesajul modificat a fost detectat.");
            
            // ==================== PASUL 7: TEST AUTENTICITATE ====================
            System.out.println("\n[PASUL 7] TEST AUTENTICITATE - Identitate Falsa");
            System.out.println("-".repeat(70));
            
            GQSignature.Semnatura semFalsa = 
                new GQSignature.Semnatura(semAlice.d, semAlice.y, idBob);  // Identitate falsa!
            
            System.out.println("Incercare: semnatura lui Alice cu identitatea lui Bob");
            boolean valid3 = bob.verificare(mesaj1, semFalsa);
            System.out.println("Rezultat verificare: " + (valid3 ? "VALIDA" : "INVALIDA"));
            
            if (valid3) {
                System.out.println("EROARE: Identitatea falsa ar trebui sa fie invalida!");
                return;
            }
            System.out.println("Corect! Identitatea falsa a fost detectata.");
            
            // ==================== PASUL 8: BOB SEMNEAZA ====================
            System.out.println("\n[PASUL 8] BOB SEMNEAZA UN MESAJ");
            System.out.println("-".repeat(70));
            
            String mesaj2 = "Confirm primirea sumei de 1000 EUR de la Alice";
            System.out.println("Mesaj: \"" + mesaj2 + "\"");
            System.out.println("\nBob semneaza...");
            
            GQSignature.Semnatura semBob = bob.semnare(mesaj2, idBob, certBob);
            
            System.out.println("Semnatura generata de Bob:");
            System.out.println("  Challenge (d): " + semBob.d.bitLength() + " biti");
            System.out.println("    Valoare (hex): " + semBob.d.toString(16));
            System.out.println("  Raspuns (y):   " + semBob.y.bitLength() + " biti");
            System.out.println("    Valoare (primii 40 hex): " + semBob.y.toString(16).substring(0, 40) + "...");
            
            // ==================== PASUL 9: ALICE VERIFICA ====================
            System.out.println("\n[PASUL 9] ALICE VERIFICA SEMNATURA LUI BOB");
            System.out.println("-".repeat(70));
            
            boolean valid4 = alice.verificare(mesaj2, semBob);
            System.out.println("Rezultat verificare: " + (valid4 ? "VALIDA" : "INVALIDA"));
            
            if (!valid4) {
                System.out.println("EROARE: Semnatura lui Bob ar trebui sa fie valida!");
                return;
            }
            
            // ==================== STATISTICI FINALE ====================
            afiseazaSeparator();
            System.out.println("STATISTICI FINALE");
            afiseazaSeparator();
            
            int dimensiuneSemnatura = (semAlice.d.bitLength() + semAlice.y.bitLength()) / 8;
            
            System.out.println("Dimensiune modul (n):     " + dimensiuneCheie + " biti");
            System.out.println("Dimensiune certificat:    " + certAlice.bitLength() + " biti");
            System.out.println("Dimensiune semnatura:     ~" + dimensiuneSemnatura + " bytes");
            System.out.println("Parametru securitate (k): " + parametruSecuritate + " biti");
            
            afiseazaSeparator();
            System.out.println("TOATE TESTELE AU FOST EXECUTATE CU SUCCES!");
            afiseazaSeparator();
            
        } catch (Exception e) {
            System.err.println("\nEROARE: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static void afiseazaSeparator() {
        System.out.println("\n" + "=".repeat(70));
    }
}