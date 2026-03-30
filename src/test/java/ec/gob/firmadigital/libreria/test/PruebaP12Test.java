package ec.gob.firmadigital.libreria.test;

import ec.gob.firmadigital.libreria.keystore.FileKeyStoreProvider;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class PruebaP12Test {
    public static void main(String[] args) {
        String rutaP12 = "C:\\ruta\\a\\tu\\certificado_CA1.p12"; // Reemplazar con la ruta real
        String password = "tu_password"; // Reemplazar con la contraseña real

        try {
            System.out.println("Iniciando validación del KeyStore...");
            FileKeyStoreProvider provider = new FileKeyStoreProvider(rutaP12);
            KeyStore ks = provider.getKeystore(password);

            Enumeration<String> aliases = ks.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
                System.out.println("Certificado cargado exitosamente.");
                System.out.println("Emisor: " + cert.getIssuerDN().getName());
                System.out.println("Sujeto: " + cert.getSubjectDN().getName());
                System.out.println("Válido hasta: " + cert.getNotAfter());

                // Verificar vigencia
                cert.checkValidity();
                System.out.println("Estado: Vigente.");
            }
        } catch (Exception e) {
            System.err.println("Error al procesar el certificado: " + e.getMessage());
            e.printStackTrace();
        }
    }
}