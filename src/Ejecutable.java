
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;

/**
 * Created by Mat on 17/05/2016.
 */

public class Ejecutable {

    //----------VARIABLES GLOBALS----------
    //fitxer del missatge original
    public static final String FITXER_PLA =
            "C:\\Users\\Mat\\Desktop\\DAM2\\git\\M09_SERVEIS\\crypto\\fitxerOriginalTextPla.txt";

    //fitxer xifrat que s'envia al destinatari
    public static final String FITXER_SIGNAT =
            "C:\\Users\\Mat\\Desktop\\DAM2\\git\\M09_SERVEIS\\crypto\\Firma.txt";
    public static final String PRIVATE_KEY_FILE =
            "C:\\Users\\Mat\\Desktop\\DAM2\\git\\M09_SERVEIS\\crypto\\private.txt";
    public static final String PUBLIC_KEY_FILE =
            "C:\\Users\\Mat\\Desktop\\DAM2\\git\\M09_SERVEIS\\crypto\\public.txt";


    public static void main(String[] args) throws IOException,NoSuchAlgorithmException,
                                                    ClassNotFoundException, IllegalBlockSizeException,
                                                    InvalidKeyException, BadPaddingException, NoSuchPaddingException {


        // Declaració de claus
        KeyPair keyPair = null;
        PrivateKey privateKey = null;
        PublicKey publicKey = null;

        //fitxer del missatge original
        File fileOriginal = new File(FITXER_PLA);

        // Es genera la clau publica i privada a partir de keyPair
        if(!Utils.areKeysPresent()) {
            System.out.println("...generant claus");
            keyPair = Utils.generateKeys();
            publicKey = keyPair.getPublic();
            privateKey = keyPair.getPrivate();
            Utils.writeKeysOnFile(PUBLIC_KEY_FILE, PRIVATE_KEY_FILE, privateKey, publicKey);
        }

        //Es resumeix l'arxiu original amb un xifrat MD5
        byte[] digestionat =  Utils.digestiona(fileOriginal,"MD5");
        //S'encripta a un buffer
        byte[] encryptDigestionat = Utils.signar(digestionat, privateKey);

        System.out.println("Longitud del fitxer original: " + fileOriginal.length());
        System.out.println("Longitud de la firma: " + encryptDigestionat.length);

        //Es genera el fitxer encriptat
        //Utils.write(FITXER_SIGNAT, Utils.concatenateByteArrays(Utils.read(fileOriginal), encryptDigestionat));
        Utils.write(FITXER_SIGNAT, Utils.concatenateByteArrays(digestionat, encryptDigestionat));


        System.out.println("OUT digestionat\n" + digestionat);
        System.out.println("OUT encryptDigestionat\n" + encryptDigestionat);
        String testing1 = "C:\\Users\\Mat\\Desktop\\DAM2\\git\\M09_SERVEIS\\crypto\\testD.txt";
        String testing2 = "C:\\Users\\Mat\\Desktop\\DAM2\\git\\M09_SERVEIS\\crypto\\testE.txt";
        String testing3 = "C:\\Users\\Mat\\Desktop\\DAM2\\git\\M09_SERVEIS\\crypto\\testDecrypt.txt";
        Utils.write(testing1, digestionat);
        Utils.write(testing2, encryptDigestionat);




        //---------COMPARACIÓ DE HASHCODE---------//

        byte[] desencriptado = Utils.decrypt(encryptDigestionat, publicKey);
        Utils.write(testing3, desencriptado);
        String str = new String(desencriptado,"UTF-8");
        System.out.println(str.hashCode());
        //str = md5(desencriptado);



        // Hash del fitxer original y del firmat
        String hashDeFitxerOriginalDigestionat = new String(digestionat,"UTF-8");
        String hashEncryptDigestionat = new String(desencriptado, "UTF-8");


        System.out.println("\n- HashCode del file original: " + hashDeFitxerOriginalDigestionat.hashCode()
                + "\n- HashCode del file firmado: " + hashEncryptDigestionat.hashCode());

        //Verificació
        if (hashDeFitxerOriginalDigestionat.equals(hashEncryptDigestionat)) {
            System.out.println("\n...fitxer original correcte");
        }
        else
            System.out.println("...ALERTA: fitxer compromés\n");


    }


    public static void muestraContenido(File file) throws FileNotFoundException, IOException {
        String cadena;
        FileReader f = new FileReader(file);
        BufferedReader b = new BufferedReader(f);
        while((cadena = b.readLine())!=null) {
            System.out.println(cadena);
        }
        b.close();
    }

    public static String md5(byte[] input) throws NoSuchAlgorithmException {
        final MessageDigest md = MessageDigest.getInstance("MD5");
        final byte[] messageDigest = md.digest(input);
        final BigInteger number = new BigInteger(1, messageDigest);

        return String.format("%032x", number);
    }
}