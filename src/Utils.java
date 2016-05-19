import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.*;

/**
 * Created by Mat on 17/05/2016.
 */
public class Utils {

    // Generador de claus
    static KeyPairGenerator keyPairGenerator;

    /**
     * Comproba si les claus existeixen
     *
     * @return si existeixen retorna true
     */
    public static boolean areKeysPresent() throws IOException {

        if (keyPairGenerator == null){
            return false;
        }
        else {
            return true;
        }
    }

    /**
     * Crea una instancia de keyPairGenerator usant
     * l'algoritme RSA i inicialitzant-lo a 1024 bits
     *
     * @return Generador de claus KeyPair
     */
    public static KeyPair generateKeys() throws NoSuchAlgorithmException {

        keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        return keyPair;
    }

    /**
     * Escriu les claus generades a un arxiu existent
     *
     * @param PUBLIC_KEY_FILE Ruta del fitxer de clau publica
     * @param PRIVATE_KEY_FILE Ruta del fitxer de clau privada
     * @param privateKey Interficia de clau Privada
     * @param publicKey Interficia de clau Publica
     */
    public static void writeKeysOnFile(String PUBLIC_KEY_FILE, String PRIVATE_KEY_FILE,
                                     PrivateKey privateKey, PublicKey publicKey) throws IOException {

        //Es creen els fluxes per a les rutes de les claus
        FileOutputStream publicFos = new FileOutputStream(PUBLIC_KEY_FILE);
        FileOutputStream privateFos = new FileOutputStream(PRIVATE_KEY_FILE);

        //Es creen els buffers (1 per cada clau)
        byte[] publicK = publicKey.getEncoded();
        byte[] privateK = privateKey.getEncoded();

        publicFos.write(publicK);
        privateFos.write(privateK);

        publicFos.close();
        privateFos.close();

        System.out.println("...claus guardades");
    }


    /**
     * A partir d'un arxiu i un tipus d'algoritme, torna un hash
     *
     * @param file Fitxer en questió
     * @param algoritme Algoritme de tipus MD5
     *
     * @return Hash únic del fitxer
     */
    public static byte[] digestiona(File file, String algoritme) throws IOException, NoSuchAlgorithmException {

        MessageDigest md = MessageDigest.getInstance(algoritme);
        md.update(read(file));
        byte[] digest = md.digest();
        System.out.println("...xifrat MD5 OK");

        return digest;
    }

    /**
     * Encriptació RSA de dades enmagatzemades a un array de bytes
     *
     * @param array buffer de memoria a encriptar
     * @param publicKey clau publica
     * @return Buffer encriptat segons algoritme RSA
     */
    public static byte[] signar(byte[] array, PublicKey publicKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        byte[]encryptDigestionat = null;
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        encryptDigestionat =  cipher.doFinal(array);
        System.out.println("...encriptat RSA per clau publica OK");

        return encryptDigestionat;
    }

    /**
     * Desencripta dades enmagatzemades a un array de bytes
     * mitjanzant la clau publica
     *
     * @param encrypted array a desencriptar
     * @param privateKey clau privada
     * @return hash de buffer desencriptat
     */
    public static byte[] decrypt(byte[] encrypted, PrivateKey privateKey) throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {

        byte[]decryptDigestionat = null;
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        decryptDigestionat = cipher.doFinal(encrypted);
        System.out.println("\n...desencriptat RSA per clau privada OK");

        return decryptDigestionat;
    }

    /**
     * Donada una ruta, escriu el seu contingut a
     * un array de bytes
     *
     * @param ruta
     * @param arrayBytes
     */
    public static void write(String ruta, byte[] arrayBytes) throws IOException {

        FileOutputStream fos = new FileOutputStream(ruta);
        fos.write(arrayBytes);
        fos.close();
    }


    /**
     * Concatena dues arrays
     *
     * @param array1 Fitxer Original pasat a bytes
     * @param array2 buffer encriptat RSA amb la clau privada
     * @return Array concatenada de array1 + array2
     */
    public static byte[] concatenateByteArrays(byte[] array1, byte[] array2){

        // Concatenamos los arrays
        byte[]encryptDigestionat = new byte[array1.length + array2.length];
        System.arraycopy(array1, 0, encryptDigestionat, 0, array1.length);
        System.arraycopy(array2, 0, encryptDigestionat, array1.length, array2.length);

        return encryptDigestionat;
    }

    /**
     * Llegueix un fitxer i el transforma a bytes
     *
     * @param file
     * @return array de bytes del fitxer en questió
     */
    public static byte[] read(File file) throws IOException {

        byte[]fileToBytes = null;

        fileToBytes = Files.readAllBytes(Paths.get(file.getAbsolutePath()));

        return fileToBytes;
    }



}
