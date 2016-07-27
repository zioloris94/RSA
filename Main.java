package rsa;

import java.math.BigInteger;
import java.util.List;

public class Main {

    public static void main(String[] args) {
        BigInteger p;
        BigInteger q;
        BigInteger e;
        final String message;

        p = new BigInteger("101");//numero primo scelto da te
        q = new BigInteger("113");//numero primo scelto da te
        e = new BigInteger("3533");//esponente pubblico,comporrà la chiave pubblica (e,n). Deve essere più piccolo e coprimo di phi(n)
        message = "Sto facendo un test";//Messaggio che noi dobbiamo inviare

        RSA RSA = new RSAImpl(p, q, e);
        System.out.println(RSA);

        List<BigInteger> encryption;
        List<BigInteger> signed;
        List<BigInteger> decimalMessage;

        encryption = RSA.encryptMessage(message);//variabile che utilizza il metodo encryptMessage passandogli una stringa
        signed = RSA.signMessage(message);//variabile per la firma digitale
        decimalMessage = RSA.messageToDecimal(message);//variabile che rappresenta il messaggio in forma decimale

        List<BigInteger> decrypt = RSA.decrypt(encryption);//variabile che rappresenta il decriptare un messaggio criptato
        List<BigInteger> verify = RSA.verify(signed);//variabile che rappresenta la verifica della firma digitale
        System.out.println();
        System.out.println("message(plain text)   = " + Utils.bigIntegerToString(decimalMessage));//qui stampiamo il messaggio senza convertirlo
        System.out.println("message(decimal)      = " + Utils.bigIntegerSum(decimalMessage));//qui stampiamo il messaggio convertito in decimale
        System.out.println("encripted(decimal)    = " + Utils.bigIntegerSum(encryption));//qui stampiamo il messaggio criptato
        System.out.println("decrypted(plain text) = " + Utils.bigIntegerToString(decrypt));//qui stampiamo il messaggio decriptato in decimale nel testo in stringa
        System.out.println("decrypted(decimal)    = " + Utils.bigIntegerSum(decrypt));//qi stampiamo il messaggio decriptato dal valore criptato in decimale
        System.out.println("signed(decimal)       = " + Utils.bigIntegerSum(signed));
        System.out.println("verified(plain text)  = " + Utils.bigIntegerToString(verify));
        System.out.println("verified(decimal)     = " + Utils.bigIntegerSum(verify));
    }
}
