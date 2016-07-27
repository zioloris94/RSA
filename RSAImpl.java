
package rsa;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;


public class RSAImpl implements RSA {

    private final static BigInteger ONE = new BigInteger("1");
    private BigInteger privateKey;
    private BigInteger e; //parte di chiave pubblica - relativa ai primi di phi, cioè che sia coprimo e più piccola di phi(n) 
    private BigInteger modulus; //parte della chiave pubblica e chiave privata ottenuta con n = p*q
    private BigInteger p; //primo
    private BigInteger q; //primo
    private final BigInteger phi;// ottenuta con phi = (p-1)*(q-1)

    RSAImpl(BigInteger p, BigInteger q, BigInteger e) {

        phi = (p.subtract(ONE)).multiply(q.subtract(ONE)); //phi = (p-1)*(q-1) 
        this.e = e;
        this.p = p;
        this.q = q;
        modulus = p.multiply(q);//variabile che rappresenta n*q
        privateKey = e.modInverse(phi);//d = e^-1 mod phi, chiave privata è ottenuta con l'inverso moltiplicativo di 'e' mod 'phi'
    }

    @Override
    public BigInteger encrypt(BigInteger bigInteger) {
        if (isModulusSmallerThanMessage(bigInteger)) {
            throw new IllegalArgumentException("Could not encrypt - message bytes are greater than modulus");
        }
        return bigInteger.modPow(e, modulus);// metodo che effettua l'operazione di (this ^exponent(e) mod modulus)
                                             
    }   

    public List<BigInteger> encryptMessage(final String message) {
        List<BigInteger> toEncrypt = new ArrayList<BigInteger>();
        BigInteger messageBytes = new BigInteger(message.getBytes());
        if (isModulusSmallerThanMessage(messageBytes)) {
            toEncrypt = getValidEncryptionBlocks(Utils.splitMessages(new ArrayList<String>() {
                {
                    add(message);
                }
            }));
        } else {
            toEncrypt.add((messageBytes));
        }
        List<BigInteger> encrypted = new ArrayList<BigInteger>();
        for (BigInteger bigInteger : toEncrypt) {
            encrypted.add(this.encrypt(bigInteger));
        }
        return encrypted;
    }

    /*Metodo per decriptare la parola criptata(che noi intendiamo come valore decimale) , utilizzando la chiave 
      privata(d,n). Ci appogiamo ad una funzione java modPow che permette di effettuare 
      l'operazione C^d mod n=m . Per C intendiamo il messaggio criptato che viene elevato con la 
      chiave privata d e mod di n */
    
    @Override
    public BigInteger decrypt(BigInteger encrypted) {
        return encrypted.modPower(privateKey, modulus);
    }
    /*Metodo per decriptare una lista di  parola criptate(che noi intendiamo come valore decimale) , utilizzando la chiave 
      privata(d,n). Ci appogiamo ad una funzione java modPow che permette di effettuare 
      l'operazione C^d mod n=m . Per C intendiamo il messaggio criptato che viene elevato con la 
      chiave privata d e mod di n */
    
    public List<BigInteger> decrypt(List<BigInteger> encryption) {
        List<BigInteger> decryption = new ArrayList<BigInteger>();
        for (BigInteger bigInteger : encryption) {
            decryption.add(this.decrypt(bigInteger));
        }
        return decryption;
    }

    @Override
    public BigInteger sign(BigInteger bigInteger) {
        return bigInteger.modPow(privateKey, modulus);
    }

    public List<BigInteger> signMessage(final String message) {
        List<BigInteger> toSign = new ArrayList<BigInteger>();
        BigInteger messageBytes = new BigInteger(message.getBytes());
        if (isModulusSmallerThanMessage(messageBytes)) {
            toSign = getValidEncryptionBlocks(Utils.splitMessages(new ArrayList<String>() {
                {
                    add(message);
                }
            }));
        } else {
            toSign.add((messageBytes));
        }
        List<BigInteger> signed = new ArrayList<BigInteger>();
        for (BigInteger bigInteger : toSign) {
            signed.add(this.sign(bigInteger));
        }
        return signed;
    }

    
    @Override
    public BigInteger Verify(BigInteger signedMessage) {
        return signedMessage.modPow(e, modulus);
    }

    public List<BigInteger> verify(List<BigInteger> signedMessages) {
        List<BigInteger> verification = new ArrayList<BigInteger>();
        for (BigInteger bigInteger : signedMessages) {
            verification.add(this.Verify(bigInteger));
        }
        return verification;
    }

    @Override
    public boolean isVerified(BigInteger signedMessage, BigInteger message) {
        return this.Verify(signedMessage).equals(message);
    }

    /**
     * assicura che il blocco da criptare sia piu piccolo del modulo
     *
     * @param messages list of blocks to be splited at half recursively
     * @return list of valid blocs
     *
     * 
     */
    private List<BigInteger> getValidEncryptionBlocks(List<String> messages) {
        List<BigInteger> validBlocks = new ArrayList<BigInteger>();
        BigInteger messageBytes = new BigInteger(messages.get(0).getBytes());
        if (!isModulusSmallerThanMessage(messageBytes)) {
            for (String msg : messages) {
                validBlocks.add(new BigInteger(msg.getBytes()));
            }
            return validBlocks;
        } else {//message is bigger than modulus so we have o split it
            return getValidEncryptionBlocks(Utils.splitMessages(messages));
        }

    }

    /*Questo metodo permette di convertire la stringa che noi inseriamo , in un numero decimale
    */
    public List<BigInteger> messageToDecimal(final String message) {
        List<BigInteger> toDecimal = new ArrayList<BigInteger>();
        BigInteger messageBytes = new BigInteger(message.getBytes());
        if (isModulusSmallerThanMessage(messageBytes)) {
            toDecimal = getValidEncryptionBlocks(Utils.splitMessages(new ArrayList<String>() {
                {
                    add(message);
                }
            }));
        } else {
            toDecimal.add((messageBytes));
        }
        List<BigInteger> decimal = new ArrayList<BigInteger>();
        for (BigInteger bigInteger : toDecimal) {
            decimal.add(bigInteger);
        }
        return decimal;
    }

    
    
    private boolean isModulusSmallerThanMessage(BigInteger messageBytes) {
        return modulus.compareTo(messageBytes) == -1;
    }

    @Override
    public String toString() {
        String s = "";
        s += "p                     = " + p + "\n";
        s += "q                     = " + q + "\n";
        s += "e                     = " + e + "\n";
        s += "private               = " + privateKey + " esponente privato\n";
        s += "modulus               = " + modulus+" valore chiamato modulo p*q";
        return s;
    }

    
}
