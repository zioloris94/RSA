
package rsa;

import java.io.Serializable;
import java.math.BigInteger;
import java.util.List;


public interface RSA extends Serializable {

   /**
     * Cifra un messaggio attraverso<b>C = M^e mod n</b> dove: <ul> <li>C =
     * Messaggio criptato <li>M = messaggio che deve essere criptato <li>e =primo 
     * relativo a phi <li>n = modulo ottenuto da p*q </ui>
     *
     * @param messaggio che deve essere criptato
     * @return messaggio criptato rappresentato da una Java BigInteger 
     */
    BigInteger encrypt(BigInteger bigInteger);

    /**
     * criptare un messaggio, verificando se i blocchi
     * dei messaggi sono validi
     *
     * @see RSAImpl#getValidEncryptionBlocks(java.util.List)
     * @see RSAImpl#encrypt(java.math.BigInteger)
     * @param Stringa messaggio
     * @return  Una lista di blocchi di messaggi criptati dove ciascun blocco criptato è rappresentato da una Java BigInteger 
     */
    List<BigInteger> encryptMessage(final String message);

    

    /**
     * decriptare un messaggio attraverso <b>M = C^d mod n</b> dove: <ul>
     * <li>M = messaggio decriptato <li>C = messaggio criptato <li>d = chiave privata -
     * ottenuta da inverso moltiplicato di 'e' mod 'phi' <li>n = modulo -
     * ottenuto da  p*q </ul>
     *
     * @param encrypted messaggio criptato
     * @return decrypted messaggio rappresentato da Java BigInteger type
     */
    BigInteger decrypt(BigInteger encrypted);

    /**
     * decriptare una lista di messaggi criptati <b>M = C^d mod n</b> dove:
     * <ul> <li>M = messaggio decriptato <li>C = messaggio criptato <li>d = chiave
     * privata - ottenuto da inverso moltiplicativo di 'e' mod 'phi' <li>n =
     * modulo - ottenuto da p*q </ul>
     *
     * @param encryption messaggio criptato rappresentato da una lista of Java BigInteger
     * @return lista di messaggi decriptati
     */
    List<BigInteger> decrypt(List<BigInteger> encryption);

    /**
     * firma digitale di un messaggio attraverso <b>A = M^d mod n</b> dove: <ul> <li>A
     * = messaggio segnato <li>M = messaggio che deve essere segnato digitalmente <li>d = chiave
     * privata - ottenuto da inversa moltiplicativa di 'e' mod 'phi' <li>n =
     * modulo - ottenuto da p*q </ul>
     *
     * @param messaggio che deve essere segnato digitalmente
     * @return messaggio segnato rappresentato da una Java BigInteger
     */
    BigInteger sign(BigInteger bigInteger);

    /**
     * firma digitale usando il metodo sign verificando se blocchi di messaggi sono
     * validi
     *
     * @see RSAImpl#getValidEncryptionBlocks(java.util.List)
     * @see RSAImpl#sign(java.math.BigInteger)
     * @param messaggio stringa
     * @return una lista di blocchi di messaggi segnati dove ciascun blocco segnato è rappresentato da una Java BigInteger
     */
    List<BigInteger> signMessage(final String message);

   

    /**
     * verificare un messaggio attraverso <b>A^e mod n = M</b> dove: <ul> <li>A
     * = messaggio segnato <li>e = primo relativo a phi <li>n = modulo - ottenuto
     * da p*q <li>M = messaggio originale </ul>
     *
     * @param messaggio che deve essere verificato
     * @return numero decimale risultato da verifica , se esso è uguale
     * alla rappresentazione decimale del messaggio originale, l'operazione avrà successo
     * verified
     * @see RSA#isVerified(java.math.BigInteger, java.math.BigInteger)
     *
     */
    BigInteger Verify(BigInteger signedMessage);

    /**
     * verifica una lista di messaggi segnati attraverso metodo di verifica
     *
     * @param messaggi firmati
     * @return lista di messaggi verificati
     * @see RSA#Verify(java.math.BigInteger)
     */
    List<BigInteger> verify(List<BigInteger> signedMessages);

    /**
     * @param messaggio firmato
     * @param messaggio originale
     * @return <code>true</code> se la rappresentazione del messaggio
     * originale matcha con la rappresentazione decimale del messaggio firmato
     * <code>false</code> altrimenti
     *
     * @see RSA#Verify(java.math.BigInteger)
     */
    boolean isVerified(BigInteger signedMessage, BigInteger message);
    
    /**
     * @param messaggio
     * @return rappresentazione decimale del messaggio
     */
    List<BigInteger> messageToDecimal(final String message);
            
    
}

