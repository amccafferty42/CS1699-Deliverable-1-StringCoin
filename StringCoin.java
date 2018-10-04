import java.io.*;
import java.security.*;
import java.security.spec.*;

class StringCoin {
    public static void main(String[] args) throws Exception{
        Blockchain blockchain = new Blockchain();
        Block[] blocks = new Block[10];
        String[][] output = new String[10][2];

        try (BufferedReader br = new BufferedReader(new FileReader(args[0]))) {
            String [] parts = new String[5];
            String line, prevLine = "", hash, type, blockString, addr;
            boolean isValid;
            int i = 0, n = 0, c = 0;
            while ((line = br.readLine()) != null) {
                parts = line.split(",");
                type = parts[1];
                if (type.equalsIgnoreCase("CREATE")) {
                    //check if genesis block
                    if (!parts[0].equals("0")) {
                        //SHA256 HASH OF PREVIOUS LINE
                        hash = calculateHash(prevLine);
                        if (!hash.equalsIgnoreCase(parts[0])) {
                            //invalid hash
                            System.out.println("Blockchain can't be read. Invalid hash on line "+(i+1));
                            System.exit(1);
                        }
                    }
                    //verify coin name
                    isValid = verifyMessage(parts[2], parts[3], "3081f03081a806072a8648ce38040130819c024100fca682ce8e12caba26efccf7110e526db078b05edecbcd1eb4a208f3ae1617ae01f35b91a47e6df63413c5e12ed0899bcd132acd50d99151bdc43ee737592e17021500962eddcc369cba8ebb260ee6b6a126d9346e38c50240678471b27a9cf44ee91a49c5147db1a9aaf244f05a434d6486931d2d14271b9e35030b71fd73da179069b32e2935630e1c2062354d0da20a6c416e50be794ca403430002405b0656317dd257ec71982519d38b42c02621290656eba54c955704e9b5d606062ec663bdeef8b79daa2631287d854da77c05d3e178c101b2f0a1dbbe5c7d5e10");
                    if (isValid) {
                        blockString = parts[0]+","+parts[1]+","+parts[2]+","+parts[3];
                        isValid = verifyMessage(blockString, parts[4], "3081f03081a806072a8648ce38040130819c024100fca682ce8e12caba26efccf7110e526db078b05edecbcd1eb4a208f3ae1617ae01f35b91a47e6df63413c5e12ed0899bcd132acd50d99151bdc43ee737592e17021500962eddcc369cba8ebb260ee6b6a126d9346e38c50240678471b27a9cf44ee91a49c5147db1a9aaf244f05a434d6486931d2d14271b9e35030b71fd73da179069b32e2935630e1c2062354d0da20a6c416e50be794ca403430002405b0656317dd257ec71982519d38b42c02621290656eba54c955704e9b5d606062ec663bdeef8b79daa2631287d854da77c05d3e178c101b2f0a1dbbe5c7d5e10");
                        if(isValid) {
                            System.out.println("Block is valid");                       
                            blocks[i] = blockchain.addBlock(line);
                            output[c][0] = parts[2];
                            output[c][1] = "3081f03081a806072a8648ce38040130819c024100fca682ce8e12caba26efccf7110e526db078b05edecbcd1eb4a208f3ae1617ae01f35b91a47e6df63413c5e12ed0899bcd132acd50d99151bdc43ee737592e17021500962eddcc369cba8ebb260ee6b6a126d9346e38c50240678471b27a9cf44ee91a49c5147db1a9aaf244f05a434d6486931d2d14271b9e35030b71fd73da179069b32e2935630e1c2062354d0da20a6c416e50be794ca403430002405b0656317dd257ec71982519d38b42c02621290656eba54c955704e9b5d606062ec663bdeef8b79daa2631287d854da77c05d3e178c101b2f0a1dbbe5c7d5e10";
                            c++;
                        }
                        else {
                            System.out.print("Blockchain can't be read.");
                            System.exit(1);
                        }
                    }
                    else {
                        System.out.print("Blockchain can't be read.");
                        System.exit(1);
                    }
                }
                else if (type.equalsIgnoreCase("TRANSFER")) {
                    hash = calculateHash(prevLine);
                    if (!hash.equalsIgnoreCase(parts[0])) {
                        //invalid hash
                        System.out.println("Blockchain can't be read. Invalid hash on line "+(i+1));
                        System.exit(1);
                    }

                    String test;
                    String[] targetCoin = new String[5];
                    n = i;
                    do {
                        test = blocks[n-1].getDataAsString();
                        targetCoin = test.split(",");
                        n--;
                    } while (!targetCoin[2].equals(parts[2]) && n >= 1);
                    if (!targetCoin[2].equals(parts[2])) {
                        System.out.print("Blockchain can't be read.");
                        System.exit(1);
                    }
                    if (targetCoin[1].equalsIgnoreCase("CREATE")) {
                        //this coin has not been transferred yet, verify transfer with bill's PK
                        addr = "3081f03081a806072a8648ce38040130819c024100fca682ce8e12caba26efccf7110e526db078b05edecbcd1eb4a208f3ae1617ae01f35b91a47e6df63413c5e12ed0899bcd132acd50d99151bdc43ee737592e17021500962eddcc369cba8ebb260ee6b6a126d9346e38c50240678471b27a9cf44ee91a49c5147db1a9aaf244f05a434d6486931d2d14271b9e35030b71fd73da179069b32e2935630e1c2062354d0da20a6c416e50be794ca403430002405b0656317dd257ec71982519d38b42c02621290656eba54c955704e9b5d606062ec663bdeef8b79daa2631287d854da77c05d3e178c101b2f0a1dbbe5c7d5e10";
                    }
                    else {
                        //this coin has been transferred. the last valid transfer contains the PK of the original owner
                        addr = targetCoin[3];
                    }
                    blockString = parts[0]+","+parts[1]+","+parts[2]+","+parts[3];
                    //iterate the block chain to find last reference of coin. if it was the create statement use Bills PK, otherwise use the address the coin was transferred to
                        isValid = verifyMessage(blockString, parts[4], addr);
                        if(isValid) {
                            System.out.println("Block is valid");                         
                            blocks[i] = blockchain.addBlock(line);
                            //System.out.println(parts[2]+" sent to "+parts[3]);
                            for (int j = 0; j < c; j++) {
                                if (output[j][0].equalsIgnoreCase(parts[2])) {
                                    output[j][1] = parts[3];
                                }
                            }
                        }
                        else {
                            System.out.print("Blockchain can't be read.");
                            System.exit(1);
                        }
                }
                prevLine = line;
                i++;
            }
            boolean blockchainGood = blockchain.iterateAndVerify();
            if (blockchainGood) {
                for (int j = 0; j < c; j++) {
                    System.out.println("Coin "+output[j][0]+" / Owner = "+output[j][1]);
                }
            }
            else {
                System.out.println("Error reading blockchain");
                System.exit(1);
            }
        }
        catch (FileNotFoundException e) {
            System.out.println("Enter a valid blockchain");
        }
        catch (IOException ioe) {
            System.out.println("Enter a valid blockchain");          
        }
    }

    public static KeyPair getKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
        SecureRandom random = new SecureRandom(); // .getInstance("SHA1PRNG", "SUN");
        keyGen.initialize(1024, random);
        return keyGen.generateKeyPair();
    }

    public static byte[] convertHexToBytes(String hex) throws Exception{
        byte[] bytes = new byte[hex.length() / 2];
        int c = 0;
        for (int j = 0; j < hex.length(); j += 2) {
            String twoHex = hex.substring(j, j + 2);
            byte byteVal = (byte) Integer.parseInt(twoHex, 16);
            bytes[c++] = byteVal;
        }
        return bytes;
    }

    public static String convertBytesToHexString(byte[] bytes) throws Exception{
        StringBuffer toReturn = new StringBuffer();
        for (int j = 0; j < bytes.length; j++) {
            String hexit = String.format("%02x", bytes[j]);
            toReturn.append(hexit);
        }
        return toReturn.toString();
    }

    public static String calculateHash(String x) throws Exception{
        if (x == null) {
            return "0";
        }
        byte[] hash = null;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            hash = digest.digest(x.getBytes());
        } catch (NoSuchAlgorithmException nsaex) {
            System.err.println("No SHA-256 algorithm found.");
            System.err.println("This generally should not happen...");
            System.exit(1);
        }
        return convertBytesToHexString(hash);
    }

    public static PublicKey loadPublicKey(String stored) throws Exception {
        byte[] data = convertHexToBytes(stored);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
        KeyFactory fact = KeyFactory.getInstance("DSA");
        return fact.generatePublic(spec);
    }

    public static PrivateKey loadPrivateKey(String stored) throws Exception {
        byte[] data = convertHexToBytes(stored);
        KeyFactory keyFactory=KeyFactory.getInstance("DSA");
        PrivateKey privKey=keyFactory.generatePrivate(new PKCS8EncodedKeySpec(data));
        return privKey;
    }

    public static String signMessage(String msg, String key) throws Exception {
        PrivateKey sk = loadPrivateKey(key);
        byte[] sigBytes = sign(msg, sk);
        String toReturn = convertBytesToHexString(sigBytes);
        return toReturn;
    }

    public static boolean verifyMessage(String msg, String sig, String key) throws Exception {
        PublicKey pk = loadPublicKey(key);
        byte[] sigBytes = convertHexToBytes(sig);
        boolean toReturn = verify(msg, sigBytes, pk);
        return toReturn;
    }

    public static byte[] sign(String toSign, PrivateKey sk) throws Exception {
        Signature dsa = Signature.getInstance("SHA1withDSA", "SUN");
        dsa.initSign(sk);

        byte[] bytes = toSign.getBytes();
        dsa.update(bytes, 0, bytes.length);
        byte[] sig = dsa.sign();
        return sig;
    }

    public static boolean verify(String toCheck, byte[] sig, PublicKey pk)
        throws Exception {
        Signature sig2 = Signature.getInstance("SHA1withDSA", "SUN");
        byte[] bytes = toCheck.getBytes();
        sig2.initVerify(pk);
        sig2.update(bytes, 0, bytes.length);
        return sig2.verify(sig);
    }
}

//PREV,CREATE,COIN,COINSIG,SIG

//PREV,TRANSFER,COIN,PK,SIG