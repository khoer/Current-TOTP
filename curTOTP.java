import java.lang.reflect.UndeclaredThrowableException;
import java.security.GeneralSecurityException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;

/** 
 *This code can be used for get TOTP current time with up to 18-digits TOTP. 
 *(10-digits must be enough)
 *Reference: https://tools.ietf.org/html/rfc6238 
 */
public class curTOTP {
    public curTOTP() {
    }
    
    private static byte[] hmac_sha(String crypto, byte[] keyBytes, byte[] text){
        try {
            Mac hmacsha = Mac.getInstance(crypto);
            SecretKeySpec macKey =
                new SecretKeySpec(keyBytes, crypto);
            hmacsha.init(macKey);
            byte[] mac_data = hmacsha.doFinal(text);
            return mac_data;
        }catch (GeneralSecurityException gse) {
            throw new UndeclaredThrowableException(gse);
        }
    }
    
    private static byte[] hexStr2Bytes(String hex){
        byte[] bArray = new BigInteger("10" + hex,16).toByteArray();
        byte[] ret = new byte[bArray.length - 1];
        for (int i = 0; i < ret.length; i++)
            ret[i] = bArray[i+1];
        return ret;
    }
    
    static final long TEST_TIME = System.currentTimeMillis()/1000;
        
    static String step(){
        long T0 = 0;
        long X = 30;
        String steps = "0";
        long T = (TEST_TIME - T0)/X;
        steps = Long.toHexString(T).toUpperCase();
        while (steps.length() < 16) steps = "0" + steps;
        return steps;
    }
                                             // 0 1  2   3    4     5     
    private static final long[] DIGITS_POWER = {1,10,100,1000,10000,100000,
      //6       7        8         9          10           11
    	1000000,10000000,100000000,1000000000,10000000000L,100000000000L,
      //12             13              14               15                
    	1000000000000L,10000000000000L,100000000000000L,1000000000000000L,
      //16                 17	               18
    	10000000000000000L,100000000000000000L,1000000000000000000L
    };
    
    public static String generateTOTP(String key, String returnDigits){
        return generateTOTP(key, returnDigits, "HmacSHA1");
    }
    
    public static String generateTOTP256(String key, String returnDigits){
        return generateTOTP(key, returnDigits, "HmacSHA256");
    }
    
    public static String generateTOTP512(String key, String returnDigits){
        return generateTOTP(key, returnDigits, "HmacSHA512");
    }
    
    public static String generateTOTP(String key, String returnDigits, String crypto){
        int codeDigits = Integer.decode(returnDigits).intValue();
        String result = null;
        String time = step();
        while (time.length() < 16 )
            time = "0" + time;
        byte[] msg = hexStr2Bytes(time);
        byte[] k = key.getBytes();//hexStr2Bytes(key);
        byte[] hash = hmac_sha(crypto, k, msg);
        int offset = hash[hash.length - 1] & 0xf;
        int binary = ((hash[offset] & 0x7f) << 24) |
            ((hash[offset + 1] & 0xff) << 16) |
            ((hash[offset + 2] & 0xff) << 8) |
            (hash[offset + 3] & 0xff);
        long otp = binary % DIGITS_POWER[codeDigits];
        result = Long.toString(otp);
        while (result.length() < codeDigits) {
            result = "0" + result;
        }
        return result;
    }
}
