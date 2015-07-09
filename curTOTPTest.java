import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

/**
 * Program for testing cur TOTP (UTC time)
 *
 */

public class curTOTPTest {

	public static void main(String[] args) {
		curTOTP totp = new curTOTP();
		
		String seed = "SomeToken";
        String seed32 = "SomeToken";
        String seed64 = "SomeToken";
        DateFormat df = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        df.setTimeZone(TimeZone.getTimeZone("UTC"));
		try {
	        System.out.println("+---------------+-----------------------+" +
	        	"------------------+----------+--------+");
	        System.out.println("|  Time(sec)    |   Time (UTC format)   " +
	          	"| Value of T(Hex)  |   TOTP   | Mode   |");
	        System.out.println("+---------------+-----------------------+" +
	           	"------------------+----------+--------+");
	        String fmtTime = String.format("%1$-11s", totp.TEST_TIME);
	        String utcTime = df.format(new Date(totp.TEST_TIME*1000));
	        String gt1 = totp.generateTOTP(seed, "10", "HmacSHA1");
	        String gt256 = totp.generateTOTP(seed32, "10", "HmacSHA256");
	        String gt512 = totp.generateTOTP(seed64, "10", "HmacSHA512");
	        System.out.println("|  " + fmtTime + "  |  " + utcTime + "  | " +
	          	totp.step() + " |" + gt1 + "| SHA1   |");
	        System.out.println("|  " + fmtTime + "  |  " + utcTime + "  | " +
	          	totp.step() + " |" + gt256 + "| SHA256 |");
	        System.out.println("|  " + fmtTime + "  |  " + utcTime + "  | " +
	           	totp.step() + " |" + gt512 + "| SHA512 |");
	        System.out.println("+---------------+-----------------------+" +
	           	"------------------+----------+--------+");
	    }catch (final Exception e){
	        System.out.println("Error : " + e);
	    }
	}
}
