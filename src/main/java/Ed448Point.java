/**
 * Ed448Point.java
 * @author Griffin Ryan (glryan@uw.edu)
 */
import java.math.BigInteger;
import java.util.Arrays;

public class Ed448Point {
    
    private static final BigInteger P = new BigInteger("2").pow(448).subtract(new BigInteger("2").pow(224)).subtract(BigInteger.ONE);
    private static final BigInteger D = new BigInteger("-39081");
    private static final BigInteger Y0 = P.subtract(BigInteger.valueOf(3));
    private static final BigInteger X0 = calculateX0(Y0);

    private BigInteger x;
    private BigInteger y;

    // Constructor for the neutral element
    public Ed448Point() {
        this.x = BigInteger.ZERO;
        this.y = BigInteger.ONE;
    }

    // Constructor for a point given x and y
    public Ed448Point(BigInteger x, BigInteger y) {
        this.x = x.mod(P);
        this.y = y.mod(P);
    }

    // Constructor that accepts a byte array for uncompressed format
    public Ed448Point(byte[] publicKeyBytes) throws Exception {
        if (publicKeyBytes.length != 112) { // 56 bytes for x + 56 bytes for y
            throw new IllegalArgumentException("Invalid public key byte array length");
        }
        byte[] xBytes = Arrays.copyOfRange(publicKeyBytes, 0, 56);
        byte[] yBytes = Arrays.copyOfRange(publicKeyBytes, 56, 112);

        this.x = new BigInteger(1, xBytes);
        this.y = new BigInteger(1, yBytes);
    }

    // Method to calculate x0 given y0
    private static BigInteger calculateX0(BigInteger y0) {
        // Assuming y is given, rearrange the curve equation to find x²
        BigInteger ySquared = y0.multiply(y0).mod(P);
        BigInteger denominator = BigInteger.ONE.subtract(D.multiply(ySquared)).mod(P);
        BigInteger numerator = BigInteger.ONE.subtract(ySquared).mod(P);
        BigInteger xSquared = numerator.multiply(denominator.modInverse(P)).mod(P);

        // Now find the square root of xSquared modulo P
        BigInteger x0 = sqrtModP(xSquared, P);

        return x0;
    }

    // Method to find the square root of a number modulo a prime
    // Tonelli-Shanks algorithm to compute square roots modulo a prime number
    private static BigInteger sqrtModP(BigInteger n, BigInteger p) {
        if (n.equals(BigInteger.ZERO)) {
            return BigInteger.ZERO;
        }

        // Check if n is a quadratic residue modulo p
        if (!n.modPow(p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2)), p).equals(BigInteger.ONE)) {
            return null; // No solution exists
        }

        BigInteger q = p.subtract(BigInteger.ONE);
        BigInteger ss = BigInteger.ZERO;
        while (q.mod(BigInteger.valueOf(2)).equals(BigInteger.ZERO)) {
            ss = ss.add(BigInteger.ONE);
            q = q.divide(BigInteger.valueOf(2));
        }

        if (ss.equals(BigInteger.ONE)) {
            return n.modPow(p.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), p);
        }

        BigInteger z;
        for (z = BigInteger.TWO; !z.modPow(p.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2)), p).equals(p.subtract(BigInteger.ONE)); z = z.add(BigInteger.ONE));

        BigInteger c = z.modPow(q, p);
        BigInteger r = n.modPow(q.add(BigInteger.ONE).divide(BigInteger.valueOf(2)), p);
        BigInteger t = n.modPow(q, p);
        BigInteger m = ss;

        while (true) {
            if (t.equals(BigInteger.ONE)) {
                return r;
            }
            BigInteger i = BigInteger.ONE;
            BigInteger zz = t.modPow(BigInteger.valueOf(2), p);
            while (!zz.equals(BigInteger.ONE) && i.compareTo(m) < 0) {
                zz = zz.modPow(BigInteger.valueOf(2), p);
                i = i.add(BigInteger.ONE);
            }
            BigInteger b = c.modPow(BigInteger.ONE.shiftLeft(m.subtract(i).subtract(BigInteger.ONE).intValue()), p);
            r = r.multiply(b).mod(p);
            c = b.modPow(BigInteger.valueOf(2), p);
            t = t.multiply(c).mod(p);
            m = i;
        }
    }

    // Method to check if two points are equal
    public boolean isEqual(Ed448Point other) {
        return this.x.equals(other.x) && this.y.equals(other.y);
    }

    // Method to get the opposite of the point
    public Ed448Point negate() {
        return new Ed448Point(this.x.negate().mod(P), this.y);
    }

    // Method to add two points on the curve
    public Ed448Point add(Ed448Point other) {
        BigInteger x1y2 = this.x.multiply(other.y).mod(P);
        BigInteger y1x2 = this.y.multiply(other.x).mod(P);
        BigInteger x1x2 = this.x.multiply(other.x).mod(P);
        BigInteger y1y2 = this.y.multiply(other.y).mod(P);

        BigInteger numeratorX = x1y2.add(y1x2).mod(P);
        BigInteger denominatorX = BigInteger.ONE.add(D.multiply(x1x2).multiply(y1y2)).mod(P);
        BigInteger newX = numeratorX.multiply(denominatorX.modInverse(P)).mod(P);

        BigInteger numeratorY = y1y2.subtract(x1x2).mod(P);
        BigInteger denominatorY = BigInteger.ONE.subtract(D.multiply(x1x2).multiply(y1y2)).mod(P);
        BigInteger newY = numeratorY.multiply(denominatorY.modInverse(P)).mod(P);

        return new Ed448Point(newX, newY);
    }

    // Scalar multiplication using the double-and-add method
    public Ed448Point scalarMultiply(BigInteger k) {
        Ed448Point result = new Ed448Point(); // neutral element
        Ed448Point base = this;

        while (!k.equals(BigInteger.ZERO)) {
            if (k.testBit(0)) { // if the least significant bit of k is 1
                result = result.add(base);
            }
            base = base.add(base);
            k = k.shiftRight(1); // divide k by 2
        }

        return result;
    }

    public byte[] toBytes() {
        byte[] xBytes = this.x.toByteArray();
        byte[] yBytes = this.y.toByteArray();

        // Ensure each coordinate is 56 bytes (448 bits), prepend with zeros if necessary
        xBytes = adjustArrayLength(xBytes, 56);
        yBytes = adjustArrayLength(yBytes, 56);

        // Combine the two arrays
        byte[] combined = new byte[112];
        System.arraycopy(xBytes, 0, combined, 0, 56);
        System.arraycopy(yBytes, 0, combined, 56, 56);

        return combined;
    }

    private byte[] adjustArrayLength(byte[] array, int length) {
        if (array.length == length) {
            return array;
        }
        byte[] newArray = new byte[length];
        int start = length - array.length;
        System.arraycopy(array, 0, newArray, start, array.length);
        return newArray;
    }

    // toString method for easy representation
    @Override
    public String toString() {
        return "(" + x.toString(16) + ", " + y.toString(16) + ")";
    }

    public BigInteger getY() {
        return this.y;
    }

    public BigInteger getX() {
        return this.x;
    }

}
