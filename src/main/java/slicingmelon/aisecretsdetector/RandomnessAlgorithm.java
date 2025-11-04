/**
 * AI Secrets Detector
 * 
 * Author: Petru Surugiu <@pedro_infosec>
 * https://github.com/slicingmelon/
 * This extension is a Burp Suite extension that uses a dual-detection approach combining fixed patterns and a randomness analysis algorithm to find exposed secrets with minimal false positives.
 */
package slicingmelon.aisecretsdetector;
import burp.api.montoya.core.ByteArray;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Randomness detection algorithm ported from RipSecrets
 * Used to determine if a byte sequence is likely to be a random string (secret)
 * 
 * Performance optimizations for hot-path (concurrent threads, thousands of requests, millions of bytes):
 * - Static bigram lookup table (65,536 entries) for O(1) bigram matching
 * - Updated bigram list (500+ bigrams) for accurate calibration
 * - Byte-level operations with getBytes() to minimize allocations
 * - Static character class arrays to avoid per-call allocation
 * - Zero-allocation countDistinctValues using boolean[256] bitmap
 * - Thread-safe memoization with ConcurrentHashMap (non-recursive put)
 * - Log-space arithmetic for pRandomDistinctValues to prevent overflow
 * - Direct factorial calculations for pBinomial (matches Rust exactly)
 */
public class RandomnessAlgorithm {
    
    // Thread-safe memoization cache for configuration calculations
    private static final ConcurrentMap<Long, Double> configCache = new ConcurrentHashMap<>();

    // THREAD-LOCAL CACHE FOR countDistinctValues
    // Avoid allocating a new int[256] on every call in a hot path.
    // Use an "epoch marker" to avoid even clearing the array.
    private static final ThreadLocal<int[]> TL_SEEN = ThreadLocal.withInitial(() -> new int[256]);
    private static final ThreadLocal<Integer> TL_MARKER = ThreadLocal.withInitial(() -> 1);
    
    // BIGRAM TABLE (STATIC, INITIALIZED ONCE)
    private static final boolean[] BIGRAM_TABLE = new boolean[1 << 16]; // 65536 entries
    private static final double BIGRAM_P; // Probability: |bigrams| / (64 * 64)
    
    // Full bigram list from RipSecrets p_random.rs for accurate calibration
    static {
        final String BIGRAM_CSV =
            "er,te,an,en,ma,ke,10,at,/m,on,09,ti,al,io,.h,./,..,ra,ht,es,or,tm,pe,ml,re,in,3/,n3,0F,ok," +
            "ey,00,80,08,ss,07,15,81,F3,st,52,KE,To,01,it,2B,2C,/E,P_,EY,B7,se,73,de,VP,EV,to,od,B0,0E,nt," +
            "et,_P,A0,60,90,0A,ri,30,ar,C0,op,03,ec,ns,as,FF,F7,po,PK,la,.p,AE,62,me,F4,71,8E,yp,pa,50,qu," +
            "D7,7D,rs,ea,Y_,t_,ha,3B,c/,D2,ls,DE,pr,am,E0,oc,06,li,do,id,05,51,40,ED,_p,70,ed,04,02,t.,rd," +
            "mp,20,d_,co,ro,ex,11,ua,nd,0C,0D,D0,Eq,le,EF,wo,e_,e.,ct,0B,_c,Li,45,rT,pt,14,61,Th,56,sT,E6," +
            "DF,nT,16,85,em,BF,9E,ne,_s,25,91,78,57,BE,ta,ng,cl,_t,E1,1F,y_,xp,cr,4F,si,s_,E5,pl,AB,ge,7E," +
            "F8,35,E2,s.,CF,58,32,2F,E7,1B,ve,B1,3D,nc,Gr,EB,C6,77,64,sl,8A,6A,_k,79,C8,88,ce,Ex,5C,28,EA," +
            "A6,2A,Ke,A7,th,CA,ry,F0,B6,7/,D9,6B,4D,DA,3C,ue,n7,9C,.c,7B,72,ac,98,22,/o,va,2D,n.,_m,B8,A3," +
            "8D,n_,12,nE,ca,3A,is,AD,rt,r_,l-,_C,n1,_v,y.,yw,1/,ov,_n,_d,ut,no,ul,sa,CT,_K,SS,_e,F1,ty,ou," +
            "nG,tr,s/,il,na,iv,L_,AA,da,Ty,EC,ur,TX,xt,lu,No,r.,SL,Re,sw,_1,om,e/,Pa,xc,_g,_a,X_,/e,vi,ds," +
            "ai,==,ts,ni,mg,ic,o/,mt,gm,pk,d.,ch,/p,tu,sp,17,/c,ym,ot,ki,Te,FE,ub,nL,eL,.k,if,he,34,e-,23," +
            "ze,rE,iz,St,EE,-p,be,In,ER,67,13,yn,ig,ib,_f,.o,el,55,Un,21,fi,54,mo,mb,gi,_r,Qu,FD,-o,ie,fo," +
            "As,7F,48,41,/i,eS,ab,FB,1E,h_,ef,rr,rc,di,b.,ol,im,eg,ap,_l,Se,19,oS,ew,bs,Su,F5,Co,BC,ud,C1," +
            "r-,ia,_o,65,.r,sk,o_,ck,CD,Am,9F,un,fa,F6,5F,nk,lo,ev,/f,.t,sE,nO,a_,EN,E4,Di,AC,95,74,1_,1A," +
            "us,ly,ll,_b,SA,FC,69,5E,43,um,tT,OS,CE,87,7A,59,44,t-,bl,ad,Or,D5,A_,31,24,t/,ph,mm,f.,ag,RS," +
            "Of,It,FA,De,1D,/d,-k,lf,hr,gu,fy,D6,89,6F,4E,/k,w_,cu,br,TE,ST,R_,E8,/O";
        
        int count = 0;
        for (String bg : BIGRAM_CSV.split(",")) {
            if (bg.length() != 2) continue;
            int b1 = bg.charAt(0) & 0xFF;
            int b2 = bg.charAt(1) & 0xFF;
            int idx = (b1 << 8) | b2;
            BIGRAM_TABLE[idx] = true;
            count++;
        }
        BIGRAM_P = count / (64.0 * 64.0);
    }
    
    
    // ========== CHARACTER CLASS RANGES (STATIC) ==========
    // Avoid allocation per call in hot path
    private static final byte[][] CLASSES_36 = {
        {(byte)'0', (byte)'9'}, 
        {(byte)'A', (byte)'Z'}
    };
    
    private static final byte[][] CLASSES_64 = {
        {(byte)'0', (byte)'9'}, 
        {(byte)'A', (byte)'Z'}, 
        {(byte)'a', (byte)'z'}
    };
    
    /**
     * Determines if a byte sequence is likely to be a random string (secret)
     * Ported from RipSecrets p_random.rs
     */
    public static boolean isRandom(ByteArray data) {
        // Check if the data is valid
        if (data == null || data.length() < SecretScannerUtils.getGenericSecretMinLength()) {
            return false;
        }
        
        double p = pRandom(data);
        if (p < 1.0 / 1e5) {
            return false;
        }
        
        boolean containsDigit = false;
        for (int i = 0; i < data.length(); i++) {
            byte b = data.getByte(i);
            if (b >= '0' && b <= '9') {
                containsDigit = true;
                break;
            }
        }
        
        if (!containsDigit && p < 1.0 / 1e4) {
            return false;
        }
        
        return true;
    }

    /**
     * Calculates the probability that a byte sequence is random
     * Ported from RipSecrets
     */
    private static double pRandom(ByteArray data) {
        double base;
        if (isHex(data)) {
            base = 16.0;
        } else if (isCapAndNumbers(data)) {
            base = 36.0;
        } else {
            base = 64.0;
        }
        
        double p = pRandomDistinctValues(data, base) * pRandomCharClass(data, base);
        
        // Bigram analysis only works reliably for base64
        if (base == 64.0) {
            p *= pRandomBigrams(data);
        }
        
        return p;
    }
    
    /**
     * Checks if a byte sequence consists only of hex characters (0-9, a-f, A-F)
     * and is at least 16 bytes long
     */
    private static boolean isHex(ByteArray data) {
        if (data.length() < 16) {
            return false;
        }
        
        for (int i = 0; i < data.length(); i++) {
            byte b = data.getByte(i);
            if (!((b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F'))) {
                return false;
            }
        }
        return true;
    }

    /**
     * Checks if a byte sequence consists only of capital letters and numbers (0-9, A-Z)
     * and is at least 16 bytes long
     */
    private static boolean isCapAndNumbers(ByteArray data) {
        if (data.length() < 16) {
            return false;
        }
        
        for (int i = 0; i < data.length(); i++) {
            byte b = data.getByte(i);
            if (!((b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z'))) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Analyzes character classes to determine randomness
     * Optimized to use static character class arrays
     */
    private static double pRandomCharClass(ByteArray data, double base) {
        if (base == 16.0) {
            return pRandomCharClassAux(data, (byte)'0', (byte)'9', 16.0);
        }
        
        double minP = Double.POSITIVE_INFINITY;
        byte[][] classes = (base == 36.0) ? CLASSES_36 : CLASSES_64;
        
        for (byte[] c : classes) {
            double p = pRandomCharClassAux(data, c[0], c[1], base);
            if (p < minP) {
                minP = p;
            }
        }
        
        return minP;
    }
    
    /**
     * Calculates randomness probability for a specific character class
     * Optimized with getBytes() for hot-path performance
     * NOTE: Uses < max (not <=) to match Rust's calibration
     */
    private static double pRandomCharClassAux(ByteArray data, byte min, byte max, double base) {
        int count = 0;
        int n = data.length();
        
        for (int i = 0; i < n; i++) {
            byte b = data.getByte(i);
            if (b >= min && b < max) {
                count++;
            }
        }
        
        double numChars = (max - min + 1);
        return pBinomial(n, count, numChars / base);
    }
    
    /**
     * Calculates binomial probability in a numerically stable way using logs.
     * This avoids overflow issues with large factorials.
     * GG version
     */
    private static double pBinomial(int n, int x, double p) {
        if (p < 0.0 || p > 1.0 || x < 0 || x > n) {
            return 0.0;
        }

        boolean leftTail = x < n * p;
        int min = leftTail ? 0 : x;
        int max = leftTail ? x : n;

        // Handle edge cases where logs would fail
        if (p == 0.0) return (min == 0) ? 1.0 : 0.0;
        if (p == 1.0) return (max == n) ? 1.0 : 0.0;

        double totalP = 0.0;
        double logP = Math.log(p);
        double logOneMinusP = Math.log(1.0 - p);

        // Start with the log probability of the first term (min)
        double logProb = logCombination(n, min) + (min * logP) + ((n - min) * logOneMinusP);

        for (int i = min; i <= max; i++) {
            totalP += Math.exp(logProb);

            // Efficiently calculate the next term's log probability from the current one
            if (i < max) {
                logProb += Math.log(n - i) - Math.log(i + 1) + logP - logOneMinusP;
            }
        }

        return totalP;
    }

    /**
     * Calculates the log of the binomial coefficient "n choose k" (nCk).
     * This is used as part of the stable pBinomial calculation.
     * GG version
     */
    private static double logCombination(int n, int k) {
        if (k < 0 || k > n) {
            return Double.NEGATIVE_INFINITY; // Log of zero
        }
        if (k == 0 || k == n) {
            return 0.0; // Log of one
        }
        // Choose the smaller of k and n-k for fewer iterations
        if (k > n / 2) {
            k = n - k;
        }

        double res = 0.0;
        for (int i = 1; i <= k; i++) {
            res += Math.log(n - i + 1) - Math.log(i);
        }
        return res;
    }
    
    /**
     * Numerically stable log(exp(a) + exp(b))
     * Used to add probabilities in log space for pRandomDistinctValues
     */
    private static double logAddExp(double a, double b) {
        if (a == Double.NEGATIVE_INFINITY) return b;
        if (b == Double.NEGATIVE_INFINITY) return a;
        if (a < b) {
            double t = a;
            a = b;
            b = t;
        }
        return a + Math.log1p(Math.exp(b - a));
    }
    
    /**
     * Calculates randomness based on bigram frequencies
     * Optimized version using static lookup table and byte-level operations
     * Zero allocations per iteration for hot-path performance
     */
    private static double pRandomBigrams(ByteArray data) {
        int n = data.length();
        
        if (n < 2) {
            // Match Rust behavior: call pBinomial with n = length
            return pBinomial(n, 0, BIGRAM_P);
        }
        
        int numBigrams = 0;
        for (int i = 0; i < n - 1; i++) {
            int idx = ((data.getByte(i) & 0xFF) << 8) | (data.getByte(i + 1) & 0xFF);
            if (BIGRAM_TABLE[idx]) {
                numBigrams++;
            }
        }
        
        // IMPORTANT: Match Rust calibration - use data.length(), not data.length() - 1
        return pBinomial(n, numBigrams, BIGRAM_P);
    }
    
    /**
     * Calculates randomness probability based on distinct values
     * Uses log-space arithmetic to prevent overflow
     */
    private static double pRandomDistinctValues(ByteArray data, double base) {
        int n = data.length();
        double logTotal = n * Math.log(base);
        int numDistinctValues = countDistinctValues(data);
        
        double logSum = Double.NEGATIVE_INFINITY;
        for (int i = 1; i <= numDistinctValues; i++) {
            double termLog = logNumPossibleOutcomes(n, i, (int) base);
            logSum = logAddExp(logSum, termLog);
        }
        
        if (!Double.isFinite(logSum)) return 0.0;
        
        double logP = logSum - logTotal;
        if (logP > 0.0) return 1.0; // clamp
        
        return Math.exp(logP);
    }
    
    /**
     * Counts distinct values in a byte array
     * Optimized with bitmap to avoid boxing overhead and ThreadLocal to avoid allocation.
     */
    private static int countDistinctValues(ByteArray data) {
        int[] seen = TL_SEEN.get();
        int marker = TL_MARKER.get();
        int distinct = 0;
        int n = data.length();

        for (int i = 0; i < n; i++) {
            int v = data.getByte(i) & 0xFF;
            if (seen[v] != marker) {
                seen[v] = marker;
                distinct++;
            }
        }

        // Increment marker for the next call on this thread.
        // Wrap around if it approaches MAX_VALUE to avoid overflow.
        marker++;
        if (marker == Integer.MAX_VALUE) {
            marker = 1; // Reset to 1, 0 is the default array value
        }
        TL_MARKER.set(marker);

        return distinct;
    }
    
    /**
     * Calculates log of number of possible outcomes
     * Uses log space to prevent overflow
     */
    private static double logNumPossibleOutcomes(int numValues, int numDistinctValues, int base) {
        double logPerm = Math.log(base);
        for (int i = 1; i < numDistinctValues; i++) {
            logPerm += Math.log(base - i);
        }
        double configs = numDistinctConfigurations(numValues, numDistinctValues);
        // configs fits in double range here; if worried, you could compute its log too
        double logConfigs = Math.log(configs);
        return logPerm + logConfigs;
    }
    
    /**
     * Calculates number of distinct configurations
     */
    private static double numDistinctConfigurations(int numValues, int numDistinctValues) {
        if (numDistinctValues == 1 || numDistinctValues == numValues) {
            return 1.0;
        }
        return numDistinctConfigurationsAux(numDistinctValues, 0, numValues - numDistinctValues);
    }
    
    /**
     * Recursive helper for distinct configurations calculation
     * Thread-safe memoized version - compute first, then cache
     * GG version
     */
    private static double numDistinctConfigurationsAux(int numPositions, int position, int remainingValues) {
        if (remainingValues == 0) {
            return 1.0;
        }
        
        // Use a packed long as a key to avoid String allocation in this hot, recursive path.
        // Assumes numPositions and position fit within 16 bits, remainingValues in 32 bits.
        final long key = ((long) numPositions << 48) | ((long) position << 32) | remainingValues;
        
        // Check cache first
        Double cached = configCache.get(key);
        if (cached != null) {
            return cached;
        }
        
        // Compute outside of map modification
        double numConfigs = 0.0;
        if (position + 1 < numPositions) {
            numConfigs += numDistinctConfigurationsAux(numPositions, position + 1, remainingValues);
        }
        numConfigs += (position + 1) * numDistinctConfigurationsAux(numPositions, position, remainingValues - 1);
        
        // Cache after computation (safe now)
        configCache.put(key, numConfigs);
        return numConfigs;
    }
}
