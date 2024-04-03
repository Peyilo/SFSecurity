import org.junit.Test;
import org.peyilo.sfsecurity.SfacgJni;

public class SfacgJniTest {

    /**
     * 新版盐值：FN_Q29XHVmfV3mYX
     * 旧版盐值：FMLxgOdsfxmN!Dt4
     *
     * 新版结果：
     * nonce=6E72CFB2-2DE1-4123-A4B1-8EF4D9414A62
     * &timestamp=1712106953992
     * &devicetoken=a
     * &sign=51A02F1DC8EEDF6B4E10BD07981F634C
     *
     * 旧版结果：
     * nonce=6E72CFB2-2DE1-4123-A4B1-8EF4D9414A62
     * &timestamp=1712106953992
     * &devicetoken=a
     * &sign=F1648CB37D4410A2B437F4CB011E8791
     */
    @Test
    public void test1() {
        SfacgJni sfacgJni = new SfacgJni();
        String sfSecurity = sfacgJni.getSFSecurity("a");
        System.out.printf(sfSecurity);
    }
}
