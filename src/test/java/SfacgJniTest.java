import org.junit.Test;
import org.peyilo.sfsecurity.SfacgJni;

public class SfacgJniTest {

    @Test
    public void test1() {
        SfacgJni sfacgJni = new SfacgJni();
        String sfSecurity = sfacgJni.getSFSecurity("a");
        System.out.printf(sfSecurity);
    }
}
