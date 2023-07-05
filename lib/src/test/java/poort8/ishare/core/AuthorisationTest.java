package poort8.ishare.core;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class AuthorisationTest {
    @Test void VerifyAccessReturnsTrue() {
        assertTrue(Authorisation.VerifyAccess(), "VerifyAccessReturnsTrue should return 'true'");
    }
}
