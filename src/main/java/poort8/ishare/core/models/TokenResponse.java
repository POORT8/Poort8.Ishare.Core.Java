package poort8.ishare.core.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import javax.annotation.Nullable;

public class TokenResponse {
    @JsonProperty("access_token")
    public @Nullable String AccessToken;
    @JsonProperty("token_type")
    public @Nullable String TokenType;
    @JsonProperty("expires_in")
    public int ExpiresIn;

    @Nullable
    public String getAccessToken() {
        return AccessToken;
    }

    public void setAccessToken(@Nullable String accessToken) {
        AccessToken = accessToken;
    }

    @Nullable
    public String getTokenType() {
        return TokenType;
    }

    public void setTokenType(@Nullable String tokenType) {
        TokenType = tokenType;
    }

    public int getExpiresIn() {
        return ExpiresIn;
    }

    public void setExpiresIn(int expiresIn) {
        ExpiresIn = expiresIn;
    }
}
