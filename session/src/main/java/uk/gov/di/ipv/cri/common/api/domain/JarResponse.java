package uk.gov.di.ipv.cri.common.api.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.cri.common.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Map;

@ExcludeFromGeneratedCoverageReport
public class JarResponse {
    @JsonProperty("shared_claims")
    private Map<String, Object> sharedClaims;

    @JsonProperty("passportSessionId")
    private String passportSessionId;

    public JarResponse(Map<String, Object> sharedClaims, String passportSessionId) {
        this.sharedClaims = sharedClaims;
        this.passportSessionId = passportSessionId;
    }

    public Map<String, Object> getSharedClaims() {
        return sharedClaims;
    }

    public String getPassportSessionId() {
        return passportSessionId;
    }
}
