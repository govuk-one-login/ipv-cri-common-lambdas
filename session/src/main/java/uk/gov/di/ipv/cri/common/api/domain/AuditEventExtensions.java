package uk.gov.di.ipv.cri.common.api.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class AuditEventExtensions {

    @JsonProperty("evidence")
    private final List<Evidence> evidence;

    @JsonCreator
    public AuditEventExtensions(
            @JsonProperty(value = "evidence", required = true) List<Evidence> evidence) {
        this.evidence = evidence;
    }

    public List<Evidence> getEvidence() {
        return evidence;
    }
}
