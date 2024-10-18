package uk.gov.di.ipv.cri.common.api.domain;

import com.fasterxml.jackson.annotation.JsonProperty;

public class Evidence {
    @JsonProperty("context")
    private String context;

    public String getContext() {
        return context;
    }

    public void setContext(String context) {
        this.context = context;
    }
}
