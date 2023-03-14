package uk.gov.di.ipv.cri.common.api.serializer;

import com.fasterxml.jackson.core.JsonProcessingException;

public class SharedClaimParsingException extends JsonProcessingException {
    public SharedClaimParsingException(String msg) {
        super(msg);
    }
}
