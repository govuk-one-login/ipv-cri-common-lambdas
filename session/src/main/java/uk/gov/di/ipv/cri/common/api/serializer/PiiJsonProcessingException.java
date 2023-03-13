package uk.gov.di.ipv.cri.common.api.serializer;

import com.fasterxml.jackson.core.JsonProcessingException;

public class PiiJsonProcessingException extends JsonProcessingException {
    public PiiJsonProcessingException(String msg) {
        super(msg);
    }
}
