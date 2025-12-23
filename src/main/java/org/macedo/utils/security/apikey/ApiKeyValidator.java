package org.macedo.utils.security.apikey;

import java.util.List;

public interface ApiKeyValidator {

    boolean isValid(String apiKey);
    List<String> getAuthorities(String apiKey);
    String resolveSubject(String apiKey);
    void registrarUso(String apiKey);

}
