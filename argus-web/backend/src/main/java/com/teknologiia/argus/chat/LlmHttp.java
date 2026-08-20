package com.teknologiia.argus.chat;

import io.modelcontextprotocol.json.McpJsonDefaults;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientResponseException;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Les appels HTTP vers les fournisseurs de modeles.
 *
 * <p>Une seule classe pour tous : la difference entre eux tient a l'URL, a
 * l'en-tete d'authentification et a la forme du corps — pas au transport.
 */
@Component
public class LlmHttp {

    /**
     * Un tour de modele avec appels d'outils peut legitimement durer.
     *
     * <p>La borne existe quand meme : sans elle, un fournisseur qui ne repond
     * jamais retiendrait un fil et le flux du navigateur indefiniment.
     */
    private static final Duration TIMEOUT = Duration.ofMinutes(4);

    /** Le champ « status » ou « reason » d'une erreur, en capitales uniquement. */
    private static final java.util.regex.Pattern MOTIF = java.util.regex.Pattern.compile(
            "\"(?:status|reason)\"\s*:\s*\"([A-Z][A-Z_]{2,39})\"");

    private final RestClient client;

    public LlmHttp() {
        // Le client du JDK plutot qu'un habillage : les fabriques de Spring ont
        // change de paquet entre Boot 3 et Boot 4, celui-ci ne bougera pas.
        java.net.http.HttpClient jdk = java.net.http.HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(20))
                .followRedirects(java.net.http.HttpClient.Redirect.NORMAL)
                .build();

        JdkClientHttpRequestFactory fabrique = new JdkClientHttpRequestFactory(jdk);
        fabrique.setReadTimeout(TIMEOUT);

        this.client = RestClient.builder().requestFactory(fabrique).build();
    }

    /**
     * POST JSON authentifie.
     *
     * @param entete nom de l'en-tete portant la cle ; {@code null} pour
     *               {@code Authorization: Bearer}
     */
    @SuppressWarnings("unchecked")
    public Map<String, Object> postJson(String url, String cle, String entete, Object corps) {
        try {
            RestClient.RequestBodySpec requete = client.post()
                    .uri(url)
                    .contentType(MediaType.APPLICATION_JSON)
                    .accept(MediaType.APPLICATION_JSON);

            if (entete == null) {
                requete = requete.header(HttpHeaders.AUTHORIZATION, "Bearer " + cle);
            } else {
                requete = requete.header(entete, cle);
            }

            Map<String, Object> reponse = requete.body(corps).retrieve().body(Map.class);
            return reponse != null ? reponse : Map.of();
        } catch (RestClientResponseException e) {
            throw new LlmHttpException(
                    e.getStatusCode().value(), motif(e.getResponseBodyAsString()), e);
        }
    }

    /**
     * Extrait le motif structure d'une erreur, et rien d'autre.
     *
     * <p>Le corps d'une erreur peut reprendre des elements de la requete, cle
     * comprise : le lire tel quel serait une fuite. Seul un jeton en capitales
     * — {@code INVALID_ARGUMENT}, {@code PERMISSION_DENIED} — est retenu.
     * Ces valeurs sont des enumerations fermees ; par construction, aucune ne
     * peut transporter un secret.
     */
    private String motif(String corps) {
        if (corps == null || corps.isBlank()) {
            return null;
        }
        var m = MOTIF.matcher(corps);
        return m.find() ? m.group(1) : null;
    }

    /** Serialise un objet en JSON. */
    public String ecrire(Object valeur) {
        try {
            return McpJsonDefaults.getMapper().writeValueAsString(valeur);
        } catch (Exception e) {
            return String.valueOf(valeur);
        }
    }

    /** Lit un objet JSON, en tolerant une chaine vide ou malformee. */
    @SuppressWarnings("unchecked")
    public Map<String, Object> parseObjet(String json) {
        if (json == null || json.isBlank()) {
            return Map.of();
        }
        try {
            Map<String, Object> lu = McpJsonDefaults.getMapper().readValue(json, Map.class);
            return lu != null ? new LinkedHashMap<>(lu) : Map.of();
        } catch (Exception e) {
            return Map.of();
        }
    }

    /** Une reponse d'erreur d'un fournisseur, reduite a son code de statut. */
    public static class LlmHttpException extends RuntimeException {

        private final int statusCode;
        private final String motif;

        public LlmHttpException(int statusCode, String motif, Throwable cause) {
            super("Le fournisseur a repondu " + statusCode
                    + (motif != null ? " (" + motif + ")" : ""), cause);
            this.statusCode = statusCode;
            this.motif = motif;
        }

        public int statusCode() {
            return statusCode;
        }

        /** Motif structure du fournisseur, ou {@code null}. */
        public String motif() {
            return motif;
        }
    }
}
