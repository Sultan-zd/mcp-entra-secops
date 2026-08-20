package com.teknologiia.argus.controller;

import com.teknologiia.argus.mcp.McpToolGateway;
import com.teknologiia.argus.web.ClientAddress;
import com.teknologiia.argus.web.RateLimiter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * L'étage public : les analyses qui n'exigent ni compte, ni clé d'API.
 *
 * <p>Cinq des quinze outils d'ARGUS ne consultent que le DNS public. Ils ne
 * touchent pas au domaine analysé, ne demandent aucun accès à une boîte aux
 * lettres, et fonctionnent donc sur des domaines qu'on ne possède pas. C'est
 * exactement ce qui peut être offert sans inscription.
 *
 * <p>Les dix autres — renseignement sur les menaces et identité Entra —
 * exigent des clés ou un tenant, et vivront derrière un compte.
 */
@RestController
@RequestMapping("/api/public")
public class PublicAnalysisController {

    /** Nom logique du serveur MCP de messagerie, tel que déclaré en configuration. */
    private static final String SERVEUR = "email";

    private final McpToolGateway gateway;
    private final RateLimiter limiteur;

    @Value("${argus.derriere-mandataire:false}")
    private boolean derriereMandataire;

    public PublicAnalysisController(McpToolGateway gateway, RateLimiter limiteur) {
        this.gateway = gateway;
        this.limiteur = limiteur;
    }

    /**
     * Demande d'analyse d'un domaine.
     *
     * <p>Le motif rejette d'emblée ce qui n'est pas un nom de domaine plausible.
     * L'outil Python valide de nouveau, plus finement — ce contrôle-ci sert à ne
     * pas dépenser un processus et des requêtes DNS pour une saisie évidemment
     * fautive.
     */
    public record DemandeDomaine(
            @NotBlank(message = "Indiquez un domaine.")
            @Size(max = 253, message = "Ce domaine est trop long.")
            @Pattern(
                    regexp = "^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$",
                    message = "Ce domaine n'est pas valide. Exemple : teknologiia.com")
            String domain) {
    }

    /**
     * Note la protection d'un domaine contre l'usurpation, de 0 à 100.
     *
     * <p>Rien n'est envoyé au domaine analysé : tout se lit dans le DNS public.
     */
    @PostMapping("/domain-posture")
    public ResponseEntity<?> posture(@Valid @RequestBody DemandeDomaine demande,
                                     HttpServletRequest requete) {
        ResponseEntity<?> refus = verifierDebit(requete);
        if (refus != null) {
            return refus;
        }
        Map<String, Object> resultat = gateway.call(
                SERVEUR, "check_domain_posture", Map.of("domain", demande.domain()));
        return ResponseEntity.ok(resultat);
    }

    /** Détail SPF seul, dont le compte de requêtes DNS face à la limite de dix. */
    @PostMapping("/spf")
    public ResponseEntity<?> spf(@Valid @RequestBody DemandeDomaine demande,
                                 HttpServletRequest requete) {
        ResponseEntity<?> refus = verifierDebit(requete);
        if (refus != null) {
            return refus;
        }
        return ResponseEntity.ok(
                gateway.call(SERVEUR, "check_spf", Map.of("domain", demande.domain())));
    }

    /** Politique DMARC du domaine, et ce qu'elle laisse réellement passer. */
    @PostMapping("/dmarc")
    public ResponseEntity<?> dmarc(@Valid @RequestBody DemandeDomaine demande,
                                   HttpServletRequest requete) {
        ResponseEntity<?> refus = verifierDebit(requete);
        if (refus != null) {
            return refus;
        }
        return ResponseEntity.ok(
                gateway.call(SERVEUR, "check_dmarc", Map.of("domain", demande.domain())));
    }

    /** Santé de l'étage public, pour la supervision et la page d'accueil. */
    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of(
                "ready", gateway.isReady(SERVEUR),
                "servers", gateway.health());
    }

    /**
     * Applique la limitation de débit.
     *
     * @return une réponse 429 si l'appelant doit patienter, {@code null} sinon
     */
    private ResponseEntity<?> verifierDebit(HttpServletRequest requete) {
        String cle = ClientAddress.of(requete, derriereMandataire);
        RateLimiter.Decision decision = limiteur.tryAcquire(cle);
        if (decision.autorise()) {
            return null;
        }
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS)
                .header(HttpHeaders.RETRY_AFTER, String.valueOf(decision.retryAfterSeconds()))
                .body(Map.of("detail",
                        "Trop d'analyses depuis cette adresse. Réessayez dans "
                                + decision.retryAfterSeconds() + " secondes."));
    }
}
