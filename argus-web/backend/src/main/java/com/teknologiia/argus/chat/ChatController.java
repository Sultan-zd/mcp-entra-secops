package com.teknologiia.argus.chat;

import com.anthropic.errors.AnthropicIoException;
import com.anthropic.errors.AnthropicServiceException;
import com.teknologiia.argus.chat.ChatContracts.ChatEvent;
import com.teknologiia.argus.chat.ChatContracts.ChatRequest;
import com.teknologiia.argus.chat.ChatContracts.ProviderInfo;
import com.teknologiia.argus.web.ClientAddress;
import com.teknologiia.argus.web.RateLimiter;
import io.modelcontextprotocol.json.McpJsonDefaults;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * L'interface conversationnelle : poser une question, obtenir une reponse
 * fondee sur les outils.
 *
 * <p>Le flux est diffuse au fil de l'eau. Une investigation qui enchaine cinq
 * outils prend plusieurs secondes ; laisser l'analyste devant un sablier
 * pendant ce temps donne l'impression que rien ne se passe, alors que c'est
 * precisement le moment ou il apprend quelque chose — quel outil est
 * interroge, et ce qu'il repond.
 */
@RestController
@RequestMapping("/api/chat")
public class ChatController {

    private static final Logger log = LoggerFactory.getLogger(ChatController.class);

    /** Une investigation outillee peut legitimement durer. */
    private static final long TIMEOUT_MS = 300_000L;

    private final Map<String, LlmProvider> fournisseurs = new LinkedHashMap<>();
    private final ToolBridge outils;
    private final RateLimiter limiteur;

    /**
     * Fils dedies : chaque conversation occupe le sien pendant toute sa duree.
     * Les fils virtuels conviennent ici — l'attente est celle du reseau.
     */
    private final ExecutorService pool = Executors.newVirtualThreadPerTaskExecutor();

    @Value("${argus.derriere-mandataire:false}")
    private boolean derriereMandataire;

    public ChatController(List<LlmProvider> disponibles, ToolBridge outils, RateLimiter limiteur) {
        disponibles.forEach(f -> this.fournisseurs.put(f.id(), f));
        this.outils = outils;
        this.limiteur = limiteur;
    }

    /** Les fournisseurs de modele proposes, et ou obtenir une cle. */
    @GetMapping("/providers")
    public List<ProviderInfo> providers() {
        return fournisseurs.values().stream().map(LlmProvider::info).toList();
    }

    /** Les outils que le modele pourra appeler, pour que l'utilisateur les voie. */
    @GetMapping("/tools")
    public List<Map<String, Object>> tools() {
        return outils.catalog().stream()
                .map(t -> Map.<String, Object>of(
                        "name", t.name(),
                        "description", t.description() != null ? t.description() : ""))
                .toList();
    }

    /**
     * Mene une conversation et diffuse chaque etape.
     *
     * <p>La cle d'API arrive dans le corps de la requete et vit le temps de
     * l'appel. Elle n'est ni journalisee, ni ecrite, ni mise en cache : la
     * plateforme n'a aucune raison de la conserver, et beaucoup de ne pas le
     * faire.
     */
    // Pas de `produces` fige ici : la methode rend soit un flux SSE, soit une
    // erreur JSON. Contraindre le type produit faisait echouer la negociation
    // sur les erreurs, qui repartaient en 500 au lieu de 400 ou 429.
    @PostMapping
    public Object converse(@Valid @RequestBody ChatRequest requete, HttpServletRequest http) {
        RateLimiter.Decision decision = limiteur.tryAcquire(
                "chat:" + ClientAddress.of(http, derriereMandataire), 20, 10);
        if (!decision.autorise()) {
            return ResponseEntity.status(429)
                    .body(Map.of("detail", "Trop de questions. Reessayez dans "
                            + decision.retryAfterSeconds() + " secondes."));
        }

        LlmProvider fournisseur = fournisseurs.get(requete.provider());
        if (fournisseur == null) {
            return ResponseEntity.badRequest()
                    .body(Map.of("detail", "Fournisseur inconnu : " + requete.provider()));
        }

        SseEmitter flux = new SseEmitter(TIMEOUT_MS);
        pool.submit(() -> {
            try {
                fournisseur.converse(requete, outils, evenement -> pousser(flux, evenement));
            } catch (Exception e) {
                // Le message d'origine peut nommer des classes, des chemins, et
                // dans le cas d'une erreur d'authentification, refleter la cle.
                // Seule une phrase choisie sort d'ici.
                log.error("Conversation en echec ({}).", fournisseur.id(), e);
                pousser(flux, ChatEvent.error(explication(e)));
            } finally {
                flux.complete();
            }
        });
        return flux;
    }

    private void pousser(SseEmitter flux, ChatEvent evenement) {
        try {
            flux.send(SseEmitter.event()
                    .name(evenement.type())
                    .data(json(evenement.payload()), MediaType.APPLICATION_JSON));
        } catch (IOException | IllegalStateException e) {
            // Le navigateur a ferme l'onglet. Ce n'est pas une anomalie.
            throw new FluxFerme();
        }
    }

    /**
     * Traduit une panne en phrase utile, sans rien reveler de l'interne.
     *
     * <p>Le tri se fait sur le <strong>code HTTP</strong>, pas sur le nom de la
     * classe d'exception. Un premier essai comparait des noms — il ratait
     * {@code UnauthorizedException}, et une cle invalide s'annoncait
     * « reessayez dans un instant », ce qui envoie l'utilisateur chercher le
     * probleme chez nous.
     *
     * <p>Le corps de la reponse du fournisseur n'est jamais repris : il peut
     * contenir des elements de la requete, cle comprise.
     */
    private String explication(Exception e) {
        if (e instanceof FluxFerme) {
            return "Conversation interrompue.";
        }
        if (e instanceof AnthropicServiceException service) {
            return switch (service.statusCode()) {
                case 401 -> "Cette cle d'API a ete refusee. Verifiez-la aupres du fournisseur.";
                case 403 -> "Cette cle n'a pas le droit d'utiliser ce modele.";
                case 404 -> "Ce modele n'existe pas ou n'est pas accessible avec cette cle.";
                case 429 -> "Le fournisseur a limite votre cle. Patientez avant de reessayer.";
                case 400, 422 -> "La demande a ete refusee par le fournisseur.";
                default -> service.statusCode() >= 500
                        ? "Le fournisseur rencontre un incident. Reessayez plus tard."
                        : "L'investigation n'a pas abouti.";
            };
        }
        if (e instanceof AnthropicIoException) {
            return "Le fournisseur n'a pas repondu. Verifiez votre connexion.";
        }
        return "L'investigation n'a pas abouti. Reessayez dans un instant.";
    }

    private String json(Object valeur) {
        try {
            return McpJsonDefaults.getMapper().writeValueAsString(valeur);
        } catch (Exception e) {
            return "{}";
        }
    }

    /** Signale un navigateur parti, pour couper la boucle sans bruit. */
    private static final class FluxFerme extends RuntimeException {
        FluxFerme() {
            super(null, null, false, false);
        }
    }
}
