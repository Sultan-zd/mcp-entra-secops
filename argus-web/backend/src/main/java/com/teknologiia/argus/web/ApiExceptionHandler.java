package com.teknologiia.argus.web;

import com.teknologiia.argus.mcp.McpToolException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

/**
 * Donne à toutes les erreurs une seule forme : {@code {"detail": "…"}}.
 *
 * <p>Deux raisons de ne pas s'en remettre au comportement par défaut de
 * Spring :
 *
 * <ul>
 *   <li>Spring masque les messages d'exception, si bien qu'une phrase écrite
 *       exprès pour l'utilisateur n'arrive jamais au navigateur, qui ne peut
 *       afficher qu'un code d'état nu.</li>
 *   <li>Les afficher tous exposerait aussi le texte des exceptions
 *       <em>imprévues</em>, qui nomment volontiers des classes, des tables ou
 *       des chemins de fichiers. Ici, seuls les messages que l'application a
 *       choisi d'écrire sortent ; l'inattendu est journalisé en entier et
 *       répondu par une phrase générique.</li>
 * </ul>
 */
@RestControllerAdvice
public class ApiExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

    /** Un outil a refusé l'entrée, ou un serveur d'analyse est en panne. */
    @ExceptionHandler(McpToolException.class)
    public ResponseEntity<Map<String, Object>> outil(McpToolException e) {
        if (e.isClientFault()) {
            return ResponseEntity.badRequest().body(Map.of("detail", e.getMessage()));
        }
        log.error("Appel d'outil MCP en échec.", e);
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body(Map.of("detail", e.getMessage()));
    }

    /** Échec de validation d'un corps de requête. */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> validation(MethodArgumentNotValidException e) {
        String detail = e.getBindingResult().getFieldErrors().stream()
                .findFirst()
                .map(f -> f.getDefaultMessage() != null ? f.getDefaultMessage() : "Champ invalide.")
                .orElse("Requête invalide.");
        return ResponseEntity.badRequest().body(Map.of("detail", detail));
    }

    /** Tout le reste : journalisé en entier, répondu sans détail. */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> inattendu(Exception e) {
        log.error("Erreur inattendue.", e);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("detail", "Une erreur interne est survenue."));
    }
}
