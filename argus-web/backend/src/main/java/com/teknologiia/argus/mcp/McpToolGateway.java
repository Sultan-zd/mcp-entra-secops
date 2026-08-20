package com.teknologiia.argus.mcp;

import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.stereotype.Service;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Le seul point par lequel cette application atteint la logique d'analyse.
 *
 * <p>C'est la décision d'architecture centrale du projet web, et elle mérite
 * d'être expliquée. Les quinze outils d'ARGUS sont écrits en Python et
 * couverts par 288 tests. Les réécrire en Java donnerait deux implémentations
 * de la même règle — la limite des dix requêtes SPF, la fusion des verdicts,
 * l'alignement DMARC — qui divergeraient en silence à la première correction
 * appliquée d'un seul côté.
 *
 * <p>Le backend Java est donc un <strong>client MCP</strong>. Il parle aux
 * serveurs existants par le protocole prévu pour ça. Accessoirement, cela
 * démontre l'intérêt réel de MCP : les mêmes serveurs servent Claude Desktop
 * et une application web, sans une ligne de code en double.
 */
@Service
@EnableConfigurationProperties(McpProperties.class)
public class McpToolGateway implements AutoCloseable {

    private static final Logger log = LoggerFactory.getLogger(McpToolGateway.class);

    private final McpProperties props;
    private final Map<String, McpServerPool> pools = new LinkedHashMap<>();

    public McpToolGateway(McpProperties props) {
        this.props = props;
    }

    @PostConstruct
    void demarrer() {
        if (props.getServers().isEmpty()) {
            log.warn("Aucun serveur MCP déclaré : les routes d'analyse répondront en panne.");
            return;
        }
        props.getServers().forEach((nom, spec) -> {
            McpServerPool pool = new McpServerPool(nom, props, spec);
            pool.start();
            pools.put(nom, pool);
        });
    }

    /**
     * Appelle un outil sur un serveur déclaré.
     *
     * @param serveur   nom logique du serveur (« email », « intel »…)
     * @param outil     nom de l'outil MCP
     * @param arguments arguments de l'outil
     * @return la sortie structurée de l'outil
     */
    public Map<String, Object> call(String serveur, String outil, Map<String, Object> arguments) {
        McpServerPool pool = pools.get(serveur);
        if (pool == null) {
            throw new McpToolException("Serveur d'analyse inconnu : " + serveur, false);
        }
        return pool.call(outil, arguments);
    }

    /** Indique si un serveur a au moins un processus vivant. */
    public boolean isReady(String serveur) {
        McpServerPool pool = pools.get(serveur);
        return pool != null && pool.isReady();
    }

    /** État de chaque serveur, pour la route de santé. */
    public Map<String, Boolean> health() {
        Map<String, Boolean> etat = new LinkedHashMap<>();
        pools.forEach((nom, pool) -> etat.put(nom, pool.isReady()));
        return etat;
    }

    @Override
    @PreDestroy
    public void close() {
        pools.values().forEach(McpServerPool::close);
        pools.clear();
    }
}
