package com.teknologiia.argus.mcp;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * ARGUS tient une regle depuis le premier jour : une adresse interne ne part
 * jamais vers un service tiers. Brancher un serveur MCP distant la contournait
 * — ses outils acceptent volontiers {@code 10.0.0.5}.
 *
 * <p>Ces tests sont la preuve que la regle tient toujours.
 */
class RemoteArgumentGuardTest {

    @Nested
    @DisplayName("ce qui ne doit jamais sortir")
    class Bloque {

        @ParameterizedTest(name = "{0}")
        @ValueSource(strings = {
                "10.0.0.5",          // classe A privee
                "192.168.1.42",      // classe C privee
                "172.16.5.9",        // classe B privee
                "127.0.0.1",         // bouclage
                "169.254.10.1",      // lien-local
                "0.0.0.0",           // adresse nulle
                "::1",               // bouclage IPv6
        })
        @DisplayName("adresses non publiques")
        void adresses(String valeur) {
            assertThatThrownBy(() -> RemoteArgumentGuard.verifier("threat_report", Map.of("t", valeur)))
                    .isInstanceOf(McpToolException.class)
                    .hasMessageContaining("non publique");
        }

        @ParameterizedTest(name = "{0}")
        @ValueSource(strings = {
                "localhost",
                "srv-ad01.corp",
                "fichiers.intranet",
                "imprimante.lan",
                "poste-42.localdomain",
        })
        @DisplayName("noms internes")
        void noms(String valeur) {
            assertThatThrownBy(() -> RemoteArgumentGuard.verifier("dns_lookup", Map.of("d", valeur)))
                    .isInstanceOf(McpToolException.class)
                    .hasMessageContaining("nom interne");
        }

        @ParameterizedTest(name = "{0}")
        @ValueSource(strings = {
                "https://intranet.local/rapport",   // l'hote est apres le schema
                "http://10.0.0.5:8080/admin",       // et avant le port
                "comptable@messagerie.internal",    // et apres l'arobase
        })
        @DisplayName("l'hote est extrait des URL et des adresses de courriel")
        void hoteExtrait(String valeur) {
            // Sans extraction, une adresse interne passerait simplement en
            // l'enveloppant dans une URL.
            assertThatThrownBy(() -> RemoteArgumentGuard.verifier("audit_domain", Map.of("u", valeur)))
                    .isInstanceOf(McpToolException.class);
        }

        @org.junit.jupiter.api.Test
        @DisplayName("une adresse interne cachee dans une liste")
        void dansUneListe() {
            // Les outils groupes prennent des listes d'indicateurs : verifier
            // seulement les chaines de premier niveau laisserait tout passer.
            assertThatThrownBy(() -> RemoteArgumentGuard.verifier(
                    "bulk_ioc_lookup", Map.of("iocs", List.of("8.8.8.8", "10.1.2.3"))))
                    .isInstanceOf(McpToolException.class);
        }

        @org.junit.jupiter.api.Test
        @DisplayName("une adresse interne cachee dans un objet imbrique")
        void dansUnObjet() {
            assertThatThrownBy(() -> RemoteArgumentGuard.verifier(
                    "contrast_scan", Map.of("cible", Map.of("hote", "192.168.0.1"))))
                    .isInstanceOf(McpToolException.class);
        }
    }

    @Nested
    @DisplayName("ce qui doit passer")
    class Passe {

        @ParameterizedTest(name = "{0}")
        @ValueSource(strings = {
                "github.com",
                "teknologiia.com",
                "8.8.8.8",                 // resolveur public
                "185.220.101.47",          // adresse publique reellement malveillante
                "https://exemple.com/a/b",
                "CVE-2021-44228",
                "T1566.002",
        })
        @DisplayName("indicateurs publics et identifiants sans rapport")
        void legitimes(String valeur) {
            // Un garde-fou trop large est aussi un defaut : il rendrait les
            // 55 outils distants inutilisables.
            assertThatCode(() -> RemoteArgumentGuard.verifier("cve_lookup", Map.of("v", valeur)))
                    .doesNotThrowAnyException();
        }

        @org.junit.jupiter.api.Test
        @DisplayName("des arguments absents ne font rien echouer")
        void argumentsAbsents() {
            assertThatCode(() -> RemoteArgumentGuard.verifier("kev_check", null))
                    .doesNotThrowAnyException();
            assertThatCode(() -> RemoteArgumentGuard.verifier("kev_check", Map.of()))
                    .doesNotThrowAnyException();
        }
    }
}
