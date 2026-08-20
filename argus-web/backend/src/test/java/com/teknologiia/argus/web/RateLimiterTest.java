package com.teknologiia.argus.web;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * La limitation de débit est ce qui empêche la page publique de devenir un
 * relais de reconnaissance. Elle mérite d'être testée pour elle-même.
 */
class RateLimiterTest {

    @Test
    @DisplayName("la capacité est consommée puis l'appelant est refusé")
    void capacitePuisRefus() {
        RateLimiter limiteur = new RateLimiter();

        for (int i = 0; i < 5; i++) {
            assertThat(limiteur.tryAcquire("a", 5, 1).autorise())
                    .as("appel %d dans la capacité", i + 1)
                    .isTrue();
        }
        assertThat(limiteur.tryAcquire("a", 5, 1).autorise()).isFalse();
    }

    @Test
    @DisplayName("deux appelants ne partagent pas leur allocation")
    void seauxIndependants() {
        RateLimiter limiteur = new RateLimiter();

        for (int i = 0; i < 3; i++) {
            limiteur.tryAcquire("a", 3, 1);
        }

        // Épuiser un appelant ne doit rien retirer à un autre : sinon un seul
        // abuseur mettrait tout le monde hors service.
        assertThat(limiteur.tryAcquire("a", 3, 1).autorise()).isFalse();
        assertThat(limiteur.tryAcquire("b", 3, 1).autorise()).isTrue();
    }

    @Test
    @DisplayName("un refus annonce une attente exploitable")
    void attenteNonNulle() {
        RateLimiter limiteur = new RateLimiter();
        limiteur.tryAcquire("a", 1, 60);

        RateLimiter.Decision decision = limiteur.tryAcquire("a", 1, 60);

        assertThat(decision.autorise()).isFalse();
        // Retry-After à 0 dirait « réessayez immédiatement », ce qui relancerait
        // aussitôt un client bien élevé dans le mur.
        assertThat(decision.retryAfterSeconds()).isGreaterThanOrEqualTo(1);
    }

    @Test
    @DisplayName("le seau se remplit avec le temps")
    void rechargeAvecLeTemps() throws InterruptedException {
        // 600 jetons par minute, soit 10 par seconde : une centaine de
        // millisecondes suffit à en regagner un, sans allonger la suite.
        RateLimiter limiteur = new RateLimiter();
        limiteur.tryAcquire("a", 1, 600);
        assertThat(limiteur.tryAcquire("a", 1, 600).autorise()).isFalse();

        Thread.sleep(250);

        assertThat(limiteur.tryAcquire("a", 1, 600).autorise()).isTrue();
    }
}
