package com.teknologiia.argus.web;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Limitation de débit par appelant, en seau à jetons.
 *
 * <p>La page publique dépense de vraies ressources à chaque appel : des
 * requêtes DNS sortantes vers un domaine que l'appelant choisit. Laissée
 * ouverte, elle deviendrait un relais de reconnaissance commode pour
 * n'importe qui.
 *
 * <p>Le seau se remplit en continu, ce qui autorise une courte rafale puis
 * ramène au débit soutenu — plutôt qu'une coupure sèche en bord de fenêtre,
 * qui punit l'utilisateur normal autant que l'abuseur.
 *
 * <p><strong>Portée :</strong> l'état vit dans ce processus. Derrière
 * plusieurs instances, chacune compte séparément et la limite effective est
 * multipliée par leur nombre. Le jour où ce service tourne à plus d'une
 * instance, cet état doit passer dans un magasin partagé.
 */
@Component
public class RateLimiter {

    /** Au-delà de cette inactivité, une entrée est oubliée. */
    private static final Duration EVICTION = Duration.ofHours(1);

    /** Taille à partir de laquelle on balaie les entrées inactives. */
    private static final int SEUIL_BALAYAGE = 10_000;

    private final Map<String, Seau> seaux = new ConcurrentHashMap<>();

    @Value("${argus.ratelimit.analyse.capacite:10}")
    private int capacite;

    @Value("${argus.ratelimit.analyse.recharge-par-minute:5}")
    private double rechargeParMinute;

    /** Tente de consommer un jeton pour {@code cle}, avec l'allocation publique. */
    public Decision tryAcquire(String cle) {
        return tryAcquire(cle, capacite, rechargeParMinute);
    }

    /** Tente de consommer un jeton contre une allocation choisie par l'appelant. */
    public Decision tryAcquire(String cle, int capaciteSeau, double rechargeSeau) {
        if (seaux.size() > SEUIL_BALAYAGE) {
            balayer();
        }
        Seau seau = seaux.computeIfAbsent(cle, k -> new Seau(capaciteSeau));
        return seau.consommer(capaciteSeau, rechargeSeau);
    }

    private void balayer() {
        long limite = System.nanoTime() - EVICTION.toNanos();
        seaux.entrySet().removeIf(e -> e.getValue().dernierAcces() < limite);
    }

    /** Résultat d'une tentative : autorisée, ou refusée avec un délai d'attente. */
    public record Decision(boolean autorise, Duration attente) {

        public static Decision ok() {
            return new Decision(true, Duration.ZERO);
        }

        public static Decision refuse(Duration attente) {
            return new Decision(false, attente);
        }

        /** Valeur de l'en-tête {@code Retry-After}, en secondes, au moins 1. */
        public long retryAfterSeconds() {
            return Math.max(1, attente.toSeconds());
        }
    }

    /**
     * Un seau, protégé par son propre verrou.
     *
     * <p>Verrouiller le seau plutôt que la carte entière : deux appelants
     * différents ne se gênent pas, ce qui est le cas courant.
     */
    private static final class Seau {

        private double jetons;
        private long dernierNano;

        Seau(int capacite) {
            this.jetons = capacite;
            this.dernierNano = System.nanoTime();
        }

        synchronized Decision consommer(int capacite, double rechargeParMinute) {
            long maintenant = System.nanoTime();
            double minutesEcoulees = (maintenant - dernierNano) / 60_000_000_000.0;
            dernierNano = maintenant;

            jetons = Math.min(capacite, jetons + minutesEcoulees * rechargeParMinute);

            if (jetons >= 1.0) {
                jetons -= 1.0;
                return Decision.ok();
            }
            // Temps nécessaire pour regagner le jeton manquant.
            double minutesAAttendre = (1.0 - jetons) / rechargeParMinute;
            return Decision.refuse(Duration.ofMillis((long) Math.ceil(minutesAAttendre * 60_000)));
        }

        synchronized long dernierAcces() {
            return dernierNano;
        }
    }
}
