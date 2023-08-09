package poort8.ishare.core;

import com.auth0.jwt.JWT;
import java.time.Instant;

public class Authorisation {
    @SuppressWarnings("ConstantConditions")
    public static boolean VerifyAccess(String delegationToken, String action, String issuer, String subject, String resource) {
        var jwtToken = JWT.decode(delegationToken);
        DelegationEvidence delegationEvidence = jwtToken.getClaim("delegationEvidence").as(DelegationEvidence.class);

        if (delegationEvidence == null) {
            System.out.printf("delegationToken %s was null%n", delegationToken);
            return false;
        }

        if ((delegationEvidence.NotBefore > Instant.now().getEpochSecond()) ||
                (delegationEvidence.NotOnOrAfter <= Instant.now().getEpochSecond())) {
            System.out.printf("NotBefore > now or NotOnOrAfter <= now in delegationToken %s%n", delegationToken);
            return false;
        }

        if (issuer != null && !issuer.equals(delegationEvidence.PolicyIssuer)) {
            System.out.printf("Access token aud %s does not match the policyIssuer in delegationToken %s%n", issuer, delegationToken);
            return false;
        }

        var policy = delegationEvidence.PolicySets.get(0).Policies.get(0);
        if (subject != null && !subject.equals(delegationEvidence.Target.AccessSubject) &&
                !policy.Target.Environment.ServiceProviders.contains(subject)) {
            System.out.printf("Access token aud %s does not match the target (AccessSubject or ServiceProvider) in delegationToken %s%n", subject, delegationToken);
            return false;
        }

        if (delegationEvidence.PolicySets.get(0).MaxDelegationDepth < 0) {
            System.out.printf("Invalid max delegation depth in delegationToken %s, should be >= 0%n", delegationToken);
            return false;
        }

        // TODO: Resource type check - nodig? Wellicht alleen identifier check?
        /*if (resource != null && !resource.equals(policy.Target.Resource.Type)) {
            System.out.printf("Invalid resource type in delegationToken %s, should be %s%n", delegationToken, resource);
            return false;
        }*/

        if (resource != null &&
                !policy.Target.Resource.Identifiers.contains(resource))
        {
            if (!delegationEvidence.PolicySets.get(0).Policies.get(0).Target.Resource.Identifiers.contains("*"))
            {
                // TODO: Verkeerde logwarning? --> "Invalid resource identifier in delegationToken {delegationToken}, should be {resourceIdentifier}"
                System.out.printf("Invalid resource type in delegationToken %s, should be %s%n", delegationToken, resource);
                return false;
            }
        }

        if (action != null && !policy.Target.Actions.contains(action)) {
            System.out.printf("Invalid policy action in delegationToken %s, should be %s%n", delegationToken, action);
            return false;
        }

        var rootEffect = policy.Rules.get(0).Effect;

        return rootEffect.equalsIgnoreCase("Permit");
    }
}