package poort8.ishare.core;

import javax.annotation.Nullable;
import java.util.ArrayList;
import com.fasterxml.jackson.annotation.JsonProperty;

public class DelegationEvidence {
    @JsonProperty("notBefore")
    public int NotBefore;
    @JsonProperty("notOnOrAfter")
    public int NotOnOrAfter;
    @JsonProperty("policyIssuer")
    public @Nullable String PolicyIssuer;
    @JsonProperty("target")
    public @Nullable TargetObject Target;
    @JsonProperty("policySets")
    public @Nullable ArrayList<PolicySet> PolicySets;

    public int getNotBefore() {
        return NotBefore;
    }

    public void setNotBefore(int notBefore) {
        NotBefore = notBefore;
    }

    public int getNotOnOrAfter() {
        return NotOnOrAfter;
    }

    public void setNotOnOrAfter(int notOnOrAfter) {
        NotOnOrAfter = notOnOrAfter;
    }

    @Nullable
    public String getPolicyIssuer() {
        return PolicyIssuer;
    }

    public void setPolicyIssuer(@Nullable String policyIssuer) {
        PolicyIssuer = policyIssuer;
    }

    @Nullable
    public TargetObject getTarget() {
        return Target;
    }

    public void setTarget(@Nullable TargetObject target) {
        Target = target;
    }

    @Nullable
    public ArrayList<PolicySet> getPolicySets() {
        return PolicySets;
    }

    public void setPolicySets(@Nullable ArrayList<PolicySet> policySets) {
        PolicySets = policySets;
    }

    public static class PolicySet {

        @JsonProperty("maxDelegationDepth")
        public int MaxDelegationDepth;
        @JsonProperty("target")
        public @Nullable TargetObject Target;
        @JsonProperty("policies")
        public @Nullable ArrayList<Policy> Policies;

        public int getMaxDelegationDepth() {
            return MaxDelegationDepth;
        }

        public void setMaxDelegationDepth(int maxDelegationDepth) {
            MaxDelegationDepth = maxDelegationDepth;
        }

        @Nullable
        public TargetObject getTarget() {
            return Target;
        }

        public void setTarget(@Nullable TargetObject target) {
            Target = target;
        }

        @Nullable
        public ArrayList<Policy> getPolicies() {
            return Policies;
        }

        public void setPolicies(@Nullable ArrayList<Policy> policies) {
            Policies = policies;
        }
    }

    public static class Policy {
        @JsonProperty("target")
        public @Nullable TargetObject Target;
        @JsonProperty("rules")
        public @Nullable ArrayList<Rule> Rules;

        @Nullable
        public TargetObject getTarget() {
            return Target;
        }

        public void setTarget(@Nullable TargetObject target) {
            Target = target;
        }

        @Nullable
        public ArrayList<Rule> getRules() {
            return Rules;
        }

        public void setRules(@Nullable ArrayList<Rule> rules) {
            Rules = rules;
        }
    }

    public static class Rule {
        @JsonProperty("effect")
        public @Nullable String Effect;

        @Nullable
        public String getEffect() {
            return Effect;
        }

        public void setEffect(@Nullable String effect) {
            Effect = effect;
        }
    }

    public static class Resource {
        @JsonProperty("type")
        public @Nullable String Type;
        @JsonProperty("identifiers")
        public @Nullable ArrayList<String> Identifiers;
        @JsonProperty("attributes")
        public @Nullable ArrayList<String> Attributes;

        @Nullable
        public String getType() {
            return Type;
        }

        public void setType(@Nullable String type) {
            Type = type;
        }

        @Nullable
        public ArrayList<String> getIdentifiers() {
            return Identifiers;
        }

        public void setIdentifiers(@Nullable ArrayList<String> identifiers) {
            Identifiers = identifiers;
        }

        @Nullable
        public ArrayList<String> getAttributes() {
            return Attributes;
        }

        public void setAttributes(@Nullable ArrayList<String> attributes) {
            Attributes = attributes;
        }
    }

    public static class Environment {
        @JsonProperty("licenses")
        public @Nullable ArrayList<String> Licenses;
        @JsonProperty("serviceProviders")
        public @Nullable ArrayList<String> ServiceProviders;

        @Nullable
        public ArrayList<String> getLicenses() {
            return Licenses;
        }

        public void setLicenses(@Nullable ArrayList<String> licenses) {
            Licenses = licenses;
        }

        @Nullable
        public ArrayList<String> getServiceProviders() {
            return ServiceProviders;
        }

        public void setServiceProviders(@Nullable ArrayList<String> serviceProviders) {
            ServiceProviders = serviceProviders;
        }
    }

    public static class TargetObject {
        @JsonProperty("accessSubject")
        public @Nullable String AccessSubject;
        @JsonProperty("environment")
        public @Nullable Environment Environment;
        @JsonProperty("resource")
        public @Nullable Resource Resource;
        @JsonProperty("actions")
        public @Nullable ArrayList<String> Actions;

        @Nullable
        public String getAccessSubject() {
            return AccessSubject;
        }

        public void setAccessSubject(@Nullable String accessSubject) {
            AccessSubject = accessSubject;
        }

        @Nullable
        public DelegationEvidence.Environment getEnvironment() {
            return Environment;
        }

        public void setEnvironment(@Nullable DelegationEvidence.Environment environment) {
            Environment = environment;
        }

        @Nullable
        public DelegationEvidence.Resource getResource() {
            return Resource;
        }

        public void setResource(@Nullable DelegationEvidence.Resource resource) {
            Resource = resource;
        }

        @Nullable
        public ArrayList<String> getActions() {
            return Actions;
        }

        public void setActions(@Nullable ArrayList<String> actions) {
            Actions = actions;
        }
    }
}
