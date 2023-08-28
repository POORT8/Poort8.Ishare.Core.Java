package poort8.ishare.core;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.jsonwebtoken.Jwts;
import java.io.*;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.*;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

import poort8.ishare.core.models.DelegationEvidence;
import poort8.ishare.core.models.TokenResponse;

public class Authorization {

    private static final String Purpose = "ISHARE";

    public static String GetAccessToken() {
        String url = GetConfig("AuthorizationRegistryUrl") + "/connect/token";

        String clientAssertion = CreateClientAssertion();

        HashMap<String, String> parameters = new HashMap<>();
        parameters.put("grant_type", "client_credentials");
        parameters.put("scope", "iSHARE");
        parameters.put("client_id", GetConfig("ClientId"));
        parameters.put("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        parameters.put("client_assertion", clientAssertion);

        String form = parameters.entrySet()
                .stream()
                .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .headers("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form))
                .build();
        HttpResponse<?> response;

        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                System.out.println("Could not get access token from Authorization Registry");
                throw new RuntimeException();
            }
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }

        TokenResponse tokenResponse = null;
        try {
            ObjectMapper mapper = new ObjectMapper();
            tokenResponse = mapper.readValue(response.body().toString(), TokenResponse.class);
        } catch (JsonProcessingException e) {
            System.out.println("Could not get access token from API response: " + e);
        }

        if (tokenResponse == null) {
            System.out.println("Could not get access token from API response");
            throw new RuntimeException();
        } else {
            System.out.println("Received token from Authorization Registry");
            return tokenResponse.AccessToken;
        }
    }

    public static String GetDelegationEvidence(String accessToken, String subject, String resourceType, String resourceIdentifier, String action) {
        String url = GetConfig("AuthorizationRegistryUrl") + "/delegation";

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .headers("Authorization", "Bearer " + accessToken)
                .POST(HttpRequest.BodyPublishers.ofString(GetDelegationMaskRequest(subject, resourceType, resourceIdentifier, action).toString()))
                .build();
        HttpResponse<?> response;

        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }

        if (response.statusCode() != 200)
        {
            System.out.printf("Could not get delegation evidence from access token (Http code %s)%n", response.statusCode());
            throw new RuntimeException();
        }

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode jsonNode;
        try {
            jsonNode = objectMapper.readTree(response.body().toString());
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        return jsonNode.get("delegation_token").asText();
    }

    @SuppressWarnings("ConstantConditions")
    public static boolean VerifyAccess(String delegationToken, String issuer, String subject, String resourceType, String resourceIdentifier, String action) {
        DelegationEvidence delegationEvidence;
        try {
            String[] chunks = delegationToken.split("\\.");
            Base64.Decoder decoder = Base64.getUrlDecoder();
            String payload = new String(decoder.decode(chunks[1]));

            ObjectMapper mapper = new ObjectMapper();
            JsonNode delegationEvidenceNode = mapper.readTree(payload).get("delegationEvidence");
            delegationEvidence = mapper.readValue(delegationEvidenceNode.toString(), DelegationEvidence.class);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }

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

        if (resourceType != null && !resourceType.equals(policy.Target.Resource.Type)) {
            System.out.printf("Invalid resource type in delegationToken %s, should be %s%n", delegationToken, resourceType);
            return false;
        }

        if (resourceIdentifier != null &&
                !policy.Target.Resource.Identifiers.contains(resourceIdentifier))
        {
            if (!delegationEvidence.PolicySets.get(0).Policies.get(0).Target.Resource.Identifiers.contains("*"))
            {
                System.out.printf("Invalid resource identifier in delegationToken %s, should be %s%n", delegationToken, resourceIdentifier);
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

    private static String CreateClientAssertion() {
        RSAPrivateKey signingKey = GetSigningKey();

        String[] certificateChain = {GetConfig("Certificate")};
        var jwt = Jwts.builder()
                .setIssuer(GetConfig("ClientId"))
                .setAudience(GetConfig("AuthorizationRegistryId"))
                .claim("sub", GetConfig("ClientId"))
                .claim("jti", UUID.randomUUID().toString())
                .setNotBefore(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + (30 * 1000L)))
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setHeaderParam("alg", "RS256")
                .setHeaderParam("typ", "JWT")
                .setHeaderParam("x5c", certificateChain)
                .signWith(signingKey);

        return jwt.compact();
    }

    private static RSAPrivateKey GetSigningKey() {
        java.security.Security.addProvider(
                new org.bouncycastle.jce.provider.BouncyCastleProvider()
        );

        KeyFactory kf;
        try {
            kf = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        RSAPrivateKey privateRsaKey;
        try {
            byte[] encoded = Base64.getDecoder().decode(GetConfig("PrivateKey"));
            PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(encoded);
            privateRsaKey = (RSAPrivateKey) kf.generatePrivate(privateKeySpec);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }

        return privateRsaKey;
    }

    private static ObjectNode GetDelegationMaskRequest(String subject, String resourceType, String resourceIdentifier, String action) {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode rootNode = mapper.createObjectNode();

        ObjectNode delegationRequest = mapper.createObjectNode();
        delegationRequest.put("policyIssuer", GetConfig("ClientId"));

        ObjectNode delegationRequestTarget = mapper.createObjectNode();
        delegationRequestTarget.put("accessSubject", subject);
        delegationRequest.set("target", delegationRequestTarget);

        ArrayNode policySets = mapper.createArrayNode();

        ArrayNode policies = mapper.createArrayNode();
        ObjectNode policiesObject = mapper.createObjectNode();

        ObjectNode policiesTarget = mapper.createObjectNode();

        ObjectNode resource = mapper.createObjectNode();
        resource.put("type", resourceType);
        ArrayNode identifiers = mapper.createArrayNode();
        identifiers.add(resourceIdentifier);
        resource.set("identifiers", identifiers);
        ArrayNode attributes = mapper.createArrayNode();
        attributes.add("*");
        resource.set("attributes", attributes);
        policiesTarget.set("resource", resource);

        ArrayNode actions = mapper.createArrayNode();
        actions.add(Purpose + "." + action);
        policiesTarget.set("actions", actions);

        ObjectNode environment = mapper.createObjectNode();
        ArrayNode serviceProviders = mapper.createArrayNode();
        serviceProviders.add(GetConfig("ClientId"));
        environment.set("serviceProviders", serviceProviders);
        policiesTarget.set("environment", environment);

        policiesObject.set("target", policiesTarget);

        ArrayNode rules = mapper.createArrayNode();
        rules.add(mapper.createObjectNode().put("effect", "Permit"));

        policiesObject.set("rules", rules);

        policies.add(policiesObject);
        policySets.add(mapper.createObjectNode().set("policies", policies));
        delegationRequest.set("policySets", policySets);

        rootNode.set("delegationRequest", delegationRequest);

        return rootNode;
    }

    private static String GetConfig(String propertyKey) {
        try {
            String configFilePath = "src/main/resources/config.properties";
            FileInputStream propsInput = new FileInputStream(configFilePath);
            Properties prop = new Properties();
            prop.load(propsInput);

            var res = prop.getProperty(propertyKey);
            if (res == null) {
                System.out.printf("Could not find property %s in configuration%n", propertyKey);
                return "";
            }
            else {
                return res;
            }
        } catch (IOException e) {
            System.out.println("IOException caught: " + e);
            return "";
        }
    }
}