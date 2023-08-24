# Poort8.Ishare.Core.Java
This library contains some core iSHARE functionality in Java.

### Configuration
The configuration file (config.properties) contains the following properties that need to be configured:
- ApiUrl: Your iSHARE endpoint URL
- ClientId: Your EORI (for example, EU.EORI.NL000000001)
- Certificate: The text value of your iSHARE certificate
  - **Exclude** the `-----BEGIN CERTIFICATE-----` prefix and `-----END CERTIFICATE-----` postfix
- Private key:  The text value of your iSHARE private key
  - **Exclude** the `-----BEGIN PRIVATE KEY-----` prefix and `-----END PRIVATE KEY-----` postfix

_Note: the values in the configuration file don't have to be put between quotations, such as `'` or `"`_


### Methods
The main class of this library is the `Authorisation` class, it contains the following methods.

#### GetAccessToken
GetAccessToken returns the delegation token from the authorization registry as a string. It uses a private method (CreateClientAssertion) to create a Json Web Token (JWT), which is needed in order to request a delegation token.
##### Parameters
- (String) `partyId`: The EORI of the party whose resource you want to request.

#### GetDelegationEvidence
GetDelegationEvidence creates a delegation request and returns the delegation evidence from the authorization registry as a string. 
##### Parameters
- (String) `accessToken`: The delegation token.
- (String) `subject`: The iSHARE identifier of the party that holds the delegated rights.
- (String) `resourceType`: The type of resource you want to access.
- (String) `resourceIdentifier`: The identifier of resource you want to access.
- (String) `action`: The type of action you want to preform.

#### VerifyAccess
VerifyAccess returns a boolean based on the delegation evidence and verification parameters. If access is permitted according to the delegation evidence, it will return `true`. If access was not permitted, it will return `false`.
##### Parameters
- (String) `accessToken`: The delegation token.
- (String) `issuer`: The iSHARE identifier of the party that issued the resource.
- (String) `subject`: The iSHARE identifier of the party that holds the delegated rights.
- (String) `resourceType`: The type of resource you want to access.
- (String) `resourceIdentifier`: The identifier of resource you want to access.
- (String) `action`: The type of action you want to preform.

_Note: if a type of verification needs to be skipped, pass `null` as the value for the designated parameter._



### Usage example
1. Retrieve your access token from the party using the GetAccessToken method.
```
String accessToken = Authorisation.GetAccessToken("EU.EORI.NL000000002");
```
2. Use the GetDelegationEvidence method with the access token you previously received and the parameters related to the resource.
```
String delegationEvidence = Authorisation.GetDelegationEvidence(accessToken, "EU.EORI.NL000000002", "GS1.CONTAINER","180621.CONTAINER-Z", "ISHARE.READ");
```
3. Use the VerifyAccess method with the delegation evidence you previously received and the parameters that need to be verified.
```
boolean hasAccess = Authorisation.VerifyAccess(delegationEvidence, "EU.EORI.NL000000003", "EU.EORI.NL000000002", "GS1.CONTAINER","180621.CONTAINER-Z", "ISHARE.READ");
```
- If, for example, you would like to skip the check on the subject: pass `null`.
```
boolean hasAccess = Authorisation.VerifyAccess(delegationEvidence, "EU.EORI.NL000000003", null, "GS1.CONTAINER","180621.CONTAINER-Z", "ISHARE.READ");
```
4. The value of `hasAccess` will tell you if access was permitted (`true`) or denied (`false`).