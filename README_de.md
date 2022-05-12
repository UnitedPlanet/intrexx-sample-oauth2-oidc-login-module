# Intrexx OAuth2/OpenID Connect Login Modul

## Einleitung

Mit dem Intrexx OpenID Connect Login Modul können Intrexx Benutzer über einen externen Identitätsanbieter authentifiziert und Intrexx in Single Sign On Umgebungen integriert werden. Dabei verwendet Intrexx die standardisierten OAuth2 oder OpenID Connect Verfahren. Als externe Anbieter kommen in Betracht:

- Microsoft Azure Active Directory
- MS Active Directory Federation Services v4.0
- Okta
- Keycloak
- Google
- GitHub
- oder weitere OAuth2/OpenID Connect-konforme Identity Provider

## Vorbedingungen

- Intrexx 19.03

## Konfiguration

### Login Module definieren

Bevor das Modul aktiviert werden kann, muss es in der Datei internal/cfg/LucyAuth.cfg registriert werden. Fügen Sie folgenden Block der Datei hinzu oder nehmen Sie die Zeile IntrexxOAuth2LoginModule in Ihre bestehende Login Konfiguration mit auf:

Beispiel OpenID Connect und Intrexx Standard Authentifizierung:

```text
IntrexxOAuth2
{
        de.uplanet.lucy.server.auth.module.intrexx.IntrexxOAuth2LoginModule sufficient
                debug=false;

        de.uplanet.lucy.server.auth.module.intrexx.IntrexxLoginModule sufficient
                de.uplanet.auth.allowEmptyPassword=true
                debug=true;

        de.uplanet.lucy.server.auth.module.anonymous.AnonymousLoginModule sufficient
                debug=true;
};
```

### Login Modul aktivieren am Beispiel Microsoft Azure AD

Aktiviert wird das Modul in der Datei internal/cfg/om.cfg. Ändern Sie den Eintrag für `binding scope="web"` auf die Login Konfiguration aus der LucyAuth.cfg mit dem OAuth2 Login Modul. Fügen Sie dann einen neuen `<oauth2>` Abschnitt unter `</authentication>` hinzu.

Zum Beispiel:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
    <authentication anonymous="05CE8CE3035924F7D3088895F1D87DADD65CFAE4">
        <binding scope="web" auth-type="IntrexxOAuth2"/>
        <binding scope="client" auth-type="IntrexxAuth"/>
        <binding scope="webservice" auth-type="IntrexxAuth"/>
        <binding scope="odataservice" auth-type="ODataAuth"/>
        <binding scope="documentintegration" auth-type="IntrexxAuth"/>
        <webserver-configuration plain-text-auth="false" integrated-auth="false"/>
    </authentication>
    <security/>
    <organization default-container-guid="4B87C2470868AAB57BFB31958D1F73583FB3778E" default-distlist-guid="4B87C2470868AAB57BFB31958D1F73583FB3778E"/>

<oauth2 name="azure">
    <provider
        auth-grant-type="authorization_code"
        auth-scheme="header"
        auth-protocol="code"
        auth-requires-nonce="true"
        auth-access-token-url="https://login.microsoftonline.com/<TENANT-ID>/oauth2/v2.0/token"
        auth-user-auth-url="https://login.microsoftonline.com/<TENANT-ID>/oauth2/v2.0/authorize"
        auth-pub-keys-src="https://login.microsoftonline.com/<TENANT-ID>/discovery/v2.0/keys"
        auth-user-info-url=""
        auth-scope="openid email profile"
        auth-client-id="<CLIENT-ID>"
        auth-client-secret="<CLIENT-SECRET>"
        auth-redirect-url="https://localhost:1337/oauth2/login/azure"
        auth-provider-prompt="none"
        auth-provider-login-hint=""
        />
        <mapping db-field-name="emailBiz" provider-claim-fieldname="email" enable-user-registration="true"/>
        <additional-redirect-params>
                <redirect-param key="response_type" value="code id_token"/>
                <redirect-param key="response_mode" value="form_post"/>
        </additional-redirect-params>
   </oauth2>

  <oauth2 name="keycloak">
      <provider
        auth-access-token-url="https://keycloak.local/auth/realms/dev/protocol/openid-connect/token"
        auth-client-id="<CLIENT-ID>"
        auth-client-secret="<CLIENT-SECRET>"
        auth-grant-type="authorization_code"
        auth-protocol="code"
        auth-provider-login-hint="This is a hint"
        auth-provider-prompt="none"
        auth-pub-keys-src="https:/keycloak.local/auth/realms/dev/protocol/openid-connect/certs"
        auth-redirect-url="https://localhost:1337/oauth2/login/keycloak"
        auth-requires-nonce="true"
        auth-scheme="header"
        auth-scope="openid email"
        auth-user-auth-url="https://keycloak.local/auth/realms/dev/protocol/openid-connect/auth"
        auth-user-info-url="https://keycloak.local/auth/realms/dev/protocol/openid-connect/userinfo"
        />
        <mapping db-field-name="emailBiz" provider-claim-fieldname="email" enable-user-registration="true"/>
    </oauth2>
  </configuration>
```

Ersetzen Sie darin `CLIENT_ID` und `CLIENT_SECRET` mit der Client ID, die Sie bei der Registrierung von Intrexx als App bei AzureAD erhalten haben. Des Weiteren muss die Redirect URL auf das eigene Portal angepasst werden. Anschließend muss der Portalserver neu gestartet werden.

### SSL Zertifikate importieren

Wenn der interne Zertifikatsspeicher von Intrexx benutzt wird, müssen alle vom Identity Provider verwendeten SSL Zertifikate in den Intrexx Zertifikatsspeicher importiert werden (Portaleigenschaften -> Zertifikate -> Download von URL). Alternativ kann der Zertifikatsspeicher der Intrexx Java Runtime verwendet werden (entfernen des JVM Parameters `-Djavax.net.ssl.trustStore=internal/cfg/cacerts` in der `internal/cfg/portal.wcf`).

### OAuth2 Login Button auf Portalstartseite

Damit der Authentifizierungsprozess für die Benutzeranmeldung über externen Identitätsanbieter von Intrexx aus initiiert werden kann, muss zunächst ein Request auf ein Intrexx Servlet erfolgen, dem über ein Query String Parameter mitgeteilt wird, welche Provider für die Anmeldung verwendet werden soll (in der om.cfg können mehrere Provider definiert werden). Zu Testzwecken lässt sich dazu am einfachsten eine Login Schaltfläche auf einer Portalseite einfügen:

```html
<input class="Button_Standard" type="Button" onclick="location.href='https://localhost:1337/oauth2/authorization/azure';" value="Anmeldung mit Azure AD">

Der letzte Teil des Pfads der URL muss dabei mit dem Namen der Provider Definition aus der `om.cfg` übereinstimmen.

Sie können mehrere solche Login Buttons für unterschiedliche Provider anlegen.

Für produktive Systeme wird dringend empfohlen, ein Portlet mit einem Login Button zu erstellen und dieses auf die Portalstartseite zu platzieren. In diesem Repository befindet sich eine Intrexx App mit Login Portlet als Beispiel.

### Benutzeranmeldung

Klickt ein Benutzer auf der Startseite auf einen der OAuth2 Anmelde-Buttons, wird er automatisch an den Provider umgeleitet und von diesem wieder an Intrexx. Intrexx erhält dann die Benutzerinformationen aus dem ID Token und mappt den Wert aus dem Token auf ein Feld in den Intrexx Benutzerstammdaten, um einen einzelnen Intrexx User zu identifizieren und anzumelden. Das Mapping zwischen Provider Feld und Intrexx Benutzerfeld kann in der om.cfg angepasst werden. Üblicherweise wird die E-Mailadresse des Benutzers dafür verwendet. Wichtig ist, dass die Werte in dem gewählten Benutzerstammdatenfeld eindeutig sind. Werden mehrere Benutzer anhand eines Token Werts ermittelt, wird die Anmeldung mit einem Fehler abgebrochen.

### Benutzerreplikation

Es wird empfohlen, die Benutzerstammdaten aus dem externen Identity Provider zu importieren/replizieren. Im Fall von Azure AD oder ADFS ist dies via LDAP möglich.

### Weiterführende Links

<https://docs.microsoft.com/de-de/azure/active-directory/develop/v2-protocols-oidc>

<https://developers.google.com/identity/protocols/OpenIDConnect>

<https://docs.microsoft.com/de-de/azure/active-directory/develop/v1-protocols-openid-connect-code>

<https://developer.okta.com/docs/api/resources/oidc>

### Weitere Konfigurationsbeispiele

```xml
<oauth2 name="google">
        <provider
                auth-grant-type="authorization_code"
                auth-scheme="header"
                auth-protocol="code"
                auth-requires-nonce="false"
                auth-access-token-url="https://www.googleapis.com/oauth2/v4/token"
                auth-user-auth-url="https://accounts.google.com/o/oauth2/v2/auth"
                auth-pub-keys-src="https://www.googleapis.com/oauth2/v3/certs"
                auth-user-info-url=""
                auth-scope="openid email"
                auth-client-id="CLIENT_ID"
                auth-client-secret="CLIENT_SECRET"
                auth-redirect-url="https://intrexxserver/oauth2/login/google"
                auth-provider-prompt="none"
                auth-provider-login-hint=""
        />
        <mapping db-field-name="emailBiz" provider-claim-fieldname="email"/>
</oauth2>
<oauth2 name="okta">
        <provider
                auth-grant-type="authorization_code"
                auth-scheme="header"
                auth-protocol="code"
                auth-requires-nonce="true"
                auth-access-token-url="https://dev-xxxxx.oktapreview.com/oauth2/default/v1/token"
                auth-user-auth-url="https://dev-xxxxx.oktapreview.com/oauth2/default/v1/authorize"
                auth-pub-keys-src="https://dev-748399.oktapreview.com/oauth2/default/v1/keys"
                auth-user-info-url=""
                auth-scope="openid email"
                auth-client-id="CLIENT_ID"
                auth-client-secret="CLIENT_SECRET"
                auth-redirect-url="https://intrexxserver/oauth2/login/okta"
                auth-provider-prompt="none"
                auth-provider-login-hint=""
        />
        <mapping db-field-name="emailBiz" provider-claim-fieldname="email"/>
</oauth2>
```

### Konfigurationsreferenz

- GENERAL

`unique_identifier : string [any string but unique among the oauth2 providers]`

- MAPPING

```text
db-field-name:  string [the property name or GUID of the Intrexx user schema field used to validate the claim]
provider-claim-fieldname :  string [the name of the field in the id token (json) used as claim]

Examples:

<mapping db-field-name="GUID-of-db-field" provider-claim-fieldname="email"/>
<mapping db-field-name="loginLwr" provider-claim-fieldname="preferred_username"/>
<mapping db-field-name="emailBiz" provider-claim-fieldname="email"/>
```

- OAUTH2/OIDC

```text
 auth_grant_type: 'authorization_code' [the grant type, can generally be 'authorization_code', 'implicit', ...  ] here only authorization_code
 auth_scheme: 'header'
 auth_protocol:  string [code | id_token]
 auth_requires_nonce:  boolean [if the provider requires a nonce]
 auth_access_token_url:  string [the providers url for the token]
 auth_user_auth_url:  string [the providers url for the authorization]
 auth_user_info_url:  string [the providers url for the user info endpoint, leave this empty when user attributes are already included in OIDC ID tokens]
 auth_pub_keys_src:  string [the src of the public keys of the provider. a url in terms of AWS, AZURE, etc]
 auth_oauth2_scope:  string [the scope containing at least 'openid' and the identifier of the required claim]
 auth_oauth2_client_id:  string [the client id given by the provider]
 auth_oauth2_client_secret:  string [the client secret given by the provider]
 auth_oauth2_redirect_url:  string [the url configured at the provider as redirect]
 auth_provider_prompt:  string [whether to show a prompt at all 'none' and 'consent' ar common among azure and google]
 auth_provider_login_hint:  string [hint to show with the login prompt]
```

- ADDITIONAL additional params as elements

```text
 response_type: id_token
 response_mode: form_post
 ```
