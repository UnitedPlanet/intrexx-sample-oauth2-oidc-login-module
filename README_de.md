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
      <mobile-devices plain-text-auth="never"/>
   </authentication>

   <oauth2 name="azuread">
        <provider
                auth-grant-type="authorization_code"
                auth-scheme="header"
                auth-protocol="id_token"
                auth-requires-nonce="true"
                auth-access-token-url="https://login.microsoftonline.com/common/oauth2/v2.0/token"
                auth-user-auth-url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
                auth-user-info-url=""
                auth-pub-keys-src="https://login.microsoftonline.com/common/discovery/v2.0/keys"
                auth-scope="openid email"
                auth-client-id="CLIENT_ID"
                auth-client-secret="CLIENT_SECRET"
                auth-redirect-url="https://intrexxserver/login/oic/authenticate"
                auth-provider-prompt="none"
                auth-provider-login-hint="This is a hint"
        />
        <mapping db-field-name="emailBiz" provider-claim-fieldname="email"/>
        <additional-redirect-params>
                <redirect-param key="response_type" value="id_token"/>
                <redirect-param key="response_mode" value="form_post"/>
        </additional-redirect-params>
   </oauth2>

   <security/>
   <organization default-container-guid="4B87C2470868AAB57BFB31958D1F73583FB3778E" default-distlist-guid="4B87C2470868AAB57BFB31958D1F73583FB3778E"/>
</configuration>
```

Ersetzen Sie darin `CLIENT_ID` und `CLIENT_SECRET` mit der Client ID, die Sie bei der Registrierung von Intrexx als App bei AzureAD erhalten haben. Des Weiteren muss die Redirect URL auf das eigene Portal angepasst werden. Anschließend muss der Portalserver neu gestartet werden.

### SSL Zertifikate importieren

Wenn der interne Zertifikatsspeicher von Intrexx benutzt wird, müssen alle vom Identity Provider verwendeten SSL Zertifikate in den Intrexx Zertifikatsspeicher importiert werden (Portaleigenschaften -> Zertifikate -> Download von URL). Alternativ kann der Zertifikatsspeicher der Intrexx Java Runtime verwendet werden (entfernen des JVM Parameters `-Djavax.net.ssl.trustStore=internal/cfg/cacerts` in der `internal/cfg/portal.wcf`).

### OAuth2 Login Button auf Portalstartseite

Damit der Authentifizierungsprozess für die Benutzeranmeldung über externen Identitätsanbieter von Intrexx aus initiiert werden kann, muss zunächst ein Request auf ein Intrexx Servlet erfolgen, dem über ein Query String Parameter mitgeteilt wird, welche Provider für die Anmeldung verwendet werden soll (in der om.cfg können mehrere Provider definiert werden). Zu Testzwecken lässt sich dazu am einfachsten eine Login Schaltfläche auf der Portal Anmeldeseite (oder einer anderen Portalseite) einfügen. Öffnen Sie dazu die Datei `\org\portal\internal\system\vm\html\login\logincore.vm` und fügen Sie folgende Zeile unterhalb der Login Form ein:

```html
<input class="Button_Standard" type="Button" onclick="location.href='?urn:schemas-unitedplanet-de:ixservlet:name=oAuth2LoginIxServlet&oauthProvider=azuread';" value="Anmeldung mit Azure AD">
```

Passen Sie dabei ggf. den Parameter `oauthProvider` an und tragen als Wert den Namen der Provider Definition aus der `om.cfg` ein.

Sie können mehrere solche Login Buttons für unterschiedliche Provider anlegen.

Für produktive Systeme wird dringend empfohlen, ein Portlet mit einem Login Button zu erstellen und dieses auf die Portalstartseite zu platzieren. Ansonsten werden die Änderungen an der logincore.vm durch Intrexx Updates unter Umständen wieder überschrieben. In diesem Repository befindet sich eine Intrexx App mit Login Portlet als Beispiel.

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
<oauth2 name="azurev1">
        <provider
                auth-access-token-url="https://login.microsoftonline.com/common/oauth2/token"
                auth-client-id="CLIENT_ID"
                auth-client-secret="CLIENT_SECRET"
                auth-grant-type="authorization_code" auth-protocol="id_token"
                auth-provider-login-hint="This is a hint"
                auth-provider-prompt="none"
                auth-pub-keys-src="https://login.microsoftonline.com/common/discovery/keys"
                auth-redirect-url="https://intrexxserver/login/oic/authenticate"
                auth-requires-nonce="true"
                auth-scheme="header"
                auth-scope="openid email"
                auth-user-auth-url="https://login.microsoftonline.com/common/oauth2/authorize"
                auth-user-info-url=""/>
        />
        <mapping db-field-name="emailBiz" provider-claim-fieldname="upn"/>
        <additional-redirect-params>
                <redirect-param key="response_type" value="id_token"/>
                <redirect-param key="response_mode" value="form_post"/>
        </additional-redirect-params>
</oauth2>
<oauth2 name="azurev2">
        <provider
                auth-grant-type="authorization_code"
                auth-scheme="header"
                auth-protocol="id_token"
                auth-requires-nonce="true"
                auth-access-token-url="https://login.microsoftonline.com/common/oauth2/v2.0/token"
                auth-user-auth-url="https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
                auth-pub-keys-src="https://login.microsoftonline.com/common/discovery/v2.0/keys"
                auth-user-info-url=""
                auth-scope="openid email"
                auth-client-id="CLIENT_ID"
                auth-client-secret="CLIENT_SECRET"
                auth-redirect-url="https://intrexxserver/login/oic/authenticate"
                auth-provider-prompt="none"
                auth-provider-login-hint="This is a hint"
        />
        <mapping db-field-name="emailBiz" provider-claim-fieldname="email"/>
        <additional-redirect-params>
                <redirect-param key="response_type" value="id_token"/>
                <redirect-param key="response_mode" value="form_post"/>
        </additional-redirect-params>
</oauth2>
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
                auth-redirect-url="https://intrexxserver/login/oic/authenticate"
                auth-provider-prompt="none"
                auth-provider-login-hint="This is a hint"
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
                auth-pub-keys-src="https://dev-xxxxx.oktapreview.com/oauth2/default/v1/keys"
                auth-user-info-url=""
                auth-scope="openid email"
                auth-client-id="CLIENT_ID"
                auth-client-secret="CLIENT_SECRET"
                auth-redirect-url="https://intrexxserver/login/oic/authenticate"
                auth-provider-prompt="none"
                auth-provider-login-hint="This is a hint"
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
 auth_user_info_url:  string [the providers url for the user info endpoint]
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
