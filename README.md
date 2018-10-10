# Intrexx OAuth2/OpenID Connect Login Modul

## Einleitung

Mit dem Intrexx OpenID Connect Login Modul können Intrexx Benutzer über einen externen Identitätsanbieter authentifiziert und Intrexx in Single Sign On Umgebungen integriert werden. Dabei verwendet Intrexx die standardisierten OAuth2 oder OpenID Connect Verfahren. Als externe Anbieter kommen in Betracht:

- Microsoft Azure Active Directory
- MS Active Directory Federation Services v4.0
- Okta
- Keycloak
- Google
- Facebook
- GitHub
- oder weitere OAuth2/OIDC-konforme Identity Provider

## Vorbedingungen

- Intrexx 18.03 ab OU4 oder Intrexx 18.09
- Für Intrexx 18.03 und Microsoft IIS wird das URL Rewrite Modul benötigt, um die OAuth2 Callbacks an den Portalserver weiterzuleiten

## Konfiguration

### Login Module definieren

Bevor das Modul aktiviert werden kann, muss es in der Datei internal/cfg/LucyAuth.cfg registriert werden. Fügen Sie folgenden Block der Datei hinzu oder nehmen Sie die Zeile IntrexxOAuth2LoginModule in Ihre bestehende Login Konfiguration mit auf:

Beispiel OpenID Connect und Intrexx Standard Authentifizierung:

`
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
`

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
                auth-pub-keys-src="https://login.microsoftonline.com/common/discovery/v2.0/keys"
                auth-scope="openid email"
                auth-client-id="CLIENT_ID"
                auth-client-secret="CLIENT_SECRET"
                auth-redirect-url="https://intrexx/portal/oauth2login"
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

### Umleitungsregeln für OAuth2 Callbacks einrichten

Wenn ein Benutzer nicht angemeldeter Benutzer auf das Portal zugreift, wird er vom Modul automatisch auf die Anmeldeseite des Identity Providers umgeleitet. Nach Anmeldung findet dann eine Umleitung zu Intrexx mit dem ID Token statt. Damit dieser Redirect korrekt an Intrexx weitgeleitet wird, benötigt man für Intexx eine Umleitungsregel im Frontend-Webserver.

#### Microsoft Internet Information Server

Installieren Sie das IIS Module "Url Rewrite" von Microsoft. Anschließend erstellen Sie eine neue Umleitungsregel wie hier beschrieben:

http://up-download.de/up/docs/intrexx-onlinehelp/8100/de/index.html?p=helpfiles/help.2.connectoren-office-365.html#IIS-Konfiguration

Tragen Sie dabei im Feld "Muster" den Ausdruck `oauth2login` ein und unter "URL umschreiben" den Ausdruck `default.asp?urn:schemas-unitedplanet-de:ixservlet:name=oAuth2LoginIxServlet` ein.

#### Tomcat

Bei der Verwendung von Tomcat als Webserver muss der Redirect für OAuth2 in der Datei "server.xml" im Installationsverzeichnis /tomcat/conf eingetragen werden. Suchen Sie dort im Host-Abschnitt am Ende der Datei nach dem folgenden Eintrag:  

```xml
<Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs" pattern="%h %l %u %t "%r" %s %b %D "%{User-Agent}i"" prefix="localhost_access_log" suffix=".txt"/>
```

Fügen Sie direkt darunter den Eintrag  

```xml
<Valve className="org.apache.catalina.valves.rewrite.RewriteValve" />
```

hinzu. Erstellen Sie dann mit einem beliebigen Texteditor eine Textdatei mit dem Namen "rewrite.config". Fügen Sie den folgenden Inhalt ein:  

```xml
RewriteRule /<portalname>/oauth2login?(.*) /<portalname>/default.ixsp?urn:schemas-unitedplanet-de:ixservlet:name=oAuth2LoginIxServlet&%{QUERY_STRING} [NC,L]
```

Bitte beachten Sie die Groß-/Kleinschreibung beim Portalnamen. Den Portalnamen können Sie in den Portaleigenschaften im Feld "Context" ermitteln. Legen Sie die rewrite.config-Datei im Installationsverzeichnis `/tomcat/conf/Catalina/<host>` ab. Führen Sie anschließend einen Neustart des Intrexx Tomcat Servlet Containers aus.

#### Intrexx 18.09 mit Tomcat / IIS

In dieser Variante wird keine Umleitungsregel benötigt. Der OAuth2 Login Endpunkt heißt hier:

`/service/oauth2/authorize`

### SSL Zertifikate importieren

Wenn der interne Zertifikatsspeicher von Intrexx benutzt wird, müssen alle vom Identity Provider verwendeten SSL Zertifikate in den Intrexx Zertifikatsspeicher importiert werden (Portaleigenschaften -> Zertifikate -> Download von URL). Alternativ kann der Zertifikatsspeicher der Intrexx Java Runtime verwendet werden (entfernen des JVM Parameters `-Djavax.net.ssl.trustStore=internal/cfg/cacerts` in der `internal/cfg/portal.wcf`).

### OAuth2 Login Button auf Portalstartseite

Damit der Authentifizierungsprozess für die Benutzeranmeldung über externen Identitätsanbieter von Intrexx aus initiiert werden kann, muss zunächst ein Request auf ein Intrexx Servlet erfolgen, dem über ein Query String Parameter mitgeteilt wird, welche Provider für die Anmeldung verwendet werden soll (in der om.cfg können mehrere Provider definiert werden). Dazu lässt sich am einfachsten eine Login Schaltfläche auf der Portal Anmeldeseite (oder einer anderen Portalseite) einfügen. Öffnen Sie dazu die Datei `\org\portal\internal\system\vm\html\login\logincore.vm` und fügen Sie folgende Zeile unterhalb der Login Form ein:

```html
<input class="Button_Standard" type="Button" onclick="location.href='?urn:schemas-unitedplanet-de:ixservlet:name=oAuth2LoginIxServlet&oauthProvider=azuread';" value="Anmeldung mit Azure AD">
```

Passen Sie dabei ggf. den Parameter `oauthProvider` an und tragen als Wert den Namen der Provider Definition aus der `om.cfg` ein.

Sie können mehrere solche Login Buttons für unterschiedliche Provider anlegen.

### Benutzeranmeldung

Klickt ein Benutzer auf der Startseite auf einen der OAuth2 Anmelde-Buttons, wird er automatisch an den Provider umgeleitet und von diesem wieder an Intrexx. Intrexx erhält dann die Benutzerinformationen aus dem ID Token und mappt den Wert aus dem Token auf ein Feld in den Intrexx Benutzerstammdaten, um einen einzelnen Intrexx User zu identifizieren und anzumelden. Das Mapping zwischen Provider Feld und Intrexx Benutzerfeld kann in der om.cfg angepasst werden. Üblicherweise wird die E-Mailadresse des Benutzers dafür verwendet. Wichtig ist, dass die Werte in dem gewählten Benutzerstammdatenfeld eindeutig sind. Werden mehrere Benutzer anhand eines Token Werts ermittelt, wird die Anmeldung mit einem Fehler abgebrochen.

### Benutzerreplikation

Es wird empfohlen, die Benutzerstammdaten aus dem externen Identity Provider zu importieren/replizieren. Im Fall von Azure AD oder ADFS ist die via LDAP möglich.

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
                auth-redirect-url="https://localhost/test/oauth2login" 
                auth-requires-nonce="true" 
                auth-scheme="header" 
                auth-scope="openid email" 
                auth-user-auth-url="https://login.microsoftonline.com/common/oauth2/authorize"/>
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
                auth-scope="openid email"
                auth-client-id="CLIENT_ID"
                auth-client-secret="CLIENT_SECRET"
                auth-redirect-url="https://localhost/test/oauth2login"
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
                auth-scope="openid email"
                auth-client-id="CLIENT_ID"
                auth-client-secret="CLIENT_SECRET"
                auth-redirect-url="https://localhost/test/oauth2login"
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
                auth-pub-keys-src="https://dev-748399.oktapreview.com/oauth2/default/v1/keys"
                auth-scope="openid email"
                auth-client-id="CLIENT_ID"
                auth-client-secret="CLIENT_SECRET"
                auth-redirect-url="https://localhost/default.ixsp?urn:schemas-unitedplanet-de:ixservlet:name=oAuth2LoginIxServlet"
                auth-provider-prompt="none"
                auth-provider-login-hint="This is a hint"
        />
        <mapping db-field-name="emailBiz" provider-claim-fieldname="email"/>
</oauth2>
```

### Konfigurationsreferenz

- GENERAL

-- unique_identifier = string [any string but unique among the oauth2 providers] 

- MAPPING

-- auth_DB_field_name_for_claim =  string [the name of the field respectively the column in the db used to validate the claim]
-- auth_provider_field_for_claim  =  string [the name of the field in the id token (json) used as claim]

- OAUTH2/OIDC

-- auth_grant_type  =  'authorization_code' [the grant type, can generally be 'authorization_code', 'implicit', ...  ] here only authorization_code
-- auth_scheme  =  'header'
-- auth_protocol  =  string [code | id_token]
-- auth_requires_nonce  =  boolean [if the provider requires a nonce]
-- auth_access_token_url =  string [the providers url for the token]
-- auth_user_auth_url  =  string [the providers url for the authorization]
-- auth_pub_keys_src  =  string [the src of the public keys of the provider. a url in terms of AWS, AZURE, etc]
-- auth_oauth2_scope =  string [the scope containing at least 'openid' and the identifier of the required claim]
-- auth_oauth2_client_id =  string [the client id given by the provider]
-- auth_oauth2_client_secret =  string [the client secret given by the provider]
-- auth_oauth2_redirect_url   =  string [the url configured at the provider as redirect]
-- auth_provider_prompt   =  string [whether to show a prompt at all 'none' and 'consent' ar common among azure and google]
-- auth_provider_login_hint  =  string [hint to show with the login prompt]

- ADDITIONAL additional params as elements

-- response_type = id_token
-- response_mode = form_post