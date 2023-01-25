# Configuration ADFS
- Dans les réglages de l'extension (module settings ou fichier LocalConfiguration.php) :
  - enableFEADFSAuthentication
  - ADFSIssuer
  - ADFSRedirectUriPrefix
- Dans le fichier config.yaml de chaque site
````
adfs
  clientId:
  clientSecret:
````
