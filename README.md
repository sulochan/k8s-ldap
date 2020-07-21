## k8s-ldap

LDAP Webhook authentication and authorisation plugin.
k8s LDAP authn-authz middleware that can talk to your ldap server, and have configurable authentication and authorisation rules based on ldap groups or user specific overrides. 

To run k8s-ldap:

    1. openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout key.pem -out cert.pem
    2. go build .
    3. ./k8s-ldap <your ldap server address> key.pem cert.pem
    

Your config file should be available in the same directory.

##### Config.json :
Configuration options:
1. **"BindDomain" : "example.com" (Optional)**
Bind Domain is only used if your username does not contain the domain. For example, if your username is jack.johnson, but you need
jack.johnson@example.com to be able to bind to ldap. Remove this from config if you simply want to bind with your username.
2. **"BaseDN": "dc=example,dc=com" (Required)**
This is the BaseDN for the ldap domain, this is required.
3. **"Filter": "(&(objectCategory=person)(objectClass=user)(samAccountName=%s))" (Required)**
You can use a different filter to search for user to authenticate. This field is required.
4. **"MemberSearchAttribute": "memberOf" (Required)**
Attribue by which group membership is found in ldap, most of the time its simply "memberOf" or "ismemberOf". This field is required.

5. **"GroupRoles" (Required)**
Group roles defines what permission this group has on the k8s API. For example, "GroupRoles": {"group1": ["admin"], "group2": ["read"]} will give members of group1 admin privileges (Read/Write/Delete) on all resources and verbs on your k8s cluster. Whereas members of group2 will only have read - List/Watch - privileges.

6. **"UserRoles" (Optional)**
User roles can override group roles. If you have user within  a group that needs more privilege than the rest of the group you can define it here. You can also restrict access to a specific user(s) with the same logic.

##### Configuring k8s cluster for LDAP Webhook :
Use your cluster deployment tool to achieve the following or add the following fields to your k8s api server:

Authentication - is driven by 2 flags, namely:

     --authentication-token-webhook-config-file
     --authentication-token-webhook-cache-ttl

Add the following to your k8s-api manifest, pointing webhook-config-file to a yaml with the following content:
 
 

    # Filename: webhook-authn-config.yaml
    
    # clusters refers to the remote service.
    clusters:
    - name: webhook-token-auth-cluster
      cluster:
        server: https://localhost:9191/authenticate
        insecure-skip-tls-verify: true
    
    # users refers to the API server's webhook configuration.
    users:
    - name: webhook-token-auth-user
    
    current-context: webhook-token-auth
    contexts:
    - context:
        cluster: webhook-token-auth-cluster
        user: webhook-token-auth-user
      name: webhook-token-auth

So your api-server configuration should consist of the following:

    --authentication-token-webhook-config-file=webhook-authn-config.yaml
    --authentication-token-webhook-cache-ttl=5m0s

Authorisation, similarly, is controlled by the following flags:

    --authorization-webhook-config-file
    --authorization-mode=Node,RBAC,Webhook

Add the follow lines to your api-server manifest, with authorization-webhook-config-file pointing to a yaml with the follwing content:

    # Filename: webhook-authz-config.yaml
    
    # clusters refers to the remote service.
    clusters:
    - name: webhook-token-authz-cluster
      cluster:
        server: https://localhost:9191/authorize
        insecure-skip-tls-verify: true
    
    # users refers to the API server's webhook configuration.
    users:
    - name: webhook-token-authz-user
    
    current-context: webhook-token-authz
    contexts:
    - context:
        cluster: webhook-token-authz-cluster
        user: webhook-token-authz-user
      name: webhook-token-authz

So, your server-api configuration should consist of line that look similar to:

    --authorization-webhook-config-file=webhook-authz-config.yaml
    --authorization-mode=Node,RBAC,Webhook

At this point, you can look at both api-server logs, and k8s-ldap logs to see authentication and authorisation request getting process though the webhook middleware.
# k8s-ldap
