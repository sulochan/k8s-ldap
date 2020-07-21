package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	log "github.com/sirupsen/logrus"
	"net/http"
	"os"
)

var ldapURL string

// TokenReview - token review request struct from k8s
type TokenReview struct {
	Kind       string                 `json:"kind"`
	ApiVersion string                 `json:"apiVersion"`
	Metadata   map[string]interface{} `json:"metadata"`
	Spec       map[string]string      `json:"spec"`
	Status     map[string]interface{} `json:"status"`
}

// ResourceAttributes - attributes for authz request
type ResourceAttributes struct {
	Namespace string `json:"namespace"`
	Verb      string `json:"verb"`
	Version   string `json:"version"`
	Resource  string `json:"resource"`
}

// Spec - authz request spec object
type Spec struct {
	Group              []string `json:"group"`
	User               string   `json:"user"`
	UID                string   `json:"uid"`
	ResourceAttributes `json:"resourceAttributes"`
}

// SubjectAccessReview - authz access review request struct from k8s
type SubjectAccessReview struct {
	Kind       string                 `json:"kind"`
	ApiVersion string                 `json:"apiVersion"`
	Spec       Spec                   `json:"spec"`
	User       string                 `json:"user"`
	Group      []string               `json:"group"`
	Status     map[string]interface{} `json:"status"`
}

func main() {
	ldapURL = "ldaps://" + os.Args[1]
	http.HandleFunc("/authenticate", AuthenticationHandler)
	http.HandleFunc("/authorize", AuthorizationHandler)
	log.Fatal(http.ListenAndServeTLS(":9191", os.Args[3], os.Args[2], nil))
}

func IsAdmin(roles []string) bool {
	for _, role := range roles {
		if role == "admin" {
			return true
		}
	}

	return false
}

func hasString(s []string, val string) bool {
	for _, item := range s {
		if item == val {
			return true
		}
	}
	return false
}

// user can read, write and delete resources.
func userHazVerb(roles []string, verb string) bool {
	readVerbs := []string{"get", "watch", "list"}
	writeVerbs := []string{"update", "patch"}
	deleteVerbs := []string{"delete"}

	for _, role := range roles {
		if role == "read" && hasString(readVerbs, verb) {
			return true
		}

		if role == "write" && hasString(writeVerbs, verb) {
			return true
		}

		if role == "delete" && hasString(deleteVerbs, verb) {
			return true
		}
	}

	return false
}

// AuthorizationHandler - handles authorization request from k8s api.
func AuthorizationHandler(w http.ResponseWriter, r *http.Request) {
	var req *SubjectAccessReview
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		log.Error("Error decoding authorization request ", err)
		http.Error(w, "Error decoding authz request", 400)
		return
	}

	log.WithFields(log.Fields{"User": req.Spec.User, "Resource": req.Spec.ResourceAttributes.Resource,
		"Verb": req.Spec.ResourceAttributes.Verb,
	}).Info("Authorization handler called.")

	userConfig := GetConfig()
	if roles, ok := userConfig.UserRoles[req.Spec.User]; ok {
		if IsAdmin(roles) {
			req.Status["allowed"] = true
			json.NewEncoder(w).Encode(req)
			return
		}

		if userHazVerb(roles, req.Spec.ResourceAttributes.Verb) {
			log.Info("User haz verb")
			req.Status["allowed"] = true
			json.NewEncoder(w).Encode(req)
			return
		} else {
			log.Info("User permission not in read/write/delete. No access allowed.")
			req.Status["allowed"] = false
			json.NewEncoder(w).Encode(req)
			return
		}
	}

	for _, group := range req.Spec.Group {
		if roles, ok := userConfig.GroupRoles[group]; ok {
			if IsAdmin(roles) {
				log.Info("group is admin")
				req.Status["allowed"] = true
				json.NewEncoder(w).Encode(req)
				return
			}

			if userHazVerb(roles, req.Spec.ResourceAttributes.Verb) {
				log.Info("group haz verb")
				req.Status["allowed"] = true
				json.NewEncoder(w).Encode(req)
				return
			}
		}
	}

	req.Status["allowed"] = false
	req.Status["reason"] = "User does not have permission."
	json.NewEncoder(w).Encode(req)
	return
}

// AuthenticationHandler - handles authentication request from k8s api.
func AuthenticationHandler(w http.ResponseWriter, r *http.Request) {
	var req *TokenReview
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&req)
	if err != nil {
		log.Error("Error decoding auth request ", err)
		http.Error(w, "Error decoding auth request", 400)
		return
	}

	if !(strings.Contains(req.Spec["token"], ":")) {
		http.Error(w, "Error: no username:password combination in request", 400)
		return
	}

	up := strings.SplitN(req.Spec["token"], ":", 2)
	username := up[0]
	password := up[1]

	log.WithFields(log.Fields{"User": username}).Info("Authenticating user with LDAP server.")

	groups, err := getADGroups(username, password)
	if err != nil {
		// Auth failed.
		req.Status = map[string]interface{}{"authenticated": false}
		json.NewEncoder(w).Encode(req)
		return
	}

	config := GetConfig()
	// first look for user in userRoles as that takes precedence.
	if _, ok := config.UserRoles[username]; ok {
		// user exists with permission so auth ok
		req.Status = map[string]interface{}{"authenticated": true}
		req.Status["user"] = map[string]interface{}{"username": username, "uid": "314", "groups": groups}
		json.NewEncoder(w).Encode(req)
		return
	}

	// now just check if one of user's group is allowed
	for _, group := range groups {
		if _, ok := config.GroupRoles[group]; ok {
			// user exists with permission so auth ok
			req.Status["authenticated"] = true
			req.Status["user"] = map[string]interface{}{"username": username, "uid": "314", "groups": groups}
			json.NewEncoder(w).Encode(req)
			return
		}
	}

	log.WithFields(log.Fields{"User": username}).Info("No matching group or user attribute. Authentication rejected.")
	req.Status["authenticated"] = false
	json.NewEncoder(w).Encode(req)
	return
}

// getADGroups - bind the user to ldap, and return its groups
func getADGroups(username, password string) ([]string, error) {
	// groups holds all the groups the user belongs to
	groups := []string{}

        // TODO: make this config var
	config := &tls.Config{InsecureSkipVerify: true}

	ldapConn, err := ldap.DialURL(ldapURL, ldap.DialWithTLSConfig(config))
	if err != nil {
		log.Error("Error getting ldap connection : ", err)
		return groups, err
	}
	defer ldapConn.Close()

	userConfig := GetConfig()

	// for specific cases where AD server binds with @domain.com
	// if such domain is defined in the config, we append it to the
	// username and try to bind with that.
	binduser := username
	if userConfig.BindDomain != "" {
		binduser = username + "@" + userConfig.BindDomain
	}

	log.WithFields(log.Fields{"User": binduser}).Info("Attempting to bind user.")
	err = ldapConn.Bind(binduser, password)
	if err != nil {
		log.Error("Error binding user to ldap server : ", err)
		return groups, err
	}

	log.WithFields(log.Fields{"User": username}).Info("Serching user membership.")

	searchString := fmt.Sprintf("(&(objectCategory=person)(objectClass=user)(samAccountName=%s))", username)
	if userConfig.Filter != "" {
		searchString = fmt.Sprintf(userConfig.Filter, username)
	}

	memberSearchAttribute := "memberOf"
	if userConfig.MemberSearchAttribute != "" {
		memberSearchAttribute = userConfig.MemberSearchAttribute
	}

	searchRequest := ldap.NewSearchRequest(
		userConfig.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		searchString,
		[]string{memberSearchAttribute},
		nil,
	)

	sr, err := ldapConn.Search(searchRequest)
	if err != nil {
		log.Error("Error searching user properties : ", err)
		return groups, err
	}

	entry := sr.Entries[0]
	for _, i := range entry.Attributes {
		for _, attr := range i.Values {
			groupList := strings.Split(attr, ",")
			for _, g := range groupList {
				if strings.HasPrefix(g, "CN=") {
					group := strings.Split(g, "=")
					groups = append(groups, group[1])
				}
			}
		}
	}

	return groups, nil
}
