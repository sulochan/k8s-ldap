package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	log "github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
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

func main() {
	app := &cli.App{
		Name: "k8s-ldap",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "key",
				Usage:    "key.pem to use for ssl",
				Required: true,
				EnvVars:  []string{"K8S_LDAP_KEY"},
			},
			&cli.StringFlag{
				Name:     "cert",
				Usage:    "cert.pem to use for ssl",
				Required: true,
				EnvVars:  []string{"K8S_LDAP_CERT"},
			},
			&cli.StringFlag{
				Name:     "url",
				Usage:    "ldap server url",
				Required: true,
				EnvVars:  []string{"K8S_LDAP_URL"},
			},
			&cli.StringFlag{
				Name:     "config",
				Usage:    "k8s-ldap config file",
				Required: true,
				EnvVars:  []string{"K8S_LDAP_CONFIG"},
			},
		},
		Action: func(c *cli.Context) error {
			RunServer(c)
			return nil

		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal("app.Run failed: ", err)
	}
}

func RunServer(c *cli.Context) {
	loadConfig(c)
	ldapURL = "ldaps://" + c.String("url")
	http.HandleFunc("/authenticate", AuthenticationHandler)
	http.HandleFunc("/authorize", AuthorizationHandler)
	log.Info("Starting Server ...")
	log.Info("Using ", c.String("key"), "", c.String("cert"))
	log.Fatal(http.ListenAndServeTLS(":443", c.String("cert"), c.String("key"), nil))
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
