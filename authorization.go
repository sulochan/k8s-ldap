package main

import (
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/http"
)

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
	writeVerbs := []string{"update", "patch", "create"}
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

	if userConfig.RestrictNamespaceAccess {
		if userNS, ok := userConfig.UserNamespaces[req.Spec.User]; ok {
			if !hasString(userNS, "all") {
				if !hasString(userNS, req.Spec.ResourceAttributes.Namespace) {
					req.Status["allowed"] = false
					json.NewEncoder(w).Encode(req)
					return
				}
			}
		}

		for _, group := range req.Spec.Group {
			if groupNS, ok := userConfig.GroupNamespaces[group]; ok {
				// If user cant access NS and is trying to do anything other than list NS, reject.
				if req.Spec.ResourceAttributes.Resource == "namespaces" && req.Spec.ResourceAttributes.Verb != "list" {
					log.Info(fmt.Sprintf("Access denied for %s %s", req.Spec.ResourceAttributes.Resource, req.Spec.ResourceAttributes.Verb))
					req.Status["allowed"] = false
					json.NewEncoder(w).Encode(req)
					return
				}

				if !hasString(groupNS, "all") {
					if !hasString(groupNS, req.Spec.ResourceAttributes.Namespace) {
						req.Status["allowed"] = false
						json.NewEncoder(w).Encode(req)
						return
					}
				}
			}
		}
	}

	if roles, ok := userConfig.UserRoles[req.Spec.User]; ok {
		if IsAdmin(roles) {
			req.Status["allowed"] = true
			json.NewEncoder(w).Encode(req)
			return
		}

		if userHazVerb(roles, req.Spec.ResourceAttributes.Verb) {
			req.Status["allowed"] = true
			json.NewEncoder(w).Encode(req)
			return
		} else {
			req.Status["allowed"] = false
			json.NewEncoder(w).Encode(req)
			return
		}
	}

	for _, group := range req.Spec.Group {
		if roles, ok := userConfig.GroupRoles[group]; ok {
			if IsAdmin(roles) {
				req.Status["allowed"] = true
				json.NewEncoder(w).Encode(req)
				return
			}

			if userHazVerb(roles, req.Spec.ResourceAttributes.Verb) {
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
