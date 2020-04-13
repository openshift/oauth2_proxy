package main

import (
	"encoding/csv"
	"github.com/openshift/oauth-proxy/providers"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"unsafe"
)

type UserIDMap struct {
	usersFile string
	m         unsafe.Pointer
}

func NewUserIDMap(usersFile string, done <-chan bool, onUpdate func()) *UserIDMap {
	um := &UserIDMap{usersFile: usersFile}
	m := make(map[string]bool)
	atomic.StorePointer(&um.m, unsafe.Pointer(&m))
	if usersFile != "" {
		log.Printf("using authenticated uids file %s", usersFile)
		WatchForUpdates(usersFile, done, func() {
			um.LoadAuthenticatedUIDsFile()
			onUpdate()
		})
		um.LoadAuthenticatedUIDsFile()
	}
	return um
}

func (um *UserIDMap) IsValid(uid string) (result bool) {
	m := *(*map[string]bool)(atomic.LoadPointer(&um.m))
	_, result = m[uid]
	return
}

func (um *UserIDMap) LoadAuthenticatedUIDsFile() {
	r, err := os.Open(um.usersFile)
	if err != nil {
		log.Fatalf("failed opening authenticated-uids-file=%q, %s", um.usersFile, err)
	}
	defer r.Close()
	csv_reader := csv.NewReader(r)
	csv_reader.Comma = ','
	csv_reader.Comment = '#'
	csv_reader.TrimLeadingSpace = true
	records, err := csv_reader.ReadAll()
	if err != nil {
		log.Printf("error reading authenticated-uids-file=%q, %s", um.usersFile, err)
		return
	}
	updated := make(map[string]bool)
	for _, r := range records {
		uid := strings.TrimSpace(r[0])
		updated[uid] = true
	}
	atomic.StorePointer(&um.m, unsafe.Pointer(&updated))
}

func newUserValidatorImpl(uids []string, usersFile string,
	done <-chan bool, onUpdate func()) func(providers.SessionState) bool {
	validUIDsStorage := NewUserIDMap(usersFile, done, onUpdate)

	var allowAll bool
	for _, uid := range uids {
		if uid == "*" {
			allowAll = true
			continue
		}
	}

	validator := func(s providers.SessionState) (valid bool) {
		log.Printf("Checking session %s", s.UserUID)
		log.Printf("Checking %s#%s", s.UserUID, s.User)
		if s.UserUID == "" {
			//TODO Kubeadmin does not have uid
			log.Printf("user id is empty. Returning %b", valid)
			return
		}
		for _, uids := range uids {
			valid = valid || s.UserUID == uids
			log.Printf("Comparing %s=%s. is the same: %b, is valid: %b", s.UserUID, uids, s.UserUID == uids, valid)
		}
		if !valid {
			valid = validUIDsStorage.IsValid(s.UserUID)
		}
		if allowAll {
			valid = true
		}
		return valid
	}
	return validator
}

func NewUserValidator(ids []string, usersFile string) func(providers.SessionState) bool {
	return newUserValidatorImpl(ids, usersFile, nil, func() {})
}
