package keychain

import (
	"fssh/internal/i18n"
    "errors"
    "fmt"
    "os"
    "time"

    kc "github.com/keybase/go-keychain"
    "fssh/internal/macos"
)

const account = "master_key_v1"

// Keychain items are per macOS user, not per $HOME. FSSH_KEYCHAIN_SERVICE
// isolates development and test runs from the real master key. Read on every
// call so tests can set it at runtime.
func services() (current, legacy string) {
    if s := os.Getenv("FSSH_KEYCHAIN_SERVICE"); s != "" {
        return s, s + "-legacy"
    }
    return "fssh", "fingerpass"
}

func MasterKeyExists() (bool, error) {
    serviceNew, serviceOld := services()
    exists, err := masterKeyExistsForService(serviceNew)
    if err != nil {
        return false, err
    }
    if exists {
        return true, nil
    }
    return masterKeyExistsForService(serviceOld)
}

func masterKeyExistsForService(svc string) (bool, error) {
    q := kc.NewItem()
    q.SetSecClass(kc.SecClassGenericPassword)
    q.SetService(svc)
    q.SetAccount(account)
    q.SetMatchLimit(kc.MatchLimitOne)
    // Only ask for attributes: reading the secret data could trigger a
    // Keychain authorization dialog just to check for existence.
    q.SetReturnAttributes(true)
    res, err := kc.QueryItem(q)
    if err != nil {
        if errors.Is(err, kc.ErrorItemNotFound) {
            return false, nil
        }
        return false, err
    }
    return len(res) > 0, nil
}

func StoreMasterKey(key []byte, overwrite bool) error {
    serviceNew, _ := services()
    exists, err := MasterKeyExists()
    if err != nil {
        return err
    }
    if exists && !overwrite {
        return nil
    }
    if exists && overwrite {
        if err := DeleteMasterKey(); err != nil {
            return err
        }
    }
    it := kc.NewItem()
    it.SetSecClass(kc.SecClassGenericPassword)
    it.SetService(serviceNew)
    it.SetAccount(account)
    it.SetAccessible(kc.AccessibleWhenUnlocked)
    it.SetData(key)

    // Retry logic for Keychain authorization
    // First authorization may take time or return temporary error
    maxRetries := 3
    for attempt := 1; attempt <= maxRetries; attempt++ {
        err = kc.AddItem(it)
        if err == nil {
            return nil
        }

        // Check if it's a user cancellation (-128)
        if kcErr, ok := err.(kc.Error); ok {
            if kcErr == kc.ErrorUserCanceled {
                return errors.New(i18n.T("keychain.canceled"))
            }
            // If item already exists (despite our check), that's okay
            if kcErr == kc.ErrorDuplicateItem {
                return nil
            }
        }

        // For other errors, retry after a short delay
        if attempt < maxRetries {
            // Wait briefly before retry (macOS authorization may need time)
            time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
            continue
        }
    }

    return fmt.Errorf(i18n.T("keychain.store_failed"), maxRetries, err)
}

// LoadMasterKey shows the Touch ID prompt with reason, then reads the master key.
func LoadMasterKey(reason string) ([]byte, error) {
    // Gate access behind biometry prompt
    if err := macos.RequireBiometry(reason); err != nil {
        return nil, err
    }
    return LoadMasterKeyWithoutPrompt()
}

// LoadMasterKeyWithoutPrompt reads the master key without Touch ID. Only use
// it after the user has already authenticated by other means (e.g. OTP mode
// migrating away from the Keychain).
func LoadMasterKeyWithoutPrompt() ([]byte, error) {
    serviceNew, serviceOld := services()
    res, err := queryMasterKey(serviceNew)
    if err != nil {
        return nil, err
    }
    if len(res) == 0 {
        // try old service for backward compatibility
        res, err = queryMasterKey(serviceOld)
        if err != nil {
            return nil, err
        }
        if len(res) == 0 {
            return nil, errors.New(i18n.T("keychain.not_initialized"))
        }
    }
    return res[0].Data, nil
}

func queryMasterKey(svc string) ([]kc.QueryResult, error) {
    q := kc.NewItem()
    q.SetSecClass(kc.SecClassGenericPassword)
    q.SetService(svc)
    q.SetAccount(account)
    q.SetMatchLimit(kc.MatchLimitOne)
    q.SetReturnData(true)
    return kc.QueryItem(q)
}

func DeleteMasterKey() error {
    serviceNew, serviceOld := services()
    it := kc.NewItem()
    it.SetSecClass(kc.SecClassGenericPassword)
    it.SetService(serviceNew)
    it.SetAccount(account)
    _ = kc.DeleteItem(it)  // Ignore errors, may not exist
    it2 := kc.NewItem()
    it2.SetSecClass(kc.SecClassGenericPassword)
    it2.SetService(serviceOld)
    it2.SetAccount(account)
    _ = kc.DeleteItem(it2)  // Ignore errors, may not exist
    return nil
}