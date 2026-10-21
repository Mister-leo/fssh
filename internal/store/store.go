package store

import (
    "crypto/rand"
    "crypto/ecdsa"
    "crypto/ed25519"
    "crypto/rsa"
    "crypto/x509"
    "encoding/base64"
    "encoding/json"
    "encoding/pem"
    "errors"
    "os"
    "path/filepath"
    "regexp"
    "strings"
    "time"

    "fssh/internal/crypt"
    "golang.org/x/crypto/ssh"
)

type EncryptedFile struct {
    Version     string `json:"version"`
    Alias       string `json:"alias"`
    Fingerprint string `json:"fingerprint"`
    PubKey      string `json:"pubkey"`
    KeyType     string `json:"key_type"`
    HKDFSalt    string `json:"hkdf_salt"`
    Nonce       string `json:"nonce"`
    Ciphertext  string `json:"ciphertext"`
    CreatedAt   string `json:"created_at"`
    Comment     string `json:"comment"`
}

type Record struct {
    Alias       string
    Fingerprint string
    Comment     string
    PKCS8DER    []byte
}

func KeysDir() string {
    home, _ := os.UserHomeDir()
    return filepath.Join(home, ".fssh", "keys")
}

var (
    ErrInvalidAlias = errors.New("invalid alias")
    ErrNotFound     = errors.New("key not found")

    aliasPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// ValidateAlias checks the naming rule for new aliases: letters, digits,
// '.', '_', '-', starting with a letter or digit, at most 64 characters.
func ValidateAlias(alias string) error {
    if !aliasPattern.MatchString(alias) {
        return ErrInvalidAlias
    }
    return nil
}

// checkAliasPath only rejects aliases that would escape KeysDir. It is used
// for existing records, which may predate ValidateAlias.
func checkAliasPath(alias string) error {
    if alias == "" || alias == "." || alias == ".." || strings.ContainsAny(alias, "/\\\x00") {
        return ErrInvalidAlias
    }
    return nil
}

// RecordPath returns the encrypted file path for alias.
func RecordPath(alias string) (string, error) {
    if err := checkAliasPath(alias); err != nil {
        return "", err
    }
    return filepath.Join(KeysDir(), alias+".enc"), nil
}

// LoadMeta reads the unencrypted metadata of a record. Returns ErrNotFound
// if the alias does not exist.
func LoadMeta(alias string) (*EncryptedFile, error) {
    path, err := RecordPath(alias)
    if err != nil {
        return nil, err
    }
    b, err := os.ReadFile(path)
    if err != nil {
        if errors.Is(err, os.ErrNotExist) {
            return nil, ErrNotFound
        }
        return nil, err
    }
    var ef EncryptedFile
    if err := json.Unmarshal(b, &ef); err != nil {
        return nil, err
    }
    return &ef, nil
}

// ListMeta returns metadata of all records, skipping unreadable files.
func ListMeta() ([]EncryptedFile, error) {
    entries, err := os.ReadDir(KeysDir())
    if err != nil {
        if errors.Is(err, os.ErrNotExist) {
            return nil, nil
        }
        return nil, err
    }
    var metas []EncryptedFile
    for _, e := range entries {
        if e.IsDir() || !strings.HasSuffix(e.Name(), ".enc") {
            continue
        }
        m, err := LoadMeta(strings.TrimSuffix(e.Name(), ".enc"))
        if err != nil {
            continue
        }
        metas = append(metas, *m)
    }
    return metas, nil
}

// FindByFingerprint returns the alias of the record with fingerprint fp.
func FindByFingerprint(fp string) (string, bool, error) {
    metas, err := ListMeta()
    if err != nil {
        return "", false, err
    }
    for _, m := range metas {
        if m.Fingerprint == fp {
            return m.Alias, true, nil
        }
    }
    return "", false, nil
}

func ensureDirs() error {
    dir := KeysDir()
    return os.MkdirAll(dir, 0700)
}

func NewRecordFromPrivateKeyBytes(alias string, keyFileBytes []byte, passphrase string, comment string) (*Record, error) {
    var k interface{}
    var err error
    if passphrase != "" {
        k, err = ssh.ParseRawPrivateKeyWithPassphrase(keyFileBytes, []byte(passphrase))
    } else {
        k, err = ssh.ParseRawPrivateKey(keyFileBytes)
    }
    if err != nil {
        return nil, err
    }
    var der []byte
    switch kk := k.(type) {
    case ed25519.PrivateKey:
        der, err = x509.MarshalPKCS8PrivateKey(kk)
    case *ed25519.PrivateKey:
        // Convert pointer to value
        der, err = x509.MarshalPKCS8PrivateKey(ed25519.PrivateKey(*kk))
    case *rsa.PrivateKey:
        der, err = x509.MarshalPKCS8PrivateKey(kk)
    case *ecdsa.PrivateKey:
        der, err = x509.MarshalPKCS8PrivateKey(kk)
    default:
        return nil, errors.New("unsupported private key type")
    }
    if err != nil {
        return nil, err
    }
    signer, err := ssh.NewSignerFromKey(k)
    if err != nil {
        return nil, err
    }
    fp := ssh.FingerprintSHA256(signer.PublicKey())
    return &Record{Alias: alias, Fingerprint: fp, Comment: comment, PKCS8DER: der}, nil
}

func SaveEncryptedRecord(rec *Record, masterKey []byte) error {
    path, err := RecordPath(rec.Alias)
    if err != nil {
        return err
    }
    if err := ensureDirs(); err != nil {
        return err
    }
    salt, err := crypt.RandBytes(rand.Reader, 32)
    if err != nil {
        return err
    }
    nonce, err := crypt.RandBytes(rand.Reader, 12)
    if err != nil {
        return err
    }
    fileKey := crypt.HKDF(masterKey, salt, []byte(rec.Alias), 32)
    ct, err := crypt.EncryptAEAD(fileKey, nonce, rec.PKCS8DER, []byte(rec.Fingerprint))
    if err != nil {
        return err
    }
    // derive public key bytes
    pk, err := x509.ParsePKCS8PrivateKey(rec.PKCS8DER)
    if err != nil {
        return err
    }
    signer, err := ssh.NewSignerFromKey(pk)
    if err != nil {
        return err
    }
    pubRaw := signer.PublicKey().Marshal()
    ef := EncryptedFile{
        Version:     "fingerpass/v1",
        Alias:       rec.Alias,
        Fingerprint: rec.Fingerprint,
        PubKey:      base64.StdEncoding.EncodeToString(pubRaw),
        KeyType:     "PKCS8",
        HKDFSalt:    base64.StdEncoding.EncodeToString(salt),
        Nonce:       base64.StdEncoding.EncodeToString(nonce),
        Ciphertext:  base64.StdEncoding.EncodeToString(ct),
        CreatedAt:   time.Now().Format(time.RFC3339),
        Comment:     rec.Comment,
    }
    b, err := json.MarshalIndent(ef, "", "  ")
    if err != nil {
        return err
    }
    return os.WriteFile(path, b, 0600)
}

func LoadDecryptedRecord(alias string, masterKey []byte) (*Record, error) {
    path, err := RecordPath(alias)
    if err != nil {
        return nil, err
    }
    b, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    var ef EncryptedFile
    if err := json.Unmarshal(b, &ef); err != nil {
        return nil, err
    }
    if ef.Version != "fingerpass/v1" || ef.Alias != alias || ef.KeyType != "PKCS8" {
        return nil, errors.New("invalid record metadata")
    }
    salt, err := base64.StdEncoding.DecodeString(ef.HKDFSalt)
    if err != nil {
        return nil, err
    }
    nonce, err := base64.StdEncoding.DecodeString(ef.Nonce)
    if err != nil {
        return nil, err
    }
    ct, err := base64.StdEncoding.DecodeString(ef.Ciphertext)
    if err != nil {
        return nil, err
    }
    fileKey := crypt.HKDF(masterKey, salt, []byte(alias), 32)
    der, err := crypt.DecryptAEAD(fileKey, nonce, ct, []byte(ef.Fingerprint))
    if err != nil {
        return nil, err
    }
    return &Record{Alias: ef.Alias, Fingerprint: ef.Fingerprint, Comment: ef.Comment, PKCS8DER: der}, nil
}

func ExportPKCS8PEM(rec *Record, passphrase string) ([]byte, error) {
    block := &pem.Block{Type: "PRIVATE KEY", Bytes: rec.PKCS8DER}
    if passphrase != "" {
        enc, err := x509.EncryptPEMBlock(rand.Reader, block.Type, block.Bytes, []byte(passphrase), x509.PEMCipherAES256)
        if err != nil {
            return nil, err
        }
        return pem.EncodeToMemory(enc), nil
    }
    return pem.EncodeToMemory(block), nil
}