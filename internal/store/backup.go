package store

import (
    "crypto/rand"
    "encoding/base64"
    "encoding/json"
    "errors"
    "fmt"
    "os"
    "path/filepath"
    "time"

    "fssh/internal/crypt"

    "golang.org/x/crypto/scrypt"
)

// A backup holds every key, decrypted and re-encrypted under a key derived
// from a backup passphrase, so it can be restored on another Mac or under a
// different auth mode (the master key never leaves the machine).

const backupVersion = "fssh-backup/v1"

// scrypt parameters for interactive use (~32 MB, well under a second).
const (
    scryptN = 1 << 15
    scryptR = 8
    scryptP = 1
)

var ErrBackupPassphrase = errors.New("wrong backup passphrase or corrupted backup file")

type backupEnvelope struct {
    Version    string `json:"version"`
    KDF        string `json:"kdf"`
    N          int    `json:"n"`
    R          int    `json:"r"`
    P          int    `json:"p"`
    Salt       string `json:"salt"`
    Nonce      string `json:"nonce"`
    Ciphertext string `json:"ciphertext"`
    CreatedAt  string `json:"created_at"`
    Count      int    `json:"count"`
}

type backupRecord struct {
    Alias       string `json:"alias"`
    Fingerprint string `json:"fingerprint"`
    Comment     string `json:"comment,omitempty"`
    CreatedAt   string `json:"created_at,omitempty"`
    PKCS8       []byte `json:"pkcs8"`
}

// WriteBackup decrypts every record with masterKey and writes them to path,
// encrypted with passphrase. path must not exist. Returns the key count.
func WriteBackup(path string, masterKey []byte, passphrase string) (int, error) {
    metas, err := ListMeta()
    if err != nil {
        return 0, err
    }
    var recs []backupRecord
    for _, m := range metas {
        rec, err := LoadDecryptedRecord(m.Alias, masterKey)
        if err != nil {
            return 0, fmt.Errorf("decrypt %s: %w", m.Alias, err)
        }
        recs = append(recs, backupRecord{rec.Alias, rec.Fingerprint, rec.Comment, rec.CreatedAt, rec.PKCS8DER})
    }
    plaintext, err := json.Marshal(recs)
    if err != nil {
        return 0, err
    }

    salt := make([]byte, 16)
    nonce := make([]byte, 12)
    if _, err := rand.Read(salt); err != nil {
        return 0, err
    }
    if _, err := rand.Read(nonce); err != nil {
        return 0, err
    }
    key, err := scrypt.Key([]byte(passphrase), salt, scryptN, scryptR, scryptP, 32)
    if err != nil {
        return 0, err
    }
    ct, err := crypt.EncryptAEAD(key, nonce, plaintext, []byte(backupVersion))
    if err != nil {
        return 0, err
    }
    env := backupEnvelope{
        Version: backupVersion, KDF: "scrypt", N: scryptN, R: scryptR, P: scryptP,
        Salt:       base64.StdEncoding.EncodeToString(salt),
        Nonce:      base64.StdEncoding.EncodeToString(nonce),
        Ciphertext: base64.StdEncoding.EncodeToString(ct),
        CreatedAt:  time.Now().Format(time.RFC3339),
        Count:      len(recs),
    }
    b, err := json.MarshalIndent(env, "", "  ")
    if err != nil {
        return 0, err
    }
    if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
        return 0, err
    }
    f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
    if err != nil {
        return 0, err
    }
    if _, err := f.Write(append(b, '\n')); err != nil {
        f.Close()
        os.Remove(path)
        return 0, err
    }
    return len(recs), f.Close()
}

// ReadBackup decrypts a backup file. The returned records are not saved.
func ReadBackup(path, passphrase string) ([]*Record, error) {
    b, err := os.ReadFile(path)
    if err != nil {
        return nil, err
    }
    var env backupEnvelope
    if err := json.Unmarshal(b, &env); err != nil || env.Version != backupVersion || env.KDF != "scrypt" {
        return nil, fmt.Errorf("%s is not an fssh backup", path)
    }
    salt, err1 := base64.StdEncoding.DecodeString(env.Salt)
    nonce, err2 := base64.StdEncoding.DecodeString(env.Nonce)
    ct, err3 := base64.StdEncoding.DecodeString(env.Ciphertext)
    if err1 != nil || err2 != nil || err3 != nil {
        return nil, ErrBackupPassphrase
    }
    key, err := scrypt.Key([]byte(passphrase), salt, env.N, env.R, env.P, 32)
    if err != nil {
        return nil, err
    }
    plaintext, err := crypt.DecryptAEAD(key, nonce, ct, []byte(backupVersion))
    if err != nil {
        return nil, ErrBackupPassphrase
    }
    var recs []backupRecord
    if err := json.Unmarshal(plaintext, &recs); err != nil {
        return nil, ErrBackupPassphrase
    }
    out := make([]*Record, 0, len(recs))
    for _, r := range recs {
        out = append(out, &Record{Alias: r.Alias, Fingerprint: r.Fingerprint, Comment: r.Comment, CreatedAt: r.CreatedAt, PKCS8DER: r.PKCS8})
    }
    return out, nil
}
