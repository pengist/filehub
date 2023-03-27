package session

import (
	"encoding/base64"
	"math/rand"
	"sync"
	"time"
)

type Session struct {
	Token     string
	Data      map[string]interface{}
	ExpiresAt time.Time
}

type SessionManager struct {
	sessions map[string]*Session
	mu       sync.RWMutex
}

var managerInstance *SessionManager
var once sync.Once

func GetInstance() *SessionManager {
	once.Do(func() {
		managerInstance = &SessionManager{
			sessions: make(map[string]*Session),
		}
	})
	return managerInstance
}

func (sm *SessionManager) CreateSession(duration time.Duration) *Session {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	token, _ := generateToken(32)
	session := &Session{
		Token:     token,
		Data:      make(map[string]interface{}),
		ExpiresAt: time.Now().Add(duration),
	}
	sm.sessions[token] = session
	return session
}

func (sm *SessionManager) GetSession(token string) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, ok := sm.sessions[token]
	if ok && session.ExpiresAt.After(time.Now()) {
		return session, true
	}
	return nil, false
}

func (sm *SessionManager) RemoveSession(token string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	delete(sm.sessions, token)
}

func generateToken(length int) (string, error) {
	// 生成随机字节
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	// 将字节编码为 Base64 字符串
	token := base64.URLEncoding.EncodeToString(bytes)

	return token, nil
}
