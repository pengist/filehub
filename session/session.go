package session

import (
	"sync"
	"time"

	"github.com/rs/xid"
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

	token := xid.New().String()

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

func (sm *SessionManager) RemoveExpiredSessions() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	for token, session := range sm.sessions {
		if session.ExpiresAt.Before(time.Now()) {
			delete(sm.sessions, token)
		}
	}
}
