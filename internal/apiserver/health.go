package apiserver

import (
	"net/http"
)

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func (s *Server) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if s.shutting.Load() {
		http.Error(w, "draining", http.StatusServiceUnavailable)
		return
	}
	if !s.cacheSynced.Load() {
		http.Error(w, "informer cache not synced", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}
