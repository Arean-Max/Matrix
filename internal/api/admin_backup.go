package api

import (
	"net/http"
	"os"
	"time"

	"eventhorizon/internal/store"
)

func (s *Server) adminBackup(w http.ResponseWriter, r *http.Request, actor string) {
	tmp, err := os.CreateTemp(s.cfg.DataDir, "eh-backup-*.db")
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	path := tmp.Name()
	tmp.Close()

	if err := os.Remove(path); err != nil {
		s.writeError(w, r, err)
		return
	}
	defer os.Remove(path)
	if err := s.store.BackupInto(path); err != nil {
		s.writeError(w, r, err)
		return
	}
	f, err := os.Open(path)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	now := s.now()
	if err := s.store.AddAudit(&store.Audit{
		TS: now.Unix(), Actor: actor, Action: store.AuditBackup,
		Detail: "database export",
	}); err != nil {
		s.writeError(w, r, err)
		return
	}
	name := "eh-backup-" + now.UTC().Format("20060102-150405") + ".db"
	w.Header().Set("Content-Type", "application/vnd.sqlite3")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	// A backup can exceed the server's normal write timeout.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(10 * time.Minute))
	http.ServeContent(w, r, name, st.ModTime(), f)
}
