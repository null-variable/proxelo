package api

import (
	"errors"
	"io"
	"net/http"

	"github.com/null-variable/proxelo/internal/importer/nginx"
	"github.com/null-variable/proxelo/internal/model"
)

// maxImport bounds an nginx upload (an archive with certificates and
// lookup files is larger than a JSON body).
const maxImport = 16 << 20

// importNginx converts an nginx configuration (nginx -T output, or a tar,
// tar.gz or zip of the configuration directory) into a new change set
// holding exactly the converted resources, and returns it with the
// conversion report. ?dryRun=true only converts.
func (a *api) importNginx(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxImport))
	if err != nil {
		var mb *http.MaxBytesError
		if errors.As(err, &mb) {
			a.fail(w, httpError{status: http.StatusRequestEntityTooLarge, msg: "upload is larger than 16 MiB"})
			return
		}
		a.fail(w, badRequest("reading body: %v", err))
		return
	}
	files, main, err := nginx.Load(raw)
	if err != nil {
		a.fail(w, badRequest("%v", err))
		return
	}
	tree, err := nginx.Parse(files, main)
	if err != nil {
		a.fail(w, httpError{status: http.StatusUnprocessableEntity, msg: err.Error()})
		return
	}
	cfg, report := nginx.Convert(tree, files)
	if r.URL.Query().Get("dryRun") == "true" {
		writeJSON(w, http.StatusOK, map[string]any{"report": report, "resources": redactConfig(cfg)})
		return
	}
	msg := r.URL.Query().Get("message")
	if msg == "" {
		msg = "Import " + main
	}
	cs, err := a.st.CreateChangeSet(r.Context(), who(r).name(), msg)
	if err != nil {
		a.fail(w, err)
		return
	}
	if err := a.importConfig(r.Context(), cs.ID, cfg); err != nil {
		// The change set would hold nothing useful.
		_ = a.st.DeleteChangeSet(r.Context(), cs.ID)
		a.fail(w, err)
		return
	}
	if cs, err = a.st.ChangeSet(r.Context(), cs.ID); err != nil {
		a.fail(w, err)
		return
	}
	a.audit(r, "import.nginx", cs.ID, map[string]any{"main": main, "files": len(files), "counts": report.Counts})
	w.Header().Set("Location", "/api/v1/changesets/"+cs.ID)
	n := 0
	for _, k := range model.Kinds {
		n += len(cfg.Of(k))
	}
	writeJSON(w, http.StatusCreated, map[string]any{"changeSet": cs, "report": report, "resources": n})
}
