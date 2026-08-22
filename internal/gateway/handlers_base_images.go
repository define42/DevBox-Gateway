package gateway

import (
	"errors"
	"io"
	"log"
	"math"
	"mime"
	"mime/multipart"
	"net/http"
	"time"

	"github.com/define42/devbox-gateway/internal/config"
	"github.com/define42/devbox-gateway/internal/dashboard"
	"github.com/define42/devbox-gateway/internal/identity"
	"github.com/define42/devbox-gateway/internal/session"
	"github.com/define42/devbox-gateway/internal/virt"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
)

const baseImageMultipartOverheadBytes = 1 << 20

type adminBaseImagesResponse struct {
	BaseImages            []string `json:"baseImages"`
	MaxUploadBytes        int64    `json:"maxUploadBytes"`
	AvailableStorageBytes uint64   `json:"availableStorageBytes"`
	Error                 string   `json:"error,omitempty"`
}

func registerAdminBaseImageRoutes(group huma.API, sessionManager *session.Manager, settings *config.Settings) {
	registerAdminBaseImageListRoute(group, sessionManager, settings)
	registerAdminBaseImageUploadRoute(group, sessionManager, settings)
	registerAdminBaseImageDeleteRoute(group, sessionManager, settings)
}

func registerAdminBaseImageListRoute(group huma.API, sessionManager *session.Manager, settings *config.Settings) {
	registerHiddenGet(group, "/admin/base-images", func(ctx huma.Context) {
		req, w := humachi.Unwrap(ctx)
		if _, ok := requireAdmin(req, w, sessionManager); !ok {
			return
		}

		images, err := virt.ListBaseImages(settings)
		availableStorageBytes := uint64(0)
		if err == nil {
			availableStorageBytes, err = virt.BaseImageAvailableBytes(settings)
		}
		if err != nil {
			log.Printf("admin base image list failed: %v", err)
			dashboard.WriteJSON(w, http.StatusInternalServerError, adminBaseImagesResponse{
				BaseImages:     []string{},
				MaxUploadBytes: maxBaseImageUploadBytes(settings),
				Error:          "Unable to load base images right now.",
			})
			return
		}
		dashboard.WriteJSON(w, http.StatusOK, adminBaseImagesResponse{
			BaseImages:            images,
			MaxUploadBytes:        maxBaseImageUploadBytes(settings),
			AvailableStorageBytes: availableStorageBytes,
		})
	})
}

func registerAdminBaseImageUploadRoute(group huma.API, sessionManager *session.Manager, settings *config.Settings) {
	registerHiddenPost(group, "/admin/base-images", func(ctx huma.Context) {
		req, w := humachi.Unwrap(ctx)
		user, ok := requireAdmin(req, w, sessionManager)
		if !ok {
			return
		}
		clearBaseImageUploadReadDeadline(w, user)

		maxBytes := maxBaseImageUploadBytes(settings)
		req.Body = http.MaxBytesReader(w, req.Body, maxBytes+baseImageMultipartOverheadBytes)
		part, name, err := baseImageUploadPart(req)
		if err != nil {
			writeAdminBaseImageError(w, user, "upload", "", true, err)
			return
		}

		written, err := virt.StoreBaseImage(settings, name, part, maxBytes)
		if err != nil {
			writeAdminBaseImageError(w, user, "upload", name, false, err)
			return
		}
		_ = part.Close()
		log.Printf("admin base image upload succeeded: user=%q image=%q bytes=%d", user.Name, name, written)
		dashboard.WriteJSON(w, http.StatusCreated, dashboard.ActionResponse{
			OK:      true,
			Message: "Base image uploaded.",
		})
	})
}

func registerAdminBaseImageDeleteRoute(group huma.API, sessionManager *session.Manager, settings *config.Settings) {
	registerHiddenPost(group, "/admin/base-images/delete", func(ctx huma.Context) {
		req, w := humachi.Unwrap(ctx)
		user, ok := requireAdmin(req, w, sessionManager)
		if !ok {
			return
		}
		if err := parseFormWithBodyLimit(w, req); err != nil {
			writeAdminBaseImageError(w, user, "delete", "", true, err)
			return
		}

		name := req.FormValue("base_image")
		if err := virt.DeleteBaseImage(settings, name); err != nil {
			writeAdminBaseImageError(w, user, "delete", name, false, err)
			return
		}
		log.Printf("admin base image delete succeeded: user=%q image=%q", user.Name, name)
		dashboard.WriteJSON(w, http.StatusOK, dashboard.ActionResponse{
			OK:      true,
			Message: "Base image deleted.",
		})
	})
}

func maxBaseImageUploadBytes(settings *config.Settings) int64 {
	configured := config.VMDiskCapacityBytes(settings)
	maximum := uint64(math.MaxInt64 - baseImageMultipartOverheadBytes)
	if configured > maximum {
		return int64(maximum)
	}
	return int64(configured)
}

func clearBaseImageUploadReadDeadline(w http.ResponseWriter, user *identity.User) {
	if err := http.NewResponseController(w).SetReadDeadline(time.Time{}); err != nil &&
		!errors.Is(err, http.ErrNotSupported) {
		log.Printf("admin base image upload could not clear read deadline: user=%q error=%v", user.Name, err)
	}
}

func baseImageUploadPart(req *http.Request) (*multipart.Part, string, error) {
	reader, err := req.MultipartReader()
	if err != nil {
		return nil, "", err
	}
	for {
		part, err := reader.NextPart()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, "", virt.ErrInvalidBaseImageName
			}
			return nil, "", err
		}

		mediaType, params, parseErr := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
		if parseErr != nil {
			_ = part.Close()
			return nil, "", parseErr
		}
		if mediaType != "form-data" || params["name"] != "base_image" {
			_ = part.Close()
			continue
		}
		name := params["filename"]
		if name == "" {
			_ = part.Close()
			return nil, "", virt.ErrInvalidBaseImageName
		}
		return part, name, nil
	}
}

func writeAdminBaseImageError(
	w http.ResponseWriter,
	user *identity.User,
	action string,
	name string,
	invalidRequest bool,
	err error,
) {
	status := http.StatusInternalServerError
	message := "Base image operation failed."
	var maxBytesErr *http.MaxBytesError
	switch {
	case errors.Is(err, virt.ErrInvalidBaseImageName):
		status = http.StatusBadRequest
		message = "Choose a single .img, .qcow2, or .raw file with a valid file name."
	case errors.Is(err, virt.ErrEmptyBaseImage):
		status = http.StatusBadRequest
		message = "Base image files cannot be empty."
	case errors.Is(err, virt.ErrInvalidBaseImageFormat):
		status = http.StatusBadRequest
		message = "Base image must contain a valid QCOW2 header."
	case errors.Is(err, virt.ErrBaseImageExists):
		status = http.StatusConflict
		message = "A base image with that name already exists."
	case errors.Is(err, virt.ErrBaseImageNotFound):
		status = http.StatusNotFound
		message = "Base image not found."
	case errors.Is(err, virt.ErrBaseImageTooLarge), errors.As(err, &maxBytesErr):
		status = http.StatusRequestEntityTooLarge
		message = "Base image exceeds the upload size limit."
	case invalidRequest && action == "upload":
		status = http.StatusBadRequest
		message = "Invalid base image upload."
	case invalidRequest && action == "delete":
		status = http.StatusBadRequest
		message = "Invalid base image deletion request."
	}
	log.Printf("admin base image %s failed: user=%q image=%q error=%v", action, user.Name, name, err)
	dashboard.WriteJSON(w, status, dashboard.ActionResponse{OK: false, Error: message})
}
