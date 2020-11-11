package giganotes

import (
	"github.com/labstack/echo"
	"github.com/labstack/echo/middleware"
	"github.com/spf13/viper"
)

var Config *viper.Viper

func RunServer() {

	Config = viper.New()
	Config.SetConfigFile("./app.yaml")

	if err := Config.ReadInConfig(); err != nil {
		return
	}

	DBConnect(Config.GetString("ConnectionString"))

	e := echo.New()

	// Middleware
	e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORS())

	// Public access rotes
	e.GET("/version", version)
	e.GET("/stats", stats)
	e.POST("/feedback", feedback)
	e.POST("/request-restore-code", requestRestoreCode)
	e.POST("/update-password", updatePassword)
	e.POST("/login", login)
	e.POST("/register", register)
	e.POST("/login-social", loginSocial)
	e.GET("/ws", ws)

	r := e.Group("/api")

	config := middleware.JWTConfig{
		Claims:     &jwtCustomClaims{},
		SigningKey: []byte("secret"),
	}

	r.Use(middleware.JWTWithConfig(config))
	r.GET("/folders", folders)
	r.GET("/notes", notes)
	r.GET("/tree-nodes-list", treeNodesList)
	r.GET("/latest-sync-data", latestSyncData)
	r.GET("/rootFolder", rootFolder)
	r.GET("/folder/:id", folder)
	r.GET("/note/:id", note)
	r.POST("/upload-note", insertNote)
	r.POST("/upload-folder", insertFolder)
	r.POST("/update-note", updateNote)
	r.POST("/update-folder", updateFolder)
	r.POST("/save-note", saveNote)
	r.POST("/save-folder", saveFolder)
	r.GET("/remove-folder/:id", removeFolder)
	r.GET("/remove-note/:id", removeNote)
	r.GET("/search-notes", searchNotes)
	r.GET("/another-app-update", anotherAppUpdate)
	r.GET("/favorite-notes", favoriteNotes)
	r.POST("/add-to-favorites", addNoteToFavorites)

	e.Logger.Fatal(e.Start(":8081"))
}
