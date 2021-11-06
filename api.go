package giganotes

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"golang.org/x/net/html/atom"
	"io"
	"log"
	"math/rand"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"

	jwt "github.com/dgrijalva/jwt-go"
	googleAuthIDTokenVerifier "github.com/futurenda/google-auth-id-token-verifier"
	"github.com/gorilla/websocket"
	"github.com/labstack/echo"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
	gomail "gopkg.in/gomail.v2"
)

const contextKey string = "user"

var (
	upgrader        = websocket.Upgrader{}
	createUserMutex = sync.Mutex{}
	GIGANOTES_SERVER_VERSION = "1.21"
)

func init() {
	rand.Seed(time.Now().UnixNano())

	upgrader.CheckOrigin = func(r *http.Request) bool {
		return true
	}
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}

func authUser(email, password string) (*User, error) {

	user := &User{}
	err := db.Where("email = ?", email).First(&user).Error
	if err != nil {
		return nil, errors.New("User not found")
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	if err != nil {
		return nil, errors.New("Incorrect password")
	}
	return user, nil

}

func createUser(email, password string) (*User, error) {
	pwHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.New("Couldn't hash password")
	}
	u := User{}
	u.Email = email
	u.PasswordHash = string(pwHash)
	u.AccountType = 0

	db.Create(&u)
	return &u, nil
}

// jwtCustomClaims are custom claims extending default ones.
type jwtCustomClaims struct {
	UserID int64 `json:"userid"`
	Admin  bool  `json:"admin"`
	jwt.StandardClaims
}

func createToken(user *User) (string, string, error) {
	// Create unique ID for the token
	tokenID := RandStringRunes(10)

	claims := &jwtCustomClaims{
		user.ID,
		true,
		jwt.StandardClaims{
			Id:        tokenID,
			ExpiresAt: time.Now().Add(time.Hour * 24 * 30).Unix(),
		},
	}
	// Create token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate encoded token by signing it using secret key and send it as response.
	t, err := token.SignedString([]byte("secret"))
	if err != nil {
		return "", tokenID, err
	}
	return t, tokenID, nil
}

type authRequestParams struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func login(c echo.Context) error {
	arp := new(authRequestParams)
	if err := c.Bind(arp); err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	user, err := authUser(arp.Email, arp.Password)

	if err != nil {
		return echo.ErrUnauthorized
	}

	if user != nil {

		var folder Folder
		db.Unscoped().Where("user_id = ? and parent_id IS NULL", user.ID).First(&folder)

		t, _, _ := createToken(user)
		return c.JSON(http.StatusOK, map[string]interface{}{
			"userId":        user.ID,
			"token":         t,
			"rootFolder":    folder,
			"encryptedData": user.EncryptedData,
		})
	}

	return echo.ErrUnauthorized
}

type loginSocialRequestParams struct {
	Email    string `json:"email"`
	Provider string `json:"provider"`
	Token    string `json:"token"`
}

func loginSocial(c echo.Context) error {
	arp := new(loginSocialRequestParams)
	if err := c.Bind(arp); err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	tokenVerified := false
	switch arp.Provider {
	case "GOOGLE":
		tokenVerified = verifyGoogleToken(arp.Token)
	default:
		return echo.ErrUnauthorized
	}

	if !tokenVerified {
		return echo.ErrUnauthorized
	}

	user := &User{}

	// Wait until another user creation operation is completed
	createUserMutex.Lock()

	err := db.Where("email = ?", arp.Email).First(&user).Error
	var folder Folder

	if err != nil {
		user, _ = createUser(arp.Email, RandStringRunes(10))

		//Create root folder for the user
		curTime := time.Now()
		newID, _ := uuid.NewV4()
		folder = Folder{}
		folder.ID = newID.String()
		folder.Level = 0
		folder.Title = "Root"
		folder.ParentID = nil
		folder.CreatedAt = curTime
		folder.UpdatedAt = curTime
		folder.UserID = user.ID
		db.Create(&folder)
		createUserMutex.Unlock()
	} else {
		createUserMutex.Unlock()
		db.Unscoped().Where("user_id = ? and parent_id IS NULL", user.ID).First(&folder)
	}

	if user != nil {
		t, _, _ := createToken(user)
		return c.JSON(http.StatusOK, map[string]interface{}{
			"userId":     user.ID,
			"token":      t,
			"rootFolder": folder,
		})
	}

	return echo.ErrUnauthorized
}

func verifyGoogleToken(token string) bool {
	v := googleAuthIDTokenVerifier.Verifier{}

	aud := Config.GetString("googleAuthAud")
	err := v.VerifyIDToken(token, []string{
		aud,
	})

	return err == nil
}

func register(c echo.Context) error {
	arp := new(authRequestParams)
	if err := c.Bind(arp); err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	existingCount := 0

	// Wait until another user creation operation is completed
	createUserMutex.Lock()

	db.Model(&User{}).Where("email = ?", arp.Email).Count(&existingCount)

	if existingCount > 0 {
		createUserMutex.Unlock()
		return c.JSON(http.StatusUnauthorized, map[string]string{
			"error": "USER_EXISTS",
		})
	}

	user, err := createUser(arp.Email, arp.Password)

	createUserMutex.Unlock()

	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	folder := Folder{}

	if user != nil {
		t, tokenID, _ := createToken(user)

		//Create root folder for the user
		curTime := time.Now()
		newID, _ := uuid.NewV4()
		folder.ID = newID.String()
		folder.Level = 0
		folder.Title = "Root"
		folder.ParentID = nil
		folder.CreatedAt = curTime
		folder.UpdatedAt = curTime
		folder.UserID = user.ID
		db.Create(&folder)

		event := new(Event)
		event.Type = 3
		event.UserID = user.ID
		event.ClientType, _ = strconv.Atoi(c.Request().Header.Get("ClientType"))
		event.ClientID = tokenID
		db.Create(event)

		return c.JSON(http.StatusOK, map[string]interface{}{
			"userId":     user.ID,
			"token":      t,
			"rootFolder": folder,
		})
	}

	return echo.ErrUnauthorized
}

type requestRestoreCodeParams struct {
	Email string `json:"email"`
}

func requestRestoreCode(c echo.Context) error {
	rp := new(requestRestoreCodeParams)
	if err := c.Bind(rp); err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	user := &User{}
	err := db.Where("email = ?", rp.Email).First(&user).Error

	if err != nil {
		return c.JSON(http.StatusNotFound, "User not found")
	}

	user.PasswordRestoreCode = RandStringRunes(6)
	db.Save(user)

	userName := Config.GetString("mailUsername")
	from := Config.GetString("mailFrom")
	password := Config.GetString("mailPassword")
	smtpServer := Config.GetString("smtpServer")
	body := "Please use the following password restore code: " + user.PasswordRestoreCode

	m := gomail.NewMessage()
	m.SetHeader("From", from)
	m.SetHeader("To", rp.Email)
	m.SetHeader("Subject", "GigaNotes - code for password restore")
	m.SetBody("text/html", "<b>"+body+"</b>")

	d := gomail.NewDialer(smtpServer, 587, userName, password)

	if err := d.DialAndSend(m); err != nil {
		return c.JSON(http.StatusNotFound, err.Error())
	}

	return c.JSON(http.StatusOK, "OK")
}

type updatePasswordRequestParams struct {
	Email    string `json:"email"`
	Code     string `json:"code"`
	Password string `json:"password"`
}

func updatePassword(c echo.Context) error {

	up := new(updatePasswordRequestParams)
	if err := c.Bind(up); err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	user := &User{}
	err := db.Where("email = ?", up.Email).First(&user).Error

	if err != nil {
		return c.JSON(http.StatusNotFound, "User not found")
	}

	pwHash, err := bcrypt.GenerateFromPassword([]byte(up.Password), bcrypt.DefaultCost)
	if err != nil {
		return c.JSON(http.StatusNotFound, "Couldn't hash password")
	}

	if up.Code != user.PasswordRestoreCode {
		return c.JSON(http.StatusNotFound, "Wrong restore code")
	}

	user.PasswordHash = string(pwHash)
	user.PasswordRestoreCode = ""
	db.Save(user)

	return c.JSON(http.StatusOK, "OK")
}

type treeNode struct {
	ID       string `json:"id"`
	ParentID string `json:"parentId"`
	Title    string `json:"title"`
	Level    int64  `json:"level"`
	Type     string `json:"type"`
}

type treeNodeSortByLevel []treeNode

func (s treeNodeSortByLevel) Len() int {
	return len(s)
}
func (s treeNodeSortByLevel) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}
func (s treeNodeSortByLevel) Less(i, j int) bool {
	return s[i].Level < s[j].Level
}

func treeNodesList(c echo.Context) error {
	user, _ := currentUser(c)
	if user == nil {
		return echo.ErrUnauthorized
	}

	var folders []Folder
	err := db.Where("user_id = ?", user.ID).Find(&folders).Error

	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	var notes []Note
	err = db.Where("user_id = ?", user.ID).Find(&notes).Error

	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	var nodesList []treeNode

	for _, folder := range folders {
		var newNode treeNode
		newNode.ID = folder.ID
		if folder.ParentID != nil {
			newNode.ParentID = *folder.ParentID
		}
		newNode.Title = folder.Title
		newNode.Level = folder.Level
		newNode.Type = "F"
		nodesList = append(nodesList, newNode)
	}

	for _, note := range notes {
		var newNode treeNode
		newNode.ID = note.ID
		newNode.ParentID = note.FolderID
		newNode.Title = note.Title
		newNode.Level = note.Level
		newNode.Type = "N"
		nodesList = append(nodesList, newNode)
	}

	sort.Sort(treeNodeSortByLevel(nodesList))

	event := new(Event)
	event.Type = 1
	event.UserID = user.ID
	event.ClientType, _ = strconv.Atoi(c.Request().Header.Get("ClientType"))
	event.ClientID = c.Request().Header.Get("ClientID")

	db.Create(event)

	return c.JSON(http.StatusOK, nodesList)
}

func folders(c echo.Context) error {
	includeDeleted := c.QueryParam("includeDeleted")
	user, _ := currentUser(c)
	if user == nil {
		return echo.ErrUnauthorized
	}

	var folders []Folder
	var err error

	if includeDeleted == "true" {
		err = db.Unscoped().Where("user_id = ?", user.ID).Order("level").Find(&folders).Error
	} else {
		err = db.Where("user_id = ?", user.ID).Order("level").Find(&folders).Error
	}

	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	return c.JSON(http.StatusOK, folders)
}

func notes(c echo.Context) error {
	folderID := c.QueryParam("folderId")
	user, _ := currentUser(c)
	if user == nil {
		return echo.ErrUnauthorized
	}

	var err error

	type ReqResult struct {
		Id       string `json:"id"`
		Title    string `json:"title"`
		FolderId string `json:"folderId"`
	}

	var reqResults []ReqResult

	if folderID != "" {
		err = db.Raw("SELECT id, title, folder_id FROM notes WHERE deleted_at IS NULL AND folder_id = ? AND user_id = ? ORDER BY updated_at DESC", folderID, user.ID).Scan(&reqResults).Error
	} else {
		err = db.Raw("SELECT id, title, folder_id FROM notes WHERE deleted_at IS NULL AND user_id = ? ORDER BY updated_at DESC", user.ID).Scan(&reqResults).Error
	}
	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	return c.JSON(http.StatusOK, reqResults)
}

func favoriteNotes(c echo.Context) error {
	user, _ := currentUser(c)
	if user == nil {
		return echo.ErrUnauthorized
	}

	var notes []Note

	err := db.Joins("JOIN user_note_favorites ON user_note_favorites.user_id = notes.user_id AND user_note_favorites.note_id = notes.id").Where("notes.user_id = ?", user.ID).Order("updated_at DESC").Find(&notes).Error

	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	return c.JSON(http.StatusOK, notes)
}

type addNoteToFavoritesRequestParams struct {
	NoteID string `json:"noteId"`
}

func addNoteToFavorites(c echo.Context) error {
	user, _ := currentUser(c)
	if user == nil {
		return echo.ErrUnauthorized
	}

	rp := new(addNoteToFavoritesRequestParams)
	if err := c.Bind(rp); err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	existingCount := 0
	db.Model(&UserNoteFavorite{}).Where("user_id = ? AND note_id = ?", user.ID, rp.NoteID).Count(&existingCount)

	if existingCount == 1 {
		return c.JSON(http.StatusOK, "OK")
	}

	favRecord := new(UserNoteFavorite)
	favRecord.UserID = user.ID
	favRecord.NoteID = rp.NoteID

	db.Create(favRecord)

	return c.JSON(http.StatusOK, "OK")
}

type latestSyncDataHolder struct {
	Notes   []SyncShortInfo `json:"notes"`
	Folders []Folder        `json:"folders"`
}

// notesinfo returns short notes info for sync
func latestSyncData(c echo.Context) error {
	user, _ := currentUser(c)
	if user == nil {
		return echo.ErrUnauthorized
	}

	var notes []Note
	err := db.Unscoped().Where("user_id = ?", user.ID).Find(&notes).Error

	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	shortInfos := make([]SyncShortInfo, len(notes))
	for i, note := range notes {
		shortInfos[i] = SyncShortInfo{ID: note.ID, CreatedAt: note.CreatedAt, UpdatedAt: note.UpdatedAt, DeletedAt: note.DeletedAt, FolderID: note.FolderID}
	}

	var folders []Folder

	err = db.Unscoped().Where("user_id = ?", user.ID).Order("level").Find(&folders).Error

	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	holder := new(latestSyncDataHolder)
	holder.Folders = folders
	holder.Notes = shortInfos

	event := new(Event)
	event.Type = 2
	event.UserID = user.ID
	event.ClientType, _ = strconv.Atoi(c.Request().Header.Get("ClientType"))
	event.ClientID = c.Request().Header.Get("ClientID")
	db.Create(event)

	return c.JSON(http.StatusOK, holder)
}

func rootFolder(c echo.Context) error {
	user, _ := currentUser(c)
	if user == nil {
	}

	var folder Folder
	err := db.Unscoped().Where("user_id = ? and parent_id IS NULL", user.ID).First(&folder).Error

	if err != nil {
		return c.JSON(http.StatusNotFound, err.Error())
	}

	if folder.UserID != user.ID {
		return echo.ErrUnauthorized
	}

	return c.JSON(http.StatusOK, folder)
}

func folder(c echo.Context) error {
	folderID := c.Param("id")

	user, _ := currentUser(c)
	if user == nil {
	}

	var folder Folder
	err := db.Unscoped().Where("id = ?", folderID).First(&folder).Error

	if err != nil {
		return c.JSON(http.StatusNotFound, err.Error())
	}

	if folder.UserID != user.ID {
		return echo.ErrUnauthorized
	}

	return c.JSON(http.StatusOK, folder)
}

func note(c echo.Context) error {
	noteID := c.Param("id")

	user, _ := currentUser(c)
	if user == nil {
		return echo.ErrUnauthorized
	}

	var note Note
	err := db.Unscoped().Where("id = ?", noteID).First(&note).Error

	if err != nil {
		return c.JSON(http.StatusNotFound, err.Error())
	}

	if note.UserID != user.ID {
		return echo.ErrUnauthorized
	}

	return c.JSON(http.StatusOK, note)
}

func removeFolder(c echo.Context) error {

	type child struct {
		ID string
	}

	folderID := c.Param("id")

	user, _ := currentUser(c)
	if user == nil {
		return echo.ErrUnauthorized
	}

	now := time.Now()

	allChildFoldersQuery := `WITH RECURSIVE children(id) AS (
    		SELECT id FROM folders WHERE id = ?
  		UNION ALL
    		SELECT f.id
    		FROM folders f
    		JOIN children c
			ON f.parent_id = c.id)
			SELECT id FROM children`

	var childs []child
	db.Raw(allChildFoldersQuery, folderID).Scan(&childs)

	var ids []string

	for _, child := range childs {
		ids = append(ids, child.ID)
	}

	db.Unscoped().Table("folders").Where("id in (?)", ids).UpdateColumn("deleted_at", now)
	db.Unscoped().Table("notes").Where("folder_id in (?)", ids).UpdateColumn("deleted_at", now)

	return c.JSON(http.StatusOK, "OK")
}

func removeNote(c echo.Context) error {
	noteID := c.Param("id")

	user, _ := currentUser(c)
	if user == nil {
		return echo.ErrUnauthorized
	}

	var note Note
	err := db.Unscoped().Where("id = ?", noteID).First(&note).Error

	if err != nil {
		return c.JSON(http.StatusNotFound, err.Error())
	}

	now := time.Now()
	note.DeletedAt = &now

	err = db.Unscoped().Save(note).Error

	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	return c.JSON(http.StatusOK, "OK")
}

func downloadImageAsBase64(url string) (string, error) {
	// Download image, convert to Base64
	response, err := http.Get(url)
	if err != nil {
		return "", err
	}

	if response.StatusCode != 200 {
		return "", err
	}

	buf := new(bytes.Buffer)

	_, err = io.Copy(buf, response.Body)
	if err != nil {
		return "", err
	}

	imgBase64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	mimeType := http.DetectContentType(buf.Bytes())
	dataContent := "data:" + mimeType + ";base64," + imgBase64
	return dataContent, nil
}
func extractImages(node *html.Node) int {
	imagesExtracted := 0

	if node.Type == html.ElementNode && node.DataAtom == atom.Img {
		for i := range node.Attr {
			img := &node.Attr[i]
			if img.Key == "src" {
				if strings.HasPrefix(img.Val, "data:") {
					continue
				}
				newRef, err := downloadImageAsBase64(img.Val)
				if err != nil {
					continue
				}
				// Modify reference to local value
				img.Val = newRef

				imagesExtracted++
			}
		}
	}

	childExtracted := 0
	for c := node.FirstChild; c != nil; c = c.NextSibling {
		childExtracted += extractImages(c)
	}
	return imagesExtracted + childExtracted
}


func processNote(note *Note) {

	r := strings.NewReader(note.Text)
	doc, err := html.Parse(r)

	if err != nil {
		log.Fatal(err)
	}

	extractedCount := extractImages(doc)

	if extractedCount > 0 {
		buf := new(bytes.Buffer)
		err = html.Render(buf, doc)
		if err != nil {
			log.Fatal(err)
		}

		note.Text = buf.String()
		err = db.Unscoped().Save(note).Error

		if err != nil {
			log.Fatal(err)
		}
	}
}

// saveNote creates a note if note.ID is blank or updates a note with given ID
func saveNote(c echo.Context) error {
	var err error
	user, _ := currentUser(c)
	if user == nil {
		return echo.ErrUnauthorized
	}

	note := new(Note)
	if err := c.Bind(note); err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	if note.ID == "" {

		newID, _ := uuid.NewV4()
		note.ID = newID.String()
		note.UserID = user.ID
		err = db.Create(note).Error
	} else {
		note.UpdatedAt = time.Now()
		err = db.Unscoped().Save(note).Error
	}

	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	go processNote(note)

	event := new(Event)
	event.Type = 3
	event.UserID = user.ID
	event.ClientType, _ = strconv.Atoi(c.Request().Header.Get("ClientType"))
	event.ClientID = c.Request().Header.Get("ClientID")
	db.Create(event)

	return c.JSON(http.StatusOK, note.ID)
}

func insertNote(c echo.Context) error {
	user, _ := currentUser(c)
	if user == nil {
		return echo.ErrUnauthorized
	}

	note := new(Note)
	if err := c.Bind(note); err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	note.UserID = user.ID

	// Check that the parent folder exsists in the database
	var parentFolder Folder
	err := db.Unscoped().Where("id = ?", note.FolderID).First(&parentFolder).Error

	if err != nil {
		return c.JSON(http.StatusNotFound, err.Error())
	}

	err = db.Create(note).Error

	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	event := new(Event)
	event.Type = 3
	event.UserID = user.ID
	event.ClientType, _ = strconv.Atoi(c.Request().Header.Get("ClientType"))
	event.ClientID = c.Request().Header.Get("ClientID")
	db.Create(event)

	return c.JSON(http.StatusOK, "OK")
}

func updateNote(c echo.Context) error {
	user, _ := currentUser(c)
	if user == nil {
		return echo.ErrUnauthorized
	}

	note := new(Note)
	if err := c.Bind(note); err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	err := db.Unscoped().Save(note).Error

	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	event := new(Event)
	event.Type = 3
	event.UserID = user.ID
	event.ClientType, _ = strconv.Atoi(c.Request().Header.Get("ClientType"))
	event.ClientID = c.Request().Header.Get("ClientID")
	db.Create(event)

	go processNote(note)

	return c.JSON(http.StatusOK, "OK")
}

// saveFolder creates a folder if folder.ID is blank or updates a folder with given ID
func saveFolder(c echo.Context) error {
	var err error
	user, _ := currentUser(c)
	if user == nil {
		return echo.ErrUnauthorized
	}

	folder := new(Folder)
	if err = c.Bind(folder); err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	if folder.ID == "" {
		newID, _ := uuid.NewV4()
		folder.ID = newID.String()
		folder.UserID = user.ID
		err = db.Create(folder).Error
	} else {
		folder.UpdatedAt = time.Now()
		err = db.Unscoped().Save(folder).Error
	}

	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	event := new(Event)
	event.Type = 3
	event.UserID = user.ID
	event.ClientType, _ = strconv.Atoi(c.Request().Header.Get("ClientType"))
	event.ClientID = c.Request().Header.Get("ClientID")
	db.Create(event)

	return c.JSON(http.StatusOK, folder.ID)
}

func insertFolder(c echo.Context) error {
	user, _ := currentUser(c)
	if user == nil {
		return echo.ErrUnauthorized
	}

	folder := new(Folder)
	if err := c.Bind(folder); err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	folder.UserID = user.ID

	if folder.ParentID == nil {
		return echo.NewHTTPError(500, "Uploading a root folder is not allowed")
	}

	// Check that the parent folder exsists in the database
	var parentFolder Folder
	err := db.Unscoped().Where("id = ?", folder.ParentID).First(&parentFolder).Error

	if err != nil {
		return c.JSON(http.StatusNotFound, err.Error())
	}

	err = db.Create(folder).Error

	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	event := new(Event)
	event.Type = 3
	event.UserID = user.ID
	event.ClientType, _ = strconv.Atoi(c.Request().Header.Get("ClientType"))
	event.ClientID = c.Request().Header.Get("ClientID")
	db.Create(event)

	return c.JSON(http.StatusOK, "OK")
}

func updateFolder(c echo.Context) error {
	user, _ := currentUser(c)
	if user == nil {
		return echo.ErrUnauthorized
	}

	folder := new(Folder)
	if err := c.Bind(folder); err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	err := db.Unscoped().Save(folder).Error

	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	event := new(Event)
	event.Type = 3
	event.UserID = user.ID
	event.ClientType, _ = strconv.Atoi(c.Request().Header.Get("ClientType"))
	event.ClientID = c.Request().Header.Get("ClientID")
	db.Create(event)

	return c.JSON(http.StatusOK, "OK")
}

func currentUser(c echo.Context) (*User, error) {
	token := c.Get(contextKey).(*jwt.Token)

	if token == nil {
		return nil, errors.New("The token is absent")
	}
	claims := token.Claims.(*jwtCustomClaims)
	userID := claims.UserID
	var user User
	err := db.First(&user, userID).Error

	if err != nil {
		return nil, errors.New("User not found in DB")
	}

	return &user, nil
}

func searchNotes(c echo.Context) error {
	query := c.QueryParam("query")
	folderID := c.QueryParam("folderId")
	user, _ := currentUser(c)
	if user == nil {
		return echo.ErrUnauthorized
	}

	var notes []Note
	var err error

	likeExpr := "%" + query + "%"

	if folderID == "" {
		err = db.Where("user_id = ? AND (title LIKE ? OR text like ?)", user.ID, likeExpr, likeExpr).Find(&notes).Error
	} else {
		err = db.Where("user_id = ? AND (title LIKE ? OR text like ?) AND folder_id = ?", user.ID, likeExpr, likeExpr, folderID).Find(&notes).Error
	}
	if err != nil {
		return echo.NewHTTPError(500, err.Error())
	}

	return c.JSON(http.StatusOK, notes)
}

func version(c echo.Context) error {
	return c.JSON(http.StatusOK, "Version " + GIGANOTES_SERVER_VERSION)
}

func anotherAppUpdate(c echo.Context) error {
	excludedClientID := c.Request().Header.Get("ClientID")

	user, _ := currentUser(c)
	if user == nil {
		return echo.ErrUnauthorized
	}

	var event Event
	err := db.Where("type = 3 AND user_id = ? AND client_id <> ?", user.ID, excludedClientID).Order("created_at desc").First(&event).Error

	if err != nil {
		return c.JSON(http.StatusOK, "")
	}

	return c.JSON(http.StatusOK, event)
}

func ws(c echo.Context) error {
	ws, err := upgrader.Upgrade(c.Response(), c.Request(), nil)
	if err != nil {
		return err
	}
	defer ws.Close()

	for {
		// Write
		err := ws.WriteMessage(websocket.TextMessage, []byte("Hello, Client!"))
		if err != nil {
			c.Logger().Error(err)
		}

		// Read
		_, msg, err := ws.ReadMessage()
		if err != nil {
			c.Logger().Error(err)
		}
		fmt.Printf("%s\n", msg)
	}
}

func feedback(c echo.Context) error {
	name := c.FormValue("name")
	email := c.FormValue("email")
	message := c.FormValue("message")

	f := Feedback{}
	f.Name = name
	f.Email = email
	f.Message = message

	db.Create(&f)

	go func() {

		userName := Config.GetString("mailUsername")
		from := Config.GetString("mailFrom")
		password := Config.GetString("mailPassword")
		smtpServer := Config.GetString("smtpServer")
		body := message

		m := gomail.NewMessage()
		m.SetHeader("From", from)
		m.SetHeader("To", from)
		m.SetHeader("Subject", "GigaNotes - feedback from "+name+" ("+email+")")
		m.SetBody("text/html", "<b>"+body+"</b>")

		d := gomail.NewDialer(smtpServer, 587, userName, password)
		d.DialAndSend(m)
	}()

	return c.JSON(http.StatusOK, "OK")
}

func stats(c echo.Context) error {
	var usersCount int
	db.Model(User{}).Count(&usersCount)

	var foldersCount int
	db.Model(Folder{}).Count(&foldersCount)

	var notesCount int
	db.Model(Note{}).Count(&notesCount)

	var todaysRegistrations int
	t := time.Now()
	year, month, day := t.Date()
	startOfDay := time.Date(year, month, day, 0, 0, 0, 0, t.Location())
	db.Model(User{}).Where("created_at > ?", startOfDay).Count(&todaysRegistrations)

	var todayFoldersCreated int
	db.Model(Folder{}).Where("created_at > ?", startOfDay).Count(&todayFoldersCreated)

	var todayNotesCreated int
	db.Model(Note{}).Where("created_at > ?", startOfDay).Count(&todayNotesCreated)

	type CountResult struct {
		Count int
	}

	var registeredWeekResult CountResult
	db.Raw("SELECT COUNT(DISTINCT(id)) as count FROM users WHERE created_at > date_trunc('week', current_date)").Scan(&registeredWeekResult)

	var registeredMonthResult CountResult
	db.Raw("SELECT COUNT(DISTINCT(id)) as count FROM users WHERE created_at > date_trunc('month', current_date)").Scan(&registeredMonthResult)

	var activeUsersResult CountResult
	db.Raw("SELECT COUNT(DISTINCT(user_id)) as count FROM events WHERE created_at > date_trunc('day', current_date)").Scan(&activeUsersResult)

	var activeDesktopUsersResult CountResult
	db.Raw("SELECT COUNT(DISTINCT(user_id)) as count FROM events WHERE created_at > date_trunc('day', current_date) AND client_type = 1").Scan(&activeDesktopUsersResult)

	var activeWebUsersResult CountResult
	db.Raw("SELECT COUNT(DISTINCT(user_id)) as count FROM events WHERE created_at > date_trunc('day', current_date) AND client_type = 2").Scan(&activeWebUsersResult)

	var activeMobileUsersResult CountResult
	db.Raw("SELECT COUNT(DISTINCT(user_id)) as count FROM events WHERE created_at > date_trunc('day', current_date) AND client_type = 3").Scan(&activeMobileUsersResult)

	// Weekly

	var activeUsersWeeklyResult CountResult
	db.Raw("SELECT COUNT(DISTINCT(user_id)) as count FROM events WHERE created_at > date_trunc('week', current_date)").Scan(&activeUsersWeeklyResult)

	var activeDesktopUsersWeeklyResult CountResult
	db.Raw("SELECT COUNT(DISTINCT(user_id)) as count FROM events WHERE created_at > date_trunc('week', current_date) AND client_type = 1").Scan(&activeDesktopUsersWeeklyResult)

	var activeWebUsersWeeklyResult CountResult
	db.Raw("SELECT COUNT(DISTINCT(user_id)) as count FROM events WHERE created_at > date_trunc('week', current_date) AND client_type = 2").Scan(&activeWebUsersWeeklyResult)

	var activeMobileUsersWeeklyResult CountResult
	db.Raw("SELECT COUNT(DISTINCT(user_id)) as count FROM events WHERE created_at > date_trunc('week', current_date) AND client_type = 3").Scan(&activeMobileUsersWeeklyResult)

	// Monthly

	var activeUsersMonthlyResult CountResult
	db.Raw("SELECT COUNT(DISTINCT(user_id)) as count FROM events WHERE created_at > date_trunc('month', current_date)").Scan(&activeUsersMonthlyResult)

	var activeDesktopUsersMonthlyResult CountResult
	db.Raw("SELECT COUNT(DISTINCT(user_id)) as count FROM events WHERE created_at > date_trunc('month', current_date) AND client_type = 1").Scan(&activeDesktopUsersMonthlyResult)

	var activeWebUsersMonthlyResult CountResult
	db.Raw("SELECT COUNT(DISTINCT(user_id)) as count FROM events WHERE created_at > date_trunc('month', current_date) AND client_type = 2").Scan(&activeWebUsersMonthlyResult)

	var activeMobileUsersMonthlyResult CountResult
	db.Raw("SELECT COUNT(DISTINCT(user_id)) as count FROM events WHERE created_at > date_trunc('month', current_date) AND client_type = 3").Scan(&activeMobileUsersMonthlyResult)

	return c.JSON(http.StatusOK, map[string]interface{}{
		"usersCountTotal":         usersCount,
		"foldersCountTotal":       foldersCount,
		"notesCountTotal":         notesCount,
		"foldersCreatedToday":     todayFoldersCreated,
		"notesCreatedToday":       todayNotesCreated,
		"registeredToday":         todaysRegistrations,
		"registeredWeek":          registeredWeekResult.Count,
		"registereMonth":          registeredMonthResult.Count,
		"usersActiveToday":        activeUsersResult.Count,
		"usersDesktopActiveToday": activeDesktopUsersResult.Count,
		"usersWebActiveToday":     activeWebUsersResult.Count,
		"usersMobileActiveToday":  activeMobileUsersResult.Count,
		"usersActiveWeek":         activeUsersWeeklyResult.Count,
		"usersDesktopActiveWeek":  activeDesktopUsersWeeklyResult.Count,
		"usersWebActiveWeek":      activeWebUsersWeeklyResult.Count,
		"usersMobileActiveWeek":   activeMobileUsersWeeklyResult.Count,
		"usersActiveMonth":        activeUsersMonthlyResult.Count,
		"usersDesktopActiveMonth": activeDesktopUsersMonthlyResult.Count,
		"usersWebActiveMonth":     activeWebUsersMonthlyResult.Count,
		"usersMobileActiveMonth":  activeMobileUsersMonthlyResult.Count,
	})
}
