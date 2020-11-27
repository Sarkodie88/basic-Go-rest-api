package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/dgrijalva/jwt-go"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
	"golang.org/x/crypto/bcrypt"
)

// Order represents the model for an order
// Default table name will be `orders`
type Order struct {
	// gorm.Model
	OrderID      uint      `json:"orderId" gorm:"primary_key"`
	CustomerName string    `json:"customerName"`
	OrderedAt    time.Time `json:"orderedAt"`
	Location     string    `json:"location"`
	// Items        []Item    `json:"items" gorm:"foreignkey:OrderID"`
}

// Item represents the model for an item in the order
type Item struct {
	// gorm.Model
	LineItemID  uint   `json:"lineItemId" gorm:"primary_key"`
	ItemCode    string `json:"itemCode"`
	Description string `json:"description"`
	Quantity    uint   `json:"quantity"`
	// OrderID     uint   `json:"-"`
}

type Book struct {
	// gorm.Model
	Title  string `json:"title"`
	Author string `json:"author"`
}

type User struct {
	// gorm.Model
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Msg struct {
	// gorm.Model
	Message string `json:"message"`
}

type Tkn struct {
	// gorm.Model
	Token string `json:"token"`
}

type Token struct {
	// gorm.Model
	Email string `json:"email"`
	*jwt.StandardClaims
}

var db *gorm.DB

func initDB() {
	var err error
	dataSourceName := "root:sark@tcp(localhost:3306)/?parseTime=True"
	db, err = gorm.Open("mysql", dataSourceName)

	if err != nil {
		fmt.Println(err)
		panic("failed to connect database")
	}

	// Create the database. This is a one-time step.
	// Comment out if running multiple times - You may see an error otherwise
	db.Exec("CREATE DATABASE if not exists orders_db")
	db.Exec("USE orders_db")

	// Migration to create tables for Order and Item schema
	db.AutoMigrate(&Order{}, &Item{}, &Book{}, &User{})
}

func createOrder(w http.ResponseWriter, r *http.Request) {
	var order Order
	json.NewDecoder(r.Body).Decode(&order)
	// Creates new order by inserting records in the `orders` and `items` table
	db.Create(&order)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(order)
}

func createBook(w http.ResponseWriter, r *http.Request) {
	var book Book
	json.NewDecoder(r.Body).Decode(&book)
	db, err := sql.Open("mysql", "root:sark@tcp(127.0.0.1:3306)/orders_db")
	if err != nil {
		return
	}
	insForm, err := db.Prepare("INSERT INTO books(title, author) VALUES(?, ?)")
	if err != nil {
		panic(err.Error())
	}
	insForm.Exec(book.Title, book.Author)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(book)
}

func userLogin(w http.ResponseWriter, r *http.Request) {
	var user User
	json.NewDecoder(r.Body).Decode(&user)
	db, err := sql.Open("mysql", "root:sark@tcp(127.0.0.1:3306)/orders_db")
	if err != nil {
		return
	}
	var mail, pass string
	selDB, err := db.Query("SELECT * FROM users WHERE email=?", user.Email)
	if err != nil {
		return
	}
	if selDB.Next() {
		err = selDB.Scan(&mail, &pass)
		if err != nil {
			return
		}
		err = bcrypt.CompareHashAndPassword([]byte(pass), []byte(user.Password))
		if err != nil {
			// log.Println("password incorrect")
			mess := Msg{"incorrect password"}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(mess)
		} else {

			expiresAt := time.Now().Add(time.Minute * 1000).Unix()
			tk := Token{
				Email: user.Email,
				StandardClaims: &jwt.StandardClaims{
					ExpiresAt: expiresAt,
				},
			}
			token := jwt.NewWithClaims(jwt.GetSigningMethod("HS256"), tk)

			tokenString, error := token.SignedString([]byte("secret"))
			if error != nil {
				log.Println(error)
			}
			mess := Tkn{tokenString}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(mess)
		}
	} else {
		mess := Msg{"incorrect email"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mess)
		// log.Println("incorrect email")
	}

}

func createUser(w http.ResponseWriter, r *http.Request) {
	var user User
	json.NewDecoder(r.Body).Decode(&user)
	db, err := sql.Open("mysql", "root:sark@tcp(127.0.0.1:3306)/orders_db")
	if err != nil {
		return
	}
	selDB, err := db.Query("SELECT * FROM users WHERE email=?", user.Email)
	if err != nil {
		return
	}
	if !selDB.Next() {
		cost := bcrypt.DefaultCost
		hash, err := bcrypt.GenerateFromPassword([]byte(user.Password), cost)
		if err != nil {
			return
		}
		user.Password = string(hash)

		// MYSQL code for database insert.
		insForm, err := db.Prepare("INSERT INTO users(email, password) VALUES(?, ?)")
		if err != nil {
			panic(err.Error())
		}
		insForm.Exec(user.Email, hash)
		mess1 := Msg{"user created successfully"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(user)
		json.NewEncoder(w).Encode(mess1)
	} else {
		mess := Msg{"email already associated with a user"}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(mess)
		// http.Error(w, err.Error(), 400)
	}
	defer db.Close()
}

func getOrders(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var orders []Order
	db.Preload("Items").Find(&orders)
	json.NewEncoder(w).Encode(orders)
}

func getOrder(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	params := mux.Vars(r)
	inputOrderID := params["orderId"]

	var order Order
	db.Preload("Items").First(&order, inputOrderID)
	json.NewEncoder(w).Encode(order)
}

func updateOrder(w http.ResponseWriter, r *http.Request) {
	var updatedOrder Order
	json.NewDecoder(r.Body).Decode(&updatedOrder)
	db.Save(&updatedOrder)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(updatedOrder)
}

func deleteOrder(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	inputOrderID := params["orderId"]
	// Convert `orderId` string param to uint64
	id64, _ := strconv.ParseUint(inputOrderID, 10, 64)
	// Convert uint64 to uint
	idToDelete := uint(id64)

	db.Where("order_id = ?", idToDelete).Delete(&Item{})
	db.Where("order_id = ?", idToDelete).Delete(&Order{})
	w.WriteHeader(http.StatusNoContent)
}

func main() {
	router := mux.NewRouter()
	// Create
	router.HandleFunc("/orders", createOrder).Methods("POST")
	// Read
	router.HandleFunc("/orders/{orderId}", getOrder).Methods("GET")
	// Read-all
	router.HandleFunc("/orders", getOrders).Methods("GET")
	// Update
	router.HandleFunc("/orders/{orderId}", updateOrder).Methods("PUT")
	// Delete
	router.HandleFunc("/orders/{orderId}", deleteOrder).Methods("DELETE")
	//create book
	router.HandleFunc("/books", createBook).Methods("POST")
	// create user
	router.HandleFunc("/users", createUser).Methods("POST")
	// user login
	router.HandleFunc("/login", userLogin).Methods("POST")

	// Initialize db connection
	initDB()
	log.Println("listening on http://localhost:8080")

	log.Fatal(http.ListenAndServe(":8080", router))
}
