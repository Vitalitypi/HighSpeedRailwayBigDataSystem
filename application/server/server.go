package server

import (
	"fmt"
	"net/http"
)

func handleQuery(w http.ResponseWriter, r *http.Request) {
	values := r.URL.Query()
	fmt.Println(values)
	w.Write([]byte("hello,world"))
}
func handleRegister(w http.ResponseWriter, r *http.Request) {
	values := r.URL.Query()
	fmt.Println(values, r.Method)
	form := make([]byte, 1024)
	r.Body.Read(form)
	fmt.Println(string(form))
	w.Write([]byte("hello,world"))
}
func StartHttpSever() {
	http.HandleFunc("/query", handleQuery)
	http.HandleFunc("/register", handleRegister)
	http.ListenAndServe("localhost:6666", nil)
}
