/*
Cliente
*/
package cli

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sdspractica/srv"
	"sdspractica/util"
	"strconv"
	"strings"
	"time"
)

var usuarioActual string
var ruta string
var exit bool

type nota struct {
	Usuario   string
	Contenido string
}

type fichero struct {
	Nombre        string
	Contenido     string
	Key           []byte
	Autor         string
	Public        bool
	SharedUsers   map[string]user
	Notas         []nota
	NumCaracteres int
	Extension     string
	NumRevisiones int
	FechaCreacion time.Time
	Version       int
}

type user struct {
	Name       string            // nombre de usuario
	Hash       []byte            // hash de la contraseña
	Salt       []byte            // sal para la contraseña
	Token      []byte            // token de sesión
	Seen       time.Time         // última vez que fue visto
	Data       map[string]string // datos adicionales del usuario
	Directorio directorio        // directorio del usuario
}

type directorio struct {
	Nombre   string
	Ficheros map[string]fichero
}

type PasswordConfig struct {
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

var config = &PasswordConfig{
	time:    1,
	memory:  64 * 1024,
	threads: 4,
	keyLen:  32,
}

func chk(e error) {
	if e != nil {
		panic(e)
	}
}

func registro(pubJSON []byte, pkJSON []byte, client *http.Client) {

	usuario := ""
	password := ""

	fmt.Println("\n*** Registro ***")
	fmt.Print("Usuario: ")
	fmt.Scanln(&usuario)
	fmt.Print("Contraseña: ")
	fmt.Scanln(&password)

	data := url.Values{}
	data.Set("cmd", "register")
	data.Set("user", usuario)

	keyClient := sha512.Sum512([]byte(password))
	keyLogin := keyClient[:32]  // una mitad para el login (256 bits)
	keyData := keyClient[32:64] // la otra para los datos (256 bits)

	data.Set("pass", util.Encode64(keyLogin))

	// comprimimos y codificamos la clave pública
	data.Set("pubkey", util.Encode64(util.Compress(pubJSON)))

	// comprimimos, ciframos y codificamos la clave privada
	data.Set("prikey", util.Encode64(util.Encrypt(util.Compress(pkJSON), keyData)))

	r, err := client.PostForm("https://localhost:10443", data)
	chk(err)
	fmt.Println("El usuario se ha registrado correctamente")
	r.Body.Close()
}

func login(client *http.Client) {
	usuario := ""
	password := ""

	fmt.Println("\n*** Login ***")
	fmt.Print("Usuario: ")
	fmt.Scanln(&usuario)
	fmt.Print("Contraseña: ")
	fmt.Scanln(&password)

	data := url.Values{}
	data.Set("cmd", "login")  // comando (string)
	data.Set("user", usuario) // usuario (string)

	// hash con SHA512 de la contraseña
	keyClient := sha512.Sum512([]byte(password))
	keyLogin := keyClient[:32] // una mitad para el login (256 bits)

	data.Set("pass", util.Encode64(keyLogin))                  // contraseña (a base64 porque es []byte)
	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	resp := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // decodificamos la respuesta para utilizar sus campos más adelante
	if resp.Ok {
		usuarioActual = usuario
		ruta = "/" + usuarioActual
		menuLogin()
	} else {
		fmt.Println("Credenciales inválidas")
	}
	r.Body.Close()
}

func menuLogin() {
	cadena := ""
	exit = false

	for !exit {
		fmt.Println("\n*** Home ***")
		fmt.Print("Introduce 'help' para obtener información de los comandos\n\n")
		fmt.Println("ruta: " + ruta)
		fmt.Print("$ ")
		inputReader := bufio.NewReader(os.Stdin)
		cadena, _ = inputReader.ReadString('\n')
		accionComando(cadena)
	}
}

func lsComando(client *http.Client) {
	data := url.Values{}
	data.Set("cmd", "ls")
	data.Set("user", usuarioActual)
	data.Set("ruta", ruta)

	r, err := client.PostForm("https://localhost:10443", data)
	chk(err)
	resp := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // decodificamos la respuesta para utilizar sus campos más adelante
	if resp.Ok {
		fmt.Println(resp.Msg)
	}
	r.Body.Close()
}

func uploadComando(nombreFichero string, client *http.Client) {
	data := url.Values{}
	data.Set("cmd", "upload")
	data.Set("user", usuarioActual)

	nombreFichero = nombreFichero[:len(nombreFichero)-2]
	file, err := ioutil.ReadFile("./ficheros/" + nombreFichero)
	if err != nil {
		fmt.Println(err)
	} else {
		data.Set("ruta", ruta)
		data.Set("ruta", ruta)
		data.Set("contenidoFichero", string(file))
		data.Set("nombreFichero", nombreFichero)

		r, err := client.PostForm("https://localhost:10443", data)
		chk(err)
		resp := srv.Resp{}
		json.NewDecoder(r.Body).Decode(&resp)
		fmt.Println(resp.Msg)
		r.Body.Close()
	}
}

func touchComando(nombreFichero string, client *http.Client) {
	data := url.Values{}
	data.Set("cmd", "touch")
	data.Set("user", usuarioActual)
	data.Set("ruta", ruta)
	data.Set("nombreFichero", nombreFichero)
	fmt.Print("Contenido: ")
	inputReader := bufio.NewReader(os.Stdin)
	cadena, _ := inputReader.ReadString('\n')
	cadena = cadena[:len(cadena)-2]
	data.Set("contenido", cadena)

	r, err := client.PostForm("https://localhost:10443", data)
	chk(err)
	resp := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&resp)
	fmt.Println(resp.Msg)

	r.Body.Close()
}

func shareComando(nombreFichero string, usuario string, client *http.Client) {
	data := url.Values{}
	data.Set("cmd", "share")
	data.Set("user", usuarioActual)
	data.Set("nombreFichero", nombreFichero)
	data.Set("userShare", usuario)

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	resp := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&resp)
	fmt.Println(resp.Msg)
	r.Body.Close()
}

func unshareComando(nombreFichero string, usuario string, client *http.Client) {
	data := url.Values{}
	data.Set("cmd", "unshare")
	data.Set("user", usuarioActual)
	data.Set("nombreFichero", nombreFichero)
	data.Set("userUnshare", usuario)

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	resp := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&resp)
	fmt.Println(resp.Msg)
	r.Body.Close()
}

func publicComando(nombreFichero string, client *http.Client) {
	data := url.Values{}
	data.Set("cmd", "public")
	data.Set("user", usuarioActual)
	data.Set("nombreFichero", nombreFichero)

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	resp := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&resp)
	fmt.Println(resp.Msg)
	r.Body.Close()
}

func privateComando(nombreFichero string, client *http.Client) {
	data := url.Values{}
	data.Set("cmd", "private")
	data.Set("user", usuarioActual)
	data.Set("nombreFichero", nombreFichero)

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	resp := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&resp)
	fmt.Println(resp.Msg)
	r.Body.Close()
}

func catComando(nombreFichero string, client *http.Client) {
	data := url.Values{}
	data.Set("cmd", "cat")
	data.Set("user", usuarioActual)
	data.Set("nombreFichero", nombreFichero)
	data.Set("ruta", ruta)
	r, err := client.PostForm("https://localhost:10443", data)
	chk(err)
	resp := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&resp)
	var fichero fichero
	json.Unmarshal([]byte(resp.Msg), &fichero)
	if resp.Ok { // Mostramos el contenido del fichero
		nombreFichero := strings.Split(resp.Msg, " ")[0]
		contenidoFichero := resp.Msg[len(nombreFichero)+1 : len(resp.Msg)]
		fmt.Println("Nombre: " + nombreFichero)
		fmt.Println(contenidoFichero)
	} else {
		fmt.Println(resp.Msg)
	}
	r.Body.Close()
}

func deleteComando(nombreFichero string, client *http.Client) {

	data := url.Values{}
	data.Set("cmd", "delete")
	data.Set("user", usuarioActual)
	data.Set("nombreFichero", nombreFichero)

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	resp := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&resp)
	if resp.Ok {
		fmt.Println(resp.Msg)
	} else {
		fmt.Println(resp.Msg)
	}
	r.Body.Close()
}

func detailsComando(nombreFichero string, client *http.Client) {

	data := url.Values{}
	data.Set("cmd", "details")
	data.Set("user", usuarioActual)
	data.Set("nombreFichero", nombreFichero)
	data.Set("ruta", ruta)

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	resp := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // decodificamos la respuesta para utilizar sus campos más adelante
	var fichero fichero
	json.Unmarshal([]byte(resp.Msg), &fichero)

	if resp.Ok { // Mostramos el contenido del fichero
		fmt.Println("Nombre: " + strings.Split(fichero.Nombre, "/")[0])
		fmt.Println("Autor: " + fichero.Autor)
		fmt.Println("Public: " + strconv.FormatBool(fichero.Public))
		if len(fichero.SharedUsers) > 0 {
			fmt.Println("------------------------------------------------------------")
			fmt.Print("Usuarios compartidos: ")
			for key := range fichero.SharedUsers {
				fmt.Print(key)
			}
			fmt.Println()
		}
		if len(fichero.Notas) > 0 {
			fmt.Println("------------------------------------------------------------")
			fmt.Print("Notas\n\n")
			for i := 0; i < len(fichero.Notas); i++ {
				fmt.Println("Autor: " + fichero.Notas[i].Usuario)
				fmt.Println(fichero.Notas[i].Contenido + "\n")
				fmt.Println("------------------------------------------------------------")
			}
		}
		fmt.Println("Número de carácteres: " + strconv.Itoa(fichero.NumCaracteres))
		fmt.Println("Formato: " + fichero.Extension)
		fmt.Println("Número de revisiones: " + strconv.Itoa(fichero.NumRevisiones))
		fmt.Println("Fecha de creación: " + fichero.FechaCreacion.Format("2006-01-02 15:04:05"))
		fmt.Println("Versión: " + strconv.Itoa(fichero.Version))
	} else {
		fmt.Println(resp.Msg)
	}
	r.Body.Close() // hay que cerrar el reader del body
}

func cdComando(directorio string, client *http.Client) {

	data := url.Values{}
	data.Set("cmd", "cd")
	data.Set("user", usuarioActual)
	data.Set("directorio", directorio)

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	resp := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // decodificamos la respuesta para utilizar sus campos más adelante
	if resp.Ok {
		ruta = resp.Msg
	} else {
		fmt.Println(resp.Msg)
	}
	r.Body.Close()
}

func noteComando(nombreFichero string, client *http.Client) {

	data := url.Values{}
	data.Set("cmd", "note")
	data.Set("user", usuarioActual)
	data.Set("nombreFichero", nombreFichero)
	data.Set("ruta", ruta)
	fmt.Print("Contenido: ")
	inputReader := bufio.NewReader(os.Stdin)
	cadena, _ := inputReader.ReadString('\n')
	data.Set("contenido", cadena)
	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	resp := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // decodificamos la respuesta para utilizar sus campos más adelante
	fmt.Println(resp.Msg)
	r.Body.Close()
}

func accionComando(cadena string) {

	var moreCommands = true
	trozos := strings.Split(cadena, " ")
	comando := trozos[0]
	if len(trozos) == 1 {
		moreCommands = false
		comando = comando[:len(comando)-2]
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	switch comando {
	case "help":

		if moreCommands {
			fmt.Println("Este comando no acepta argumentos")
		} else {
			helpComando()
		}
	case "ls":

		if moreCommands {
			fmt.Println("Este comando no acepta argumentos")
		} else {
			lsComando(client)
		}
	case "cd":

		if moreCommands {
			directorio := trozos[1]
			cdComando(directorio, client)
		} else {
			ruta = "/"
		}
	case "touch":

		if !moreCommands {
			fmt.Println("Debes introducir el nombre del fichero como argumento")
		} else {
			if len(trozos) > 2 {
				fmt.Println("Debes introducir el nombre del fichero únicamente")
			} else {
				nombreFichero := trozos[1]
				touchComando(nombreFichero, client)
			}
		}
	case "cat":

		if len(trozos) != 2 {
			fmt.Println("Error al introducir argumentos")
		} else {
			nombreFichero := trozos[1]
			catComando(nombreFichero, client)
		}
	case "upload":

		if len(trozos) != 2 {
			fmt.Println("Error al introducir argumentos")
		} else {
			nombreFichero := trozos[1]
			uploadComando(nombreFichero, client)
		}
	case "delete":

		if len(trozos) != 2 {
			fmt.Println("Error al introducir argumentos")
		} else {
			nombreFichero := trozos[1]
			deleteComando(nombreFichero, client)
		}
	case "details":

		if len(trozos) != 2 {
			fmt.Println("Error al introducir argumentos")
		} else {
			nombreFichero := trozos[1]
			detailsComando(nombreFichero, client)
		}
	case "share":

		if !moreCommands {
			fmt.Println("Debes introducir el nombre del fichero y del usuario a compartir")
		} else {
			if len(trozos) == 2 || len(trozos) > 3 {
				fmt.Println("Debes introducir el nombre del fichero y del usuario a compartir únicamente")
			} else if len(trozos) == 3 {
				nombreFichero := trozos[1]
				usuario := trozos[2]
				shareComando(nombreFichero, usuario, client)
			}
		}
	case "unshare":

		if !moreCommands {
			fmt.Println("Debes introducir el nombre del fichero y del usuario a compartir")
		} else {
			if len(trozos) == 2 || len(trozos) > 3 {
				fmt.Println("Debes introducir el nombre del fichero y del usuario a compartir únicamente")
			} else if len(trozos) == 3 {
				nombreFichero := trozos[1]
				usuario := trozos[2]
				unshareComando(nombreFichero, usuario, client)
			}
		}
	case "public":

		if !moreCommands {
			fmt.Println("Debes introducir el nombre del fichero como argumento")
		} else {
			if len(trozos) > 2 {
				fmt.Println("Debes introducir el nombre del fichero únicamente")
			} else {
				nombreFichero := trozos[1]
				publicComando(nombreFichero, client)
			}
		}
	case "private":

		if !moreCommands {
			fmt.Println("Debes introducir el nombre del fichero como argumento")
		} else {
			if len(trozos) > 2 {
				fmt.Println("Debes introducir el nombre del fichero únicamente")
			} else {
				nombreFichero := trozos[1]
				privateComando(nombreFichero, client)
			}
		}
	case "note":

		if !moreCommands {
			fmt.Println("Debes introducir el nombre del fichero como argumento")
		} else {
			if len(trozos) > 3 {
				fmt.Println("Debes introducir el nombre del fichero únicamente")
			} else {
				nombreFichero := trozos[1]
				noteComando(nombreFichero, client)
			}
		}
	case "exit":
		exit = true
	default:
		fmt.Println("Error al introducir el comando")
	}
}

func helpComando() {

	comandosHelp :=
		`
*** Comandos ***
	
ls 						Muestra los ficheros que se encuentren en la ruta
cd 						Te lleva al directorio raíz
cd [nombre_usuario]				Te lleva al directorio del usuario				
touch [nombre_fichero] 				Crea un fichero en la ruta
cat [nombre_fichero] 				Muestra el contenido del fichero
upload [nombre_fichero]				Sube un fichero de la carpeta ficheros
details [nombre_fichero]			Muestra los detalles(metadatos) del fichero
delete [nombre_fichero]				Elimina un fichero
share [nombre_fichero] [nombre_usuario]		Comparte el fichero con otro usuario
unshare [nombre_fichero] [nombre_usuario]	Descomparte el fichero con otro usuario
public [nombre_fichero]				Pone el fichero público para los demás usuarios
private [nombre_fichero]			Pone el fichero privado
note [nombre_fichero] 				Escribe una nota en el fichero
exit						Salir al menú inicial

`
	fmt.Print(comandosHelp)

}

// Run gestiona el modo cliente
func Run() {

	// menu
	var opcion int

	menu :=
		`
*** Práctica SDS ***
	Menú

[ 1 ] Registro
[ 2 ] Iniciar sesión
[ 3 ] Salir

`
	for opcion != 3 {
		fmt.Print(menu)
		fmt.Print("Opcion: ")
		fmt.Scanln(&opcion)

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}

		// generamos un par de claves (privada, pública) para el servidor
		pkClient, err := rsa.GenerateKey(rand.Reader, 1024)
		chk(err)
		pkClient.Precompute() // aceleramos su uso con un precálculo

		pkJSON, err := json.Marshal(&pkClient) // codificamos con JSON
		chk(err)

		keyPub := pkClient.Public()           // extraemos la clave pública por separado
		pubJSON, err := json.Marshal(&keyPub) // y codificamos con JSON
		chk(err)

		switch opcion {
		case 1:
			registro(pubJSON, pkJSON, client)
		case 2:
			login(client)
		default:
			fmt.Println("Hasta luego!!")
		}
	}
}
