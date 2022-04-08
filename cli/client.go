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
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"sdspractica/srv"
	"sdspractica/util"
	"strings"
)

var usuarioActual string

// chk comprueba y sale si hay errores (ahorra escritura en programas sencillos)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

func registro(pubJSON []byte, pkJSON []byte, client *http.Client) {

	usuario := ""
	password := ""

	fmt.Println("*** Registro ***")
	fmt.Println("Usuario: ")
	fmt.Scanln(&usuario)
	fmt.Println("Contraseña: ")
	fmt.Scanln(&password)

	// ** ejemplo de registro
	data := url.Values{}        // estructura para contener los valores
	data.Set("cmd", "register") // comando (string)
	data.Set("user", usuario)   // usuario (string)

	// hash con SHA512 de la contraseña
	keyClient := sha512.Sum512([]byte(password))
	keyLogin := keyClient[:32]  // una mitad para el login (256 bits)
	keyData := keyClient[32:64] // la otra para los datos (256 bits)

	data.Set("pass", util.Encode64(keyLogin)) // "contraseña" a base64

	// comprimimos y codificamos la clave pública
	data.Set("pubkey", util.Encode64(util.Compress(pubJSON)))

	// comprimimos, ciframos y codificamos la clave privada
	data.Set("prikey", util.Encode64(util.Encrypt(util.Compress(pkJSON), keyData)))

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	r.Body.Close()             // hay que cerrar el reader del body
	fmt.Println()
}

func login(client *http.Client) {
	// ** ejemplo de login

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
	fmt.Println(resp)                     // imprimimos por pantalla
	if resp.Ok {
		usuarioActual = usuario
		menuLogin()
	}
	r.Body.Close() // hay que cerrar el reader del body
}

func lsComando(client *http.Client) {
	fmt.Println("entra en ls")
	data := url.Values{}
	data.Set("cmd", "ls")           // comando (string)
	data.Set("user", usuarioActual) // usuario (string)

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	resp := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // decodificamos la respuesta para utilizar sus campos más adelante
	fmt.Println(resp)                     // imprimimos por pantalla
	if resp.Ok {
		fmt.Println("Directorios:")
		fmt.Println(resp.Msg)
	}
	r.Body.Close() // hay que cerrar el reader del body
}

func menuLogin() {

	cadena := ""

	for strings.Split(cadena, " ")[0] != "exit" {
		fmt.Println("\n*** Home ***")
		fmt.Print("Introduce 'help' para obtener información de los comandos\n\n")
		fmt.Print("$ ")
		inputReader := bufio.NewReader(os.Stdin)
		cadena, _ = inputReader.ReadString('\n')
		accionComando(cadena)
	}
}

func uploadComando(ruta string, nombreFichero string, client *http.Client) {
	// ** ejemplo de registro
	data := url.Values{}            // estructura para contener los valores
	data.Set("cmd", "upload")       // comando (string)
	data.Set("user", usuarioActual) // usuario (string)
	//dir, err := os.Getwd()
	//fmt.Println(dir)
	file, err := ioutil.ReadFile("./ficheros/" + ruta)
	if err != nil {
		fmt.Println(err)
	} else {
		//fmt.Println(string(file))

		data.Set("contenidoFichero", string(file)) // usuario (string)
		data.Set("nombreFichero", nombreFichero)

		r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
		chk(err)
		resp := srv.Resp{}
		json.NewDecoder(r.Body).Decode(&resp) // decodificamos la respuesta para utilizar sus campos más adelante
		//fmt.Println(resp)                     // imprimimos por pantalla
		if resp.Ok {
			fmt.Println(resp.Msg)
		} else {
			fmt.Println(resp.Msg)
		}
		r.Body.Close() // hay que cerrar el reader del body

		// imprimir el string
		//fmt.Println(datosComoString)
	}

}

func catComando(nombreFichero string, client *http.Client) {
	// ** ejemplo de registro
	data := url.Values{}                     // estructura para contener los valores
	data.Set("cmd", "cat")                   // comando (string)
	data.Set("user", usuarioActual)          // usuario (string)
	data.Set("nombreFichero", nombreFichero) // nombre del fichero (string)

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	resp := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // decodificamos la respuesta para utilizar sus campos más adelante
	//fmt.Println(resp)                     // imprimimos por pantalla
	if resp.Ok {
		fmt.Println(resp.Msg)
	} else {
		fmt.Println(resp.Msg)
	}
	r.Body.Close() // hay que cerrar el reader del body
}

func deleteComando(nombreFichero string, client *http.Client) {
	// ** ejemplo de registro
	data := url.Values{}                     // estructura para contener los valores
	data.Set("cmd", "delete")                // comando (string)
	data.Set("user", usuarioActual)          // usuario (string)
	data.Set("nombreFichero", nombreFichero) // nombre del fichero (string)

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	resp := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // decodificamos la respuesta para utilizar sus campos más adelante
	//fmt.Println(resp)                     // imprimimos por pantalla
	if resp.Ok {
		fmt.Println(resp.Msg)
	} else {
		fmt.Println(resp.Msg)
	}
	r.Body.Close() // hay que cerrar el reader del body
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
		break
	case "touch":
		//accion_touch()
		break
	case "cat":
		if len(trozos) != 2 {
			fmt.Println("Error al introducir argumentos")
		} else {
			nombreFichero := trozos[1]
			catComando(nombreFichero, client)
		}
		break
	case "upload":
		if len(trozos) != 3 {
			fmt.Println("Error al introducir argumentos")
		} else {
			ruta := trozos[1]
			nombreFichero := trozos[2]
			uploadComando(ruta, nombreFichero, client)
		}
		break
	case "delete":
		if len(trozos) != 2 {
			fmt.Println("Error al introducir argumentos")
		} else {
			nombreFichero := trozos[1]
			deleteComando(nombreFichero, client)
		}
		break
	case "share":
		//accion_share()
		break
	default:
		fmt.Println("Ese comando no existe")
		break
	}
}

func helpComando() {

	// NO CAMBIAR -- SE MUESTRAN BIEN
	comandosHelp :=
		`
*** Comandos ***
	
ls 						Muestra los ficheros que se encuentren en la ruta
touch [nombre_fichero] 				Crea un fichero en la ruta
cat [nombre_fichero] 				Muestra el contenido del fichero
upload [ruta] [nombre_fichero]			Sube un fichero a partir de una ruta
delete [nombre_fichero]				Elimina un fichero
share [nombre_fichero] [nombre_usuario]		Comparte el fichero con otro usuario

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

		/* creamos un cliente especial que no comprueba la validez de los certificados
		esto es necesario por que usamos certificados autofirmados (para pruebas) */

		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}

		// hash con SHA512 de la contraseña
		/*
			keyClient := sha512.Sum512([]byte("contraseña del cliente"))
			keyLogin := keyClient[:32]  // una mitad para el login (256 bits)
			keyData := keyClient[32:64] // la otra para los datos (256 bits)
		*/

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
			break
		case 2:
			login(client)
			break
		default:
			fmt.Println("Hasta luego!!")
			break
		}
	}

	/*

		// ** ejemplo de registro
		data := url.Values{}                      // estructura para contener los valores
		data.Set("cmd", "register")               // comando (string)
		data.Set("user", "usuario")               // usuario (string)
		data.Set("pass", util.Encode64(keyLogin)) // "contraseña" a base64

		// comprimimos y codificamos la clave pública
		data.Set("pubkey", util.Encode64(util.Compress(pubJSON)))

		// comprimimos, ciframos y codificamos la clave privada
		data.Set("prikey", util.Encode64(util.Encrypt(util.Compress(pkJSON), keyData)))

		r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
		chk(err)
		io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
		r.Body.Close()             // hay que cerrar el reader del body
		fmt.Println()

		// ** ejemplo de login
		data = url.Values{}
		data.Set("cmd", "login")                                  // comando (string)
		data.Set("user", "usuario")                               // usuario (string)
		data.Set("pass", util.Encode64(keyLogin))                 // contraseña (a base64 porque es []byte)
		r, err = client.PostForm("https://localhost:10443", data) // enviamos por POST
		chk(err)
		resp := srv.Resp{}
		json.NewDecoder(r.Body).Decode(&resp) // decodificamos la respuesta para utilizar sus campos más adelante
		fmt.Println(resp)                     // imprimimos por pantalla
		r.Body.Close()                        // hay que cerrar el reader del body

		// ** ejemplo de data sin utilizar el token correcto
		badToken := make([]byte, 16)
		_, err = rand.Read(badToken)
		chk(err)

		data = url.Values{}
		data.Set("cmd", "data")                    // comando (string)
		data.Set("user", "usuario")                // usuario (string)
		data.Set("pass", util.Encode64(keyLogin))  // contraseña (a base64 porque es []byte)
		data.Set("token", util.Encode64(badToken)) // token incorrecto
		r, err = client.PostForm("https://localhost:10443", data)
		chk(err)
		io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
		r.Body.Close()             // hay que cerrar el reader del body
		fmt.Println()

		// ** ejemplo de data con token correcto

		data = url.Values{}
		data.Set("cmd", "data")                      // comando (string)
		data.Set("user", "usuario")                  // usuario (string)
		data.Set("pass", util.Encode64(keyLogin))    // contraseña (a base64 porque es []byte)
		data.Set("token", util.Encode64(resp.Token)) // token correcto
		r, err = client.PostForm("https://localhost:10443", data)
		chk(err)
		io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
		r.Body.Close()             // hay que cerrar el reader del body
		fmt.Println()

	*/

}
