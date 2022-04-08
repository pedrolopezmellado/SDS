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
var ruta string

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
		ruta = "/" + usuarioActual
		menuLogin()
	}
	r.Body.Close() // hay que cerrar el reader del body
}

func menuLogin() {

	cadena := ""

	for strings.Split(cadena, " ")[0] != "exit\n" {
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
	data.Set("cmd", "ls")           // comando (string)
	data.Set("user", usuarioActual) // usuario (string)

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	resp := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // decodificamos la respuesta para utilizar sus campos más adelante
	//fmt.Println(resp)                     // imprimimos por pantalla
	if resp.Ok {
		fmt.Println(resp.Msg)
	}
	r.Body.Close() // hay que cerrar el reader del body
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
		fmt.Println(resp.Msg)
		r.Body.Close() // hay que cerrar el reader del body

		// imprimir el string
		//fmt.Println(datosComoString)
	}
}

func touchComando(nombreFichero string, client *http.Client) {
	data := url.Values{}
	data.Set("cmd", "touch")        // comando (string)
	data.Set("user", usuarioActual) // usuario (string)
	data.Set("nombreFichero", nombreFichero)

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	resp := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // decodificamos la respuesta para utilizar sus campos más adelante
	fmt.Println(resp)                     // imprimimos por pantalla
	if resp.Ok {
		fmt.Println(resp.Msg)
	}
	r.Body.Close() // hay que cerrar el reader del body
}

func shareComando(nombreFichero string, usuario string, client *http.Client) {
	fmt.Print(usuario)
	data := url.Values{}
	data.Set("cmd", "share")        // comando (string)
	data.Set("user", usuarioActual) // usuario (string)
	data.Set("nombreFichero", nombreFichero)
	data.Set("userShare", usuario)

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	resp := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // decodificamos la respuesta para utilizar sus campos más adelante
	fmt.Println(resp.Msg)
	r.Body.Close() // hay que cerrar el reader del body
}

func publicComando(nombreFichero string, client *http.Client) {
	data := url.Values{}
	data.Set("cmd", "public")       // comando (string)
	data.Set("user", usuarioActual) // usuario (string)
	data.Set("nombreFichero", nombreFichero)

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	resp := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // decodificamos la respuesta para utilizar sus campos más adelante
	fmt.Println(resp.Msg)
	r.Body.Close() // hay que cerrar el reader del body*/
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

cdComando(directorio string, client *http.Client) {
	// ** ejemplo de registro
	data := url.Values{}            // estructura para contener los valores
	data.Set("cmd", "cd")           // comando (string)
	data.Set("user", usuarioActual) // usuario (string)

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	resp := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // decodificamos la respuesta para utilizar sus campos más adelante
	//fmt.Println(resp)                     // imprimimos por pantalla
	if resp.Ok {
		nombres := strings.Split(resp.Msg, " ")
		for _, nombre := range nombres {
			fmt.Println("/" + nombre)
		}
	} else {
		fmt.Println(resp.Msg)
	}
	r.Body.Close() // hay que cerrar el reader del body
}

func paraTi(client *http.Client) {
	// ** ejemplo de registro
	data := url.Values{}            // estructura para contener los valores
	data.Set("cmd", "cd")           // comando (string)
	data.Set("user", usuarioActual) // usuario (string)

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	resp := srv.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // decodificamos la respuesta para utilizar sus campos más adelante
	//fmt.Println(resp)                     // imprimimos por pantalla
	if resp.Ok {
		nombres := strings.Split(resp.Msg, " ")
		for _, nombre := range nombres {
			fmt.Println("/" + nombre)
		}
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
	case "cd":
		if moreCommands {
			directorio := trozos[1]
			cdComando(directorio, client)
		} else {
			ruta = "/"

		}

		break
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
		break
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
		break
	case "private":
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
cd 						Te lleva al directorio raíz
cd [nombre_usuario]				Te lleva al directorio del usuario				
touch [nombre_fichero] 				Crea un fichero en la ruta
cat [nombre_fichero] 				Muestra el contenido del fichero
upload [ruta] [nombre_fichero]			Sube un fichero a partir de una ruta
delete [nombre_fichero]				Elimina un fichero
share [nombre_fichero] [nombre_usuario]		Comparte el fichero con otro usuario
public [nombre_fichero]				Pone el fichero público para los demás usuarios
private [nombre_fichero]			Pone el fichero privado

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
