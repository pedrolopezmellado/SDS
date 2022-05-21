/*
Servidor
*/

//
package srv

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"sdspractica/util"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"golang.org/x/crypto/argon2"
)

type PasswordConfig struct {
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

type fichero struct {
	Nombre        string
	Contenido     string
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

type directorio struct {
	Nombre   string
	Ficheros map[string]fichero
}

type nota struct {
	Usuario   string
	Contenido string
}

// ejemplo de tipo para un usuario
type user struct {
	Name       string            // nombre de usuario
	Hash       []byte            // hash de la contraseña
	Salt       []byte            // sal para la contraseña
	Token      []byte            // token de sesión
	Seen       time.Time         // última vez que fue visto
	Data       map[string]string // datos adicionales del usuario
	Directorio directorio        // directorio del usuario
}

// config para generar hash
var config = &PasswordConfig{
	time:    1,
	memory:  64 * 1024,
	threads: 4,
	keyLen:  32,
}

// maximo de versiones que puede tener un fichero
const maxVersion int = 5

// mapa con todos los usuarios
var gUsers map[string]user

// clave que cifra contenido en disco
var keyServidor []byte

// chk comprueba y sale si hay errores (ahorra escritura en programas sencillos)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// función para resumir (SHA256)
func hash(data []byte) []byte {
	h := sha256.New() // creamos un nuevo hash (SHA2-256)
	h.Write(data)     // procesamos los datos
	return h.Sum(nil) // obtenemos el resumen
}

func loadEnv() {
	err := godotenv.Load()
	if err != nil {
		log.Panicf("failed reading data from .env: %s", err)
	}
}

func obtenerExtension(nombreFichero string) string {
	trozos := strings.Split(nombreFichero, ".")
	var IsLetter = regexp.MustCompile(`^[a-zA-Z]+$`).MatchString

	if len(trozos) != 2 || !IsLetter(trozos[1]) {
		return "error"
	}
	return trozos[1]
}

func existeFichero(nombreFichero string, ficheros map[string]fichero) (fichero, bool) {
	//empezamos desde la ultima posible version para coger el fichero más reciente
	var ficheroResultado fichero
	var existe bool
	for i := maxVersion; i >= 1; i-- {
		key := nombreFichero + "/v" + strconv.Itoa(i)
		if ficheroResultado, existe := ficheros[key]; existe {
			return ficheroResultado, existe
		}
	}
	return ficheroResultado, existe
}

func leerEnDisco() {
	dataUsuarios, err := ioutil.ReadFile("disco.txt")
	if err != nil {
		log.Panicf("failed reading data from file: %s", err)
	}

	dataKey, err := ioutil.ReadFile("keyServidor.txt")
	if err != nil {
		log.Panicf("failed reading data from file: %s", err)
	}

	err = json.Unmarshal([]byte(dataKey), &keyServidor)
	if len(dataUsuarios) > 0 {
		dataUsuarios = util.Decrypt(dataUsuarios, keyServidor)

		dataUsuarios = util.Decompress(dataUsuarios)
		err = json.Unmarshal([]byte(dataUsuarios), &gUsers)
	}
}

func guardarEnDisco() {
	datosUsuarios, err := json.Marshal(gUsers)
	chk(err)
	datosKey, err := json.Marshal(keyServidor)
	chk(err)

	datosUsuarios = util.Compress(datosUsuarios)
	datosUsuarios = util.Encrypt(datosUsuarios, keyServidor)

	err = ioutil.WriteFile("disco.txt", datosUsuarios, 0644)
	err = ioutil.WriteFile("keyServidor.txt", datosKey, 0644)
}

func generatePassword(password []byte, salt *[]byte) []byte {
	config = &PasswordConfig{
		time:    1,
		memory:  64 * 1024,
		threads: 4,
		keyLen:  32,
	}
	hash := argon2.IDKey(password, *salt, config.time, config.memory, config.threads, config.keyLen)
	nuevaSalt := base64.RawStdEncoding.EncodeToString(*salt)
	nuevoHash := base64.RawStdEncoding.EncodeToString(hash)

	*salt = []byte(nuevaSalt)
	hash = []byte(nuevoHash)
	format := "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"

	return []byte(fmt.Sprintf(format, argon2.Version, config.memory, config.time, config.threads, *salt, hash))
}

func comparePassword(password []byte, hash []byte) bool {
	hashString := string(hash)
	trozos := strings.Split(hashString, "$")
	c := &PasswordConfig{}
	_, err := fmt.Sscanf(trozos[3], "m=%d,t=%d,p=%d", &c.memory, &c.time, &c.threads)
	if err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(trozos[4])
	if err != nil {
		return false
	}
	decodedHash, err := base64.RawStdEncoding.DecodeString(trozos[5])
	if err != nil {
		return false
	}
	c.keyLen = uint32(len(decodedHash))
	comparisonHash := argon2.IDKey(password, salt, c.time, c.memory, c.threads, c.keyLen)
	return (subtle.ConstantTimeCompare(decodedHash, comparisonHash) == 1)
}

func Run() {

	loadEnv()
	clave := util.Decode64(os.Getenv("CLAVE")) // accedemos a la variable de entorno CLAVE
	if keyServidor == nil {
		salt := make([]byte, 16) // sal (16 bytes == 128 bits)
		rand.Read(salt)          // la sal es aleatoria
		keyServidor = argon2.IDKey(clave, salt, config.time, config.memory, config.threads, config.keyLen)
	}

	leerEnDisco() //leemos la info de la app de disco.txt
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		guardarEnDisco() //persistimos los datos en un fichero(disco.txt)
		fmt.Println("Saliendo del servidor y persistiendo datos...")
		os.Exit(1)
	}()
	http.HandleFunc("/", handler) // asignamos un handler global

	// escuchamos el puerto 10443 con https y comprobamos el error
	chk(http.ListenAndServeTLS(":10443", "localhost.crt", "localhost.key", nil))
}

func handler(w http.ResponseWriter, req *http.Request) {

	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	switch req.Form.Get("cmd") { // comprobamos comando desde el cliente
	case "register": // ** registro
		_, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if ok {
			response(w, false, "Usuario ya registrado", nil)
			return
		}
		u := user{}
		u.Name = req.Form.Get("user") // nombre
		u.Directorio.Nombre = u.Name
		u.Directorio.Ficheros = make(map[string]fichero)
		u.Salt = make([]byte, 16)                       // sal (16 bytes == 128 bits)
		rand.Read(u.Salt)                               // la sal es aleatoria
		u.Data = make(map[string]string)                // reservamos mapa de datos de usuario
		u.Data["private"] = req.Form.Get("prikey")      // clave privada
		u.Data["public"] = req.Form.Get("pubkey")       // clave pública
		password := util.Decode64(req.Form.Get("pass")) // contraseña (keyLogin)

		// "hasheamos" la contraseña con scrypt (argon2 es mejor)
		//u.Hash, _ = scrypt.Key(password, u.Salt, 16384, 8, 1, 32)
		u.Hash = generatePassword(password, &u.Salt)
		u.Seen = time.Now()        // asignamos tiempo de login
		u.Token = make([]byte, 16) // token (16 bytes == 128 bits)
		rand.Read(u.Token)         // el token es aleatorio
		if gUsers == nil {
			gUsers = make(map[string]user)
		}
		gUsers[u.Name] = u
		response(w, true, "Usuario registrado", u.Token)

	case "login":

		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "Usuario inexistente", nil)
			return
		}
		password := util.Decode64(req.Form.Get("pass")) // obtenemos la contraseña (keyLogin)
		//hash, _ := scrypt.Key(password, u.Salt, 16384, 8, 1, 32) // scrypt de keyLogin (argon2 es mejor)
		if !comparePassword(password, u.Hash) { // comparamos
			response(w, false, "Credenciales inválidas", nil)
		} else {
			u.Seen = time.Now()        // asignamos tiempo de login
			u.Token = make([]byte, 16) // token (16 bytes == 128 bits)
			rand.Read(u.Token)         // el token es aleatorio
			gUsers[u.Name] = u
			response(w, true, "Credenciales válidas", u.Token)
		}
	case "upload":

		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "Usuario inexistente", nil)
			return
		}
		ruta := req.Form.Get("ruta")
		usuario := ruta[1:]
		if u.Name != usuario {
			response(w, false, "No tienes permisos para subir ficheros en este directorio", u.Token)
			return
		}

		contenidoFichero := req.Form.Get("contenidoFichero")
		nombreFichero := req.Form.Get("nombreFichero")

		ficheroActual, okFichero := existeFichero(nombreFichero, gUsers[u.Name].Directorio.Ficheros)
		ext := obtenerExtension(nombreFichero)

		if ext == "error" {
			response(w, false, "El nombre del fichero debe seguir el formato <nombre>.<extension>", u.Token)
		} else {
			var version int
			if okFichero {
				version = ficheroActual.Version + 1
				if version > maxVersion {
					response(w, false, "Has alcanzado el número máximo de versiones para el fichero", u.Token)
					return
				}
				nombreFichero = nombreFichero + "/v" + strconv.Itoa(version)
			} else {
				version = 1
				nombreFichero = nombreFichero + "/v1"
			}
			miFichero := fichero{
				Nombre:        nombreFichero,
				Contenido:     contenidoFichero,
				Autor:         u.Name,
				Public:        false,
				SharedUsers:   make(map[string]user),
				NumCaracteres: len(contenidoFichero),
				Extension:     ext,
				FechaCreacion: time.Now(),
				Version:       version,
			}
			gUsers[u.Name].Directorio.Ficheros[nombreFichero] = miFichero
			mensaje := "Fichero subido correctamente"
			response(w, true, mensaje, u.Token)
		}
	case "cat":

		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "Usuario inexistente", nil)
			return
		}
		nombreFichero := req.Form.Get("nombreFichero")
		nombreFichero = nombreFichero[:len(nombreFichero)-2]
		ruta := req.Form.Get("ruta")
		usuario := ruta[1:]
		fichero, okFichero := gUsers[usuario].Directorio.Ficheros[nombreFichero]
		if !okFichero {
			response(w, false, "El fichero no existe", u.Token)
			return
		} else if u.Name != usuario { // si el usuario que hace la peticion no es el autor del fichero
			_, existe := fichero.SharedUsers[u.Name]
			if fichero.Public || existe { // comprobamos que el usuario tiene permisos
				fichero.NumRevisiones++
				gUsers[usuario].Directorio.Ficheros[nombreFichero] = fichero
				datos, err := json.Marshal(&fichero) //
				chk(err)
				response(w, true, string(datos), u.Token)
			} else {
				response(w, false, "El usuario no tiene permisos", u.Token)
			}
			return
		}
		fichero.NumRevisiones++
		gUsers[usuario].Directorio.Ficheros[nombreFichero] = fichero
		datos, err := json.Marshal(&fichero) //
		chk(err)
		response(w, true, string(datos), u.Token)

	case "delete":

		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "Usuario inexistente", nil)
			return
		}
		nombreFichero := req.Form.Get("nombreFichero")
		nombreFichero = nombreFichero[:len(nombreFichero)-2]
		fichero, okFichero := gUsers[u.Name].Directorio.Ficheros[nombreFichero]
		if !okFichero {
			response(w, false, "El fichero no existe", u.Token)
			return
		}
		delete(gUsers[u.Name].Directorio.Ficheros, fichero.Nombre)
		response(w, true, "Fichero eliminado correctamente", u.Token)
	case "details":

		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "Usuario inexistente", nil)
			return
		}
		nombreFichero := req.Form.Get("nombreFichero")
		nombreFichero = nombreFichero[:len(nombreFichero)-2]
		ruta := req.Form.Get("ruta")
		usuario := ruta[1:]
		fichero, okFichero := gUsers[usuario].Directorio.Ficheros[nombreFichero]
		if !okFichero {
			response(w, false, "El fichero no existe", u.Token)
			return
		} else if u.Name != usuario { // si el usuario que hace la peticion no es el autor del fichero
			_, existe := fichero.SharedUsers[u.Name]
			if fichero.Public || existe { // comprobamos que el usuario tiene permisos
				datos, err := json.Marshal(&fichero) //
				chk(err)
				response(w, true, string(datos), u.Token)
			} else {
				response(w, false, "El usuario no tiene permisos", u.Token)
			}
			return
		}
		datos, err := json.Marshal(&fichero) //
		chk(err)
		response(w, true, string(datos), u.Token)
	case "ls":

		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "No autentificado", nil)
			return
		} else if (u.Token == nil) || (time.Since(u.Seen).Minutes() > 60) {
			// sin token o con token expirado
			response(w, false, "No autentificado", nil)
			return
		} else {
			ruta := req.Form.Get("ruta")
			var nombres []string
			var mensaje string
			if ruta == "/" {
				for nombre := range gUsers {
					nombres = append(nombres, "/"+nombre)
				}
				mensaje = strings.Join(nombres, "\n")
				response(w, true, mensaje, u.Token)
				return
			} else {
				nombreUsuario := ruta[1:]
				if u.Name == nombreUsuario {
					for nombre := range u.Directorio.Ficheros {
						nombres = append(nombres, nombre)
					}
					mensaje = strings.Join(nombres, "\n")
					response(w, true, mensaje, u.Token)
					return
				} else {
					usuario := gUsers[nombreUsuario]
					for nombre, fichero := range usuario.Directorio.Ficheros {
						_, sharedUser := fichero.SharedUsers[u.Name]
						if fichero.Public || sharedUser {
							nombres = append(nombres, nombre)
						}
					}
					mensaje = strings.Join(nombres, "\n")
					response(w, true, mensaje, u.Token)
					return
				}
			}
		}
	case "touch":

		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "Error: No autentificado", nil)
			return
		} else if (u.Token == nil) || (time.Since(u.Seen).Minutes() > 60) {
			// sin token o con token expirado
			response(w, false, "Error: No autentificado", nil)
			return
		}
		contenido := req.Form.Get("contenido")
		ruta := req.Form.Get("ruta")
		usuario := ruta[1:]
		if u.Name != usuario {
			response(w, false, "Error: No tienes permisos para crear un fichero en este directorio", u.Token)
			return
		} else {
			nombreFichero := req.Form.Get("nombreFichero")
			nombreFichero = nombreFichero[:len(nombreFichero)-2]
			ext := obtenerExtension(nombreFichero)

			if ext == "error" {
				response(w, false, "Error: El nombre del fichero debe seguir el formato <nombre>.<extension>", u.Token)
				return
			} else {
				var version int
				ficheroExistente, existeFichero := existeFichero(nombreFichero, gUsers[u.Name].Directorio.Ficheros)
				if existeFichero {
					version = ficheroExistente.Version + 1
					if version > maxVersion {
						response(w, false, "Error: Has alcanzado el número máximo de versiones para el fichero", u.Token)
						return
					}
					nombreFichero = nombreFichero + "/v" + strconv.Itoa(version)
				} else {
					version = 1
					nombreFichero = nombreFichero + "/v1"
				}
				miFichero := fichero{
					Nombre:        nombreFichero,
					Contenido:     contenido,
					Autor:         u.Name,
					Public:        false,
					SharedUsers:   make(map[string]user),
					NumCaracteres: len(contenido),
					Extension:     ext,
					FechaCreacion: time.Now(),
					Version:       version,
				}
				gUsers[u.Name].Directorio.Ficheros[miFichero.Nombre] = miFichero
				response(w, true, "Fichero creado", u.Token)
				return
			}
		}
	case "cd":

		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "No autentificado", nil)
			return
		} else if (u.Token == nil) || (time.Since(u.Seen).Minutes() > 60) {
			// sin token o con token expirado
			response(w, false, "No autentificado", nil)
			return
		} else {
			directorio := req.Form.Get("directorio")
			directorio = directorio[:len(directorio)-2]
			var nombreDir string
			existe := false
			for nombre := range gUsers {
				if nombre == directorio || "/"+nombre == directorio {
					existe = true
					nombreDir = nombre
				}
			}
			if existe {
				response(w, true, "/"+nombreDir, u.Token)
			} else {
				response(w, false, "El directorio no existe", u.Token)
			}
		}
	case "share":

		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "No autentificado", nil)
			return
		} else if (u.Token == nil) || (time.Since(u.Seen).Minutes() > 60) {
			// sin token o con token expirado
			response(w, false, "No autentificado", nil)
			return
		} else {
			nombreFichero := req.Form.Get("nombreFichero")
			nombreUsuario := req.Form.Get("userShare")
			nombreUsuario = nombreUsuario[:len(nombreUsuario)-2]

			if nombreUsuario == u.Name {
				response(w, false, "No puedes compartir un fichero contigo mismo", u.Token)
				return
			}

			usuarioShare, okUser := gUsers[nombreUsuario] // ¿existe ya el usuario?
			_, okFichero := gUsers[u.Name].Directorio.Ficheros[nombreFichero]
			if !okFichero {
				response(w, false, "No existe ningún fichero con ese nombre", u.Token)
				return
			} else {
				if !okUser {
					response(w, false, "El usuario al que desea compartir su fichero no existe", u.Token)
					return
				} else {
					gUsers[u.Name].Directorio.Ficheros[nombreFichero].SharedUsers[usuarioShare.Name] = usuarioShare
					response(w, true, "Fichero compartido con "+usuarioShare.Name, u.Token)
					return
				}
			}
		}
	case "unshare":

		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "No autentificado", nil)
			return
		} else if (u.Token == nil) || (time.Since(u.Seen).Minutes() > 60) {
			// sin token o con token expirado
			response(w, false, "No autentificado", nil)
			return
		} else {
			nombreFichero := req.Form.Get("nombreFichero")
			nombreUsuario := req.Form.Get("userUnshare")
			nombreUsuario = nombreUsuario[:len(nombreUsuario)-2]

			if nombreUsuario == u.Name {
				response(w, false, "No puedes descompartir un fichero contigo mismo", u.Token)
				return
			}

			usuarioUnshare, okUser := gUsers[nombreUsuario] // ¿existe el usuario?
			_, okFichero := gUsers[u.Name].Directorio.Ficheros[nombreFichero]
			if !okFichero {
				response(w, false, "No existe ningún fichero con ese nombre", u.Token)
				return
			} else {
				if !okUser {
					response(w, false, "El usuario al que desea compartir su fichero no existe", u.Token)
					return
				} else {
					delete(gUsers[u.Name].Directorio.Ficheros[nombreFichero].SharedUsers, usuarioUnshare.Name)
					response(w, true, "Fichero descompartido con "+usuarioUnshare.Name, u.Token)
					return
				}
			}
		}
	case "public":

		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "No autentificado", nil)
			return
		} else if (u.Token == nil) || (time.Since(u.Seen).Minutes() > 60) {
			// sin token o con token expirado
			response(w, false, "No autentificado", nil)
			return
		} else {
			nombreFichero := req.Form.Get("nombreFichero")
			nombreFichero = nombreFichero[:len(nombreFichero)-2]
			fichero, ok := gUsers[u.Name].Directorio.Ficheros[nombreFichero]
			if !ok {
				response(w, false, "No existe ningún fichero con ese nombre", u.Token)
				return
			} else {
				fichero.Public = true
				gUsers[u.Name].Directorio.Ficheros[nombreFichero] = fichero
			}
			response(w, true, "Ahora "+nombreFichero+" es público", u.Token)
		}
	case "private":

		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "No autentificado", nil)
			return
		} else if (u.Token == nil) || (time.Since(u.Seen).Minutes() > 60) {
			// sin token o con token expirado
			response(w, false, "No autentificado", nil)
			return
		} else {
			nombreFichero := req.Form.Get("nombreFichero")
			nombreFichero = nombreFichero[:len(nombreFichero)-2]
			fichero, ok := gUsers[u.Name].Directorio.Ficheros[nombreFichero]
			if !ok {
				response(w, false, "No existe ningún fichero con ese nombre", u.Token)
				return
			} else {
				fichero.Public = false
				gUsers[u.Name].Directorio.Ficheros[nombreFichero] = fichero
			}
			response(w, true, "Ahora "+nombreFichero+" es privado", u.Token)
		}
	case "note":
		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "No autentificado", nil)
			return
		} else if (u.Token == nil) || (time.Since(u.Seen).Minutes() > 60) {
			response(w, false, "No autentificado", nil) // sin token o con token expirado
			return
		} else {
			nombreFichero := req.Form.Get("nombreFichero")
			nombreFichero = nombreFichero[:len(nombreFichero)-2]
			ruta := req.Form.Get("ruta")
			contenidoNota := req.Form.Get("contenido")
			contenidoNota = contenidoNota[:len(contenidoNota)-2]
			usuario := ruta[1:]
			fichero, ok := gUsers[usuario].Directorio.Ficheros[nombreFichero]
			if !ok {
				response(w, false, "El fichero no existe", u.Token)
			}
			nuevaNota := nota{
				Usuario:   u.Name,
				Contenido: contenidoNota,
			}
			if u.Name != usuario { // si el usuario que hace la peticion no es el autor del fichero
				_, existe := fichero.SharedUsers[u.Name]
				if fichero.Public || existe { // comprobamos que el usuario tiene permisos
					fichero.Notas = append(fichero.Notas, nuevaNota)
					gUsers[usuario].Directorio.Ficheros[nombreFichero] = fichero
					response(w, true, "Nota añadida correctamente", u.Token)
				} else {
					response(w, false, "El usuario no tiene permisos", u.Token)
				}
				return
			}
			fichero.Notas = append(fichero.Notas, nuevaNota)
			gUsers[usuario].Directorio.Ficheros[nombreFichero] = fichero
			response(w, true, "Nota añadida correctamente", u.Token)
			return
		}
	default:
		response(w, false, "Comando no implementado", nil)
	}
}

// respuesta del servidor
// (empieza con mayúscula ya que se utiliza en el cliente también)
// (los variables empiezan con mayúscula para que sean consideradas en el encoding)
type Resp struct {
	Ok    bool   // true -> correcto, false -> error
	Msg   string // mensaje adicional
	Token []byte // token de sesión para utilizar por el cliente
}

// función para escribir una respuesta del servidor
func response(w io.Writer, ok bool, msg string, token []byte) {
	r := Resp{Ok: ok, Msg: msg, Token: token} // formateamos respuesta
	rJSON, err := json.Marshal(&r)            // codificamos en JSON
	chk(err)                                  // comprobamos error
	w.Write(rJSON)                            // escribimos el JSON resultante
}
