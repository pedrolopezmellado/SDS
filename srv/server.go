/*
Servidor
*/
package srv

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sdspractica/util"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
)

type PasswordConfig struct {
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

type fichero struct {
	nombre      string
	contenido   string
	public      bool
	sharedUsers map[string]user
}

type directorio struct {
	nombre   string
	ficheros map[string]fichero
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

// chk comprueba y sale si hay errores (ahorra escritura en programas sencillos)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

func generatePassword(c *PasswordConfig, password []byte, salt *[]byte) []byte {
	hash := argon2.IDKey(password, *salt, c.time, c.memory, c.threads, c.keyLen)
	nuevaSalt := base64.RawStdEncoding.EncodeToString(*salt)
	nuevoHash := base64.RawStdEncoding.EncodeToString(hash)

	*salt = []byte(nuevaSalt)
	hash = []byte(nuevoHash)
	format := "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s"

	return []byte(fmt.Sprintf(format, argon2.Version, c.memory, c.time, c.threads, *salt, hash))
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

// mapa con todos los usuarios
// (se podría serializar con JSON o Gob, etc. y escribir/leer de disco para persistencia)
var gUsers map[string]user

// gestiona el modo servidor
func Run() {

	gUsers = make(map[string]user) // inicializamos mapa de usuarios
	http.HandleFunc("/", handler)  // asignamos un handler global

	// escuchamos el puerto 10443 con https y comprobamos el error
	chk(http.ListenAndServeTLS(":10443", "localhost.crt", "localhost.key", nil))
}

func handler(w http.ResponseWriter, req *http.Request) {
	config := &PasswordConfig{
		time:    1,
		memory:  64 * 1024,
		threads: 4,
		keyLen:  32,
	}
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	switch req.Form.Get("cmd") { // comprobamos comando desde el cliente
	case "register": // ** registro

		fmt.Println("Usuarios antes de hacer el registro: " + strconv.Itoa(len(gUsers)))
		_, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if ok {
			response(w, false, "Usuario ya registrado", nil)
			return
		}

		u := user{}
		u.Name = req.Form.Get("user") // nombre
		u.Directorio.nombre = u.Name
		u.Directorio.ficheros = make(map[string]fichero)
		u.Salt = make([]byte, 16)                       // sal (16 bytes == 128 bits)
		rand.Read(u.Salt)                               // la sal es aleatoria
		u.Data = make(map[string]string)                // reservamos mapa de datos de usuario
		u.Data["private"] = req.Form.Get("prikey")      // clave privada
		u.Data["public"] = req.Form.Get("pubkey")       // clave pública
		password := util.Decode64(req.Form.Get("pass")) // contraseña (keyLogin)

		// "hasheamos" la contraseña con scrypt (argon2 es mejor)
		//u.Hash, _ = scrypt.Key(password, u.Salt, 16384, 8, 1, 32)
		u.Hash = generatePassword(config, password, &u.Salt)
		u.Seen = time.Now()        // asignamos tiempo de login
		u.Token = make([]byte, 16) // token (16 bytes == 128 bits)
		rand.Read(u.Token)         // el token es aleatorio
		gUsers[u.Name] = u
		fmt.Println("Usuarios despues de hacer el registro: " + strconv.Itoa(len(gUsers)))
		response(w, true, "Usuario registrado", u.Token)

	case "login": // ** login
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

		contenidoFichero := req.Form.Get("contenidoFichero")
		nombreFichero := req.Form.Get("nombreFichero")

		ficheroActual, okFichero := gUsers[u.Name].Directorio.ficheros[nombreFichero]
		if okFichero {
			response(w, false, "El fichero "+ficheroActual.nombre+" ya existe", u.Token)
			return
		}

		miFichero := fichero{
			nombre:    nombreFichero,
			contenido: contenidoFichero,
		}
		gUsers[u.Name].Directorio.ficheros[nombreFichero] = miFichero
		mensaje := "Fichero subido correctamente"
		response(w, true, mensaje, u.Token)

	case "cat":
		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "Usuario inexistente", nil)
			return
		}
		nombreFichero := req.Form.Get("nombreFichero")
		fichero, okFichero := gUsers[u.Name].Directorio.ficheros[nombreFichero]
		if !okFichero {
			response(w, false, "El fichero no existe", u.Token)
			return
		}
		response(w, true, fichero.contenido, u.Token)

	case "delete":
		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "Usuario inexistente", nil)
			return
		}
		nombreFichero := req.Form.Get("nombreFichero")
		fichero, okFichero := gUsers[u.Name].Directorio.ficheros[nombreFichero]
		if !okFichero {
			response(w, false, "El fichero no existe", u.Token)
			return
		}
		delete(gUsers[u.Name].Directorio.ficheros, fichero.nombre)
		response(w, true, "Fichero eliminado correctamente", u.Token)

	case "data": // ** obtener datos de usuario
		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "No autentificado", nil)
			return
		} else if (u.Token == nil) || (time.Since(u.Seen).Minutes() > 60) {
			// sin token o con token expirado
			response(w, false, "No autentificado", nil)
			return
		} else if !bytes.EqualFold(u.Token, util.Decode64(req.Form.Get("token"))) {
			// token no coincide
			response(w, false, "No autentificado", nil)
			return
		}

		datos, err := json.Marshal(&u.Data) //
		chk(err)
		u.Seen = time.Now()
		gUsers[u.Name] = u
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
			var nombres []string
			var mensaje string
			for nombre := range u.Directorio.ficheros {
				nombres = append(nombres, nombre)
			}
			if len(nombres) == 0 {
				mensaje = "Tu directorio no contiene ficheros actualmente"
			} else {
				mensaje = strings.Join(nombres, " ")
			}
			response(w, true, mensaje, u.Token)
		}
	case "touch":
		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "No autentificado", nil)
			return
		} else if (u.Token == nil) || (time.Since(u.Seen).Minutes() > 60) {
			// sin token o con token expirado
			response(w, false, "No autentificado", nil)
			return
		} else {
			miFichero := fichero{
				nombre:    req.Form.Get("nombreFichero"),
				contenido: "",
			}
			gUsers[u.Name].Directorio.ficheros[miFichero.nombre] = miFichero
			response(w, true, "Fichero creado", u.Token)
		}
	case "share":
		/*u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "No autentificado", nil)
			return
		} else if (u.Token == nil) || (time.Since(u.Seen).Minutes() > 60) {
			// sin token o con token expirado
			response(w, false, "No autentificado", nil)
			return
		} else {
			nombreFichero := req.Form.Get("nombreFichero")
			usuario := req.Form.Get("userShare")
			fichero, ok := gUsers[u.Name].Directorio.ficheros[nombreFichero]
			if !ok {
				response(w, false, "No existe ningún fichero con ese nombre", u.Token)
				return
			}
			else{
				u, ok := gUsers[req.Form.Get("userShare")]
				if()
			}
			response(w, true, "Fichero creado", u.Token)
		}*/
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
